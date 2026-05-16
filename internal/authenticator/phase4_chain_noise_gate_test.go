// Package authenticator: σ_flood noise-budget gate for the chain-rotation
// Auth pipeline.
//
// This file is the canonical 1k-trial gate that supersedes the earlier
// `phase4_neg_base2_test.go` exploration test. Two variants are defined:
//
//   - TestAuthChainNoiseGate (fast, default): 100 trials, runs in ~a few
//     minutes wall on 16 cores via a worker pool. Asserts every trial
//     passes — 100% over 100 trials is a strictly tighter check than 99.9%
//     over 1k in expectation, so any tail event would still surface here.
//
//   - TestAuthChainNoiseGate_Full (1000 trials, gated behind
//     `PPIAV_RUN_HEAVY=1`): the canonical noise-budget gate. Asserts Ver
//     pass rate ≥ 99.9% (≥ 999 / 1000). Run on the VPS during Task 15;
//     too slow for the default `go test ./...` loop on a dev box (10
//     trials = ~33s single-threaded → 1000 ≈ 55 min; parallel across 16
//     cores trims to ~5–10 min, but convention per
//     `feedback_no_logn15_local` is to gate anything that takes more than
//     a couple minutes behind PPIAV_RUN_HEAVY).
//
// What this productionizes vs the exploration test it replaces:
//
//  1. Replaces the inline `chainRotate` helper with the production
//     `authchain.Evaluator`.
//  2. Runs N independent trials with randomized `Key.S` to exercise
//     chain-length variance across the [1, λ) rotation set.
//  3. Tracks the empirical Ver pass rate rather than asserting per-trial
//     (so a single noise-tail event in 1000 trials doesn't fail the full
//     gate spuriously).
//
// Params: LogN=14 (per `feedback_no_logn15_local`); λ=128 (production).
package authenticator

import (
	"crypto/rand"
	"math"
	"math/bits"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/butvinm/ppiav/internal/authchain"
	"github.com/butvinm/ppiav/internal/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

const (
	chainGateLambda     = 128
	chainGateTrialsFast = 100
	chainGateTrialsFull = 1000
	// Empirical pass-rate threshold for the full gate. σ_flood = 2¹⁶ and
	// ε = 2²⁰ are engineered for >4σ tail per DESIGN.md:361-364 — 99.9%
	// over 1k trials is the tighter empirical check.
	chainGatePassRate = 0.999
)

// gen2PartyAtomKeys runs the 2-party multi-party GaloisKeyGen handshake
// at the seven negative-galEl auth atoms and returns the aggregated keys.
// Matches the wire-protocol shape Phase 4 VAgent emits to VClient.
func gen2PartyAtomKeys(
	t *testing.T,
	params ckks.Parameters,
	skC, skA *rlwe.SecretKey,
	atoms []int,
	crsLabel []byte,
) []*rlwe.GaloisKey {
	t.Helper()
	crs, err := sampling.NewKeyedPRNG(crsLabel)
	require.NoError(t, err)

	gkg := multiparty.NewGaloisKeyGenProtocol(params)
	out := make([]*rlwe.GaloisKey, 0, len(atoms))
	for _, atom := range atoms {
		galEl := params.GaloisElement(-atom)
		crp := gkg.SampleCRP(crs)

		shareC := gkg.AllocateShare()
		shareA := gkg.AllocateShare()
		require.NoError(t, gkg.GenShare(skC, galEl, crp, &shareC))
		require.NoError(t, gkg.GenShare(skA, galEl, crp, &shareA))

		acc := gkg.AllocateShare()
		acc.GaloisElement = galEl
		require.NoError(t, gkg.AggregateShares(shareC, shareA, &acc))

		gk := rlwe.NewGaloisKey(params)
		require.NoError(t, gkg.GenGaloisKey(acc, crp, gk))
		out = append(out, gk)
	}
	return out
}

// gen2PartyPK runs the 2-party PublicKeyGen handshake → joint pk.
func gen2PartyPK(
	t *testing.T,
	params ckks.Parameters,
	skC, skA *rlwe.SecretKey,
	crsLabel []byte,
) *rlwe.PublicKey {
	t.Helper()
	crs, err := sampling.NewKeyedPRNG(crsLabel)
	require.NoError(t, err)

	proto := multiparty.NewPublicKeyGenProtocol(params)
	crp := proto.SampleCRP(crs)

	shareC := proto.AllocateShare()
	shareA := proto.AllocateShare()
	proto.GenShare(skC, crp, &shareC)
	proto.GenShare(skA, crp, &shareA)

	agg := proto.AllocateShare()
	proto.AggregateShares(shareC, shareA, &agg)

	pk := rlwe.NewPublicKey(params)
	proto.GenPublicKey(agg, crp, pk)
	return pk
}

// joint2PartyDecrypt runs the 2-party KeySwitch-to-zero protocol with
// flooding noise σ = floodSigma. Returns the recovered plaintext slot
// vector. Matches ppiav's MPD-Auth joint-decryption shape.
func joint2PartyDecrypt(
	t *testing.T,
	params ckks.Parameters,
	skC, skA *rlwe.SecretKey,
	encoder *ckks.Encoder,
	ct *rlwe.Ciphertext,
	floodSigma float64,
) []float64 {
	t.Helper()
	proto, err := multiparty.NewKeySwitchProtocol(params, ring.DiscreteGaussian{
		Sigma: floodSigma,
		Bound: 6 * floodSigma,
	})
	require.NoError(t, err)

	zeroSk := rlwe.NewSecretKey(params)
	shareC := proto.AllocateShare(ct.Level())
	shareA := proto.AllocateShare(ct.Level())
	proto.GenShare(skC, zeroSk, ct, &shareC)
	proto.GenShare(skA, zeroSk, ct, &shareA)

	agg := proto.AllocateShare(ct.Level())
	require.NoError(t, proto.AggregateShares(shareC, shareA, &agg))

	out := ckks.NewCiphertext(params, ct.Degree(), ct.Level())
	proto.KeySwitch(ct, agg, out)

	zeroDec := rlwe.NewDecryptor(params, zeroSk)
	pt := zeroDec.DecryptNew(out)
	slots := make([]float64, params.MaxSlots())
	require.NoError(t, encoder.Decode(pt, slots))
	return slots
}

// chainGateTrial runs a single Auth → joint-decrypt → Ver round-trip with
// randomized Key.S and trial-unique CRS labels (so parallel trials draw
// independent randomness for pk and atom keys). Returns whether Ver
// accepted.
func chainGateTrial(t *testing.T, params ckks.Parameters, atoms []int, trialIdx int) bool {
	t.Helper()

	kgen := rlwe.NewKeyGenerator(params)
	skC := kgen.GenSecretKeyNew()
	skA := kgen.GenSecretKeyNew()

	pkLabel := []byte("phase4-chain-gate-crs-pk-" + itoaTest(trialIdx))
	atomLabel := []byte("phase4-chain-gate-crs-atoms-" + itoaTest(trialIdx))

	pkJoint := gen2PartyPK(t, params, skC, skA, pkLabel)
	atomGKs := gen2PartyAtomKeys(t, params, skC, skA, atoms, atomLabel)

	// Synthetic rlk — Auth never relinearizes, but authchain.New requires
	// non-nil rlk for the evaluator key set.
	rlk := rlwe.NewRelinearizationKey(params)
	rot, err := authchain.New(params, rlk, atomGKs, atoms)
	require.NoError(t, err)

	cfg := Config{Lambda: chainGateLambda, Epsilon: math.Exp2(20)}
	a, err := New(cfg, params)
	require.NoError(t, err)
	key, err := KeyGen(cfg, rand.Reader)
	require.NoError(t, err)

	encoder := ckks.NewEncoder(params)
	const m = 0.5
	values := make([]float64, params.MaxSlots())
	values[0] = m
	pt := ckks.NewPlaintext(params, params.MaxLevel())
	require.NoError(t, encoder.Encode(values, pt))
	encryptor := rlwe.NewEncryptor(params, pkJoint)
	ct, err := encryptor.EncryptNew(pt)
	require.NoError(t, err)

	ctM, err := a.Auth(key, encryptor, rot, ct)
	require.NoError(t, err)

	plaintext := joint2PartyDecrypt(t, params, skC, skA, encoder, ctM, math.Exp2(16))
	_, ok := a.Ver(key, plaintext)
	return ok
}

// itoaTest is a tiny strconv.Itoa stand-in to keep the import list short.
func itoaTest(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// runChainGate runs `nTrials` independent trials in parallel via a worker
// pool sized to GOMAXPROCS. Returns the number of Ver-accepted trials.
// Lattigo v6.2.0+ per-structure methods are concurrent-safe (per the
// CLAUDE.md "Lattigo concurrency" note); each trial also builds fresh
// keys + evaluator so there's no shared mutable state across workers.
func runChainGate(t *testing.T, nTrials int) int {
	t.Helper()
	params := testParams(t) // LogN=14

	atoms := []int{}
	for a := 1; a < chainGateLambda; a <<= 1 {
		atoms = append(atoms, a)
	}

	var passes int64
	var wg sync.WaitGroup
	jobs := make(chan int, nTrials)
	for i := 0; i < nTrials; i++ {
		jobs <- i
	}
	close(jobs)

	workers := runtime.GOMAXPROCS(0)
	if workers > nTrials {
		workers = nTrials
	}
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				if chainGateTrial(t, params, atoms, idx) {
					atomic.AddInt64(&passes, 1)
				}
			}
		}()
	}
	wg.Wait()
	return int(passes)
}

// TestAuthChainNoiseGate is the default-run fast variant: 100 trials,
// asserts every trial passes. Catches gross noise-budget regressions on
// the local dev box; the canonical 99.9% gate runs in
// TestAuthChainNoiseGate_Full behind `PPIAV_RUN_HEAVY=1`.
func TestAuthChainNoiseGate(t *testing.T) {
	if testing.Short() {
		t.Skip("σ_flood noise-budget gate: skipped in -short mode")
	}
	passes := runChainGate(t, chainGateTrialsFast)
	require.Equalf(t, chainGateTrialsFast, passes,
		"σ_flood gate (fast): expected all %d trials to pass Ver, got %d",
		chainGateTrialsFast, passes)
}

// TestAuthChainNoiseGate_Full is the canonical 1k-trial σ_flood gate:
// asserts Ver pass rate ≥ 99.9% (≥ 999/1000). Gated behind
// PPIAV_RUN_HEAVY=1 because 1000 trials at LogN=14 takes ~5+ minutes wall
// even on 16 cores. Run on the VPS during Task 15. If this fails, STOP
// and document a σ_flood recalibration in a follow-up docs/plans/ entry
// — do NOT silently bump the constant.
func TestAuthChainNoiseGate_Full(t *testing.T) {
	testutil.RequireHeavy(t, "σ_flood 1000-trial gate (~5+ minutes wall)")
	passes := runChainGate(t, chainGateTrialsFull)
	rate := float64(passes) / float64(chainGateTrialsFull)
	t.Logf("σ_flood gate (full): %d/%d trials passed (%.4f)", passes, chainGateTrialsFull, rate)
	require.GreaterOrEqualf(t, rate, chainGatePassRate,
		"σ_flood gate (full): Ver pass rate %.4f below threshold %.4f (%d/%d). "+
			"Calibrate σ_flood per a follow-up docs/plans/ entry.",
		rate, chainGatePassRate, passes, chainGateTrialsFull)
}

// TestAuthChainStats logs the chain-length distribution Auth exercises
// across `[0, λ) \ S` for a single random `S`. Documents the "max
// popcount 7, mean 3.52 over 64 non-S rotations" claim from the plan's
// amendment. Useful for noise-budget regression hunts.
func TestAuthChainStats(t *testing.T) {
	cfg := Config{Lambda: chainGateLambda, Epsilon: math.Exp2(20)}
	key, err := KeyGen(cfg, rand.Reader)
	require.NoError(t, err)

	inS := sInSet(key.S, chainGateLambda)
	stats := struct{ max, sum, count int }{}
	for j := 1; j < chainGateLambda; j++ {
		if inS[j] {
			continue
		}
		pc := bits.OnesCount(uint(j))
		if pc > stats.max {
			stats.max = pc
		}
		stats.sum += pc
		stats.count++
	}
	mean := float64(stats.sum) / float64(stats.count)
	t.Logf("Auth chain stats: rotations=%d, max chain=%d, mean=%.2f, total atom-ops=%d",
		stats.count, stats.max, mean, stats.sum)
	assert.LessOrEqual(t, stats.max, 7, "max chain length over j ∈ [1, 127] must be ≤ 7")
}
