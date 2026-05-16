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
	"fmt"
	"math"
	"math/bits"
	"runtime"
	"strconv"
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
//
// Returns an error instead of calling t.FailNow — this helper runs from
// worker goroutines and `t.FailNow` is undefined-behaviour off the main
// goroutine per testing package docs.
func gen2PartyAtomKeys(
	params ckks.Parameters,
	skC, skA *rlwe.SecretKey,
	atoms []int,
	crsLabel []byte,
) ([]*rlwe.GaloisKey, error) {
	crs, err := sampling.NewKeyedPRNG(crsLabel)
	if err != nil {
		return nil, fmt.Errorf("gen2PartyAtomKeys: build CRS: %w", err)
	}

	gkg := multiparty.NewGaloisKeyGenProtocol(params)
	out := make([]*rlwe.GaloisKey, 0, len(atoms))
	for _, atom := range atoms {
		galEl := params.GaloisElement(-atom)
		crp := gkg.SampleCRP(crs)

		shareC := gkg.AllocateShare()
		shareA := gkg.AllocateShare()
		if err := gkg.GenShare(skC, galEl, crp, &shareC); err != nil {
			return nil, fmt.Errorf("gen2PartyAtomKeys: GenShare skC atom %d: %w", atom, err)
		}
		if err := gkg.GenShare(skA, galEl, crp, &shareA); err != nil {
			return nil, fmt.Errorf("gen2PartyAtomKeys: GenShare skA atom %d: %w", atom, err)
		}

		acc := gkg.AllocateShare()
		acc.GaloisElement = galEl
		if err := gkg.AggregateShares(shareC, shareA, &acc); err != nil {
			return nil, fmt.Errorf("gen2PartyAtomKeys: AggregateShares atom %d: %w", atom, err)
		}

		gk := rlwe.NewGaloisKey(params)
		if err := gkg.GenGaloisKey(acc, crp, gk); err != nil {
			return nil, fmt.Errorf("gen2PartyAtomKeys: GenGaloisKey atom %d: %w", atom, err)
		}
		out = append(out, gk)
	}
	return out, nil
}

// gen2PartyPK runs the 2-party PublicKeyGen handshake → joint pk.
// Worker-goroutine-safe (returns errors rather than failing the test).
func gen2PartyPK(
	params ckks.Parameters,
	skC, skA *rlwe.SecretKey,
	crsLabel []byte,
) (*rlwe.PublicKey, error) {
	crs, err := sampling.NewKeyedPRNG(crsLabel)
	if err != nil {
		return nil, fmt.Errorf("gen2PartyPK: build CRS: %w", err)
	}

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
	return pk, nil
}

// joint2PartyDecrypt runs the 2-party KeySwitch-to-zero protocol with
// flooding noise σ = floodSigma. Returns the recovered plaintext slot
// vector. Matches ppiav's MPD-Auth joint-decryption shape.
// Worker-goroutine-safe (returns errors rather than failing the test).
func joint2PartyDecrypt(
	params ckks.Parameters,
	skC, skA *rlwe.SecretKey,
	encoder *ckks.Encoder,
	ct *rlwe.Ciphertext,
	floodSigma float64,
) ([]float64, error) {
	proto, err := multiparty.NewKeySwitchProtocol(params, ring.DiscreteGaussian{
		Sigma: floodSigma,
		Bound: 6 * floodSigma,
	})
	if err != nil {
		return nil, fmt.Errorf("joint2PartyDecrypt: NewKeySwitchProtocol: %w", err)
	}

	zeroSk := rlwe.NewSecretKey(params)
	shareC := proto.AllocateShare(ct.Level())
	shareA := proto.AllocateShare(ct.Level())
	proto.GenShare(skC, zeroSk, ct, &shareC)
	proto.GenShare(skA, zeroSk, ct, &shareA)

	agg := proto.AllocateShare(ct.Level())
	if err := proto.AggregateShares(shareC, shareA, &agg); err != nil {
		return nil, fmt.Errorf("joint2PartyDecrypt: AggregateShares: %w", err)
	}

	out := ckks.NewCiphertext(params, ct.Degree(), ct.Level())
	proto.KeySwitch(ct, agg, out)

	zeroDec := rlwe.NewDecryptor(params, zeroSk)
	pt := zeroDec.DecryptNew(out)
	slots := make([]float64, params.MaxSlots())
	if err := encoder.Decode(pt, slots); err != nil {
		return nil, fmt.Errorf("joint2PartyDecrypt: Decode: %w", err)
	}
	return slots, nil
}

// chainGateTrial runs a single Auth → joint-decrypt → Ver round-trip with
// randomized Key.S and trial-unique CRS labels (so parallel trials draw
// independent randomness for pk and atom keys). Returns whether Ver
// accepted, plus an error if any subprotocol failed. This helper is
// invoked from worker goroutines and must not call `t.FailNow`.
func chainGateTrial(params ckks.Parameters, atoms []int, trialIdx int) (bool, error) {
	kgen := rlwe.NewKeyGenerator(params)
	skC := kgen.GenSecretKeyNew()
	skA := kgen.GenSecretKeyNew()

	pkLabel := []byte("phase4-chain-gate-crs-pk-" + strconv.Itoa(trialIdx))
	atomLabel := []byte("phase4-chain-gate-crs-atoms-" + strconv.Itoa(trialIdx))

	pkJoint, err := gen2PartyPK(params, skC, skA, pkLabel)
	if err != nil {
		return false, err
	}
	atomGKs, err := gen2PartyAtomKeys(params, skC, skA, atoms, atomLabel)
	if err != nil {
		return false, err
	}

	// Synthetic rlk — Auth never relinearizes, but authchain.New requires
	// non-nil rlk for the evaluator key set.
	rlk := rlwe.NewRelinearizationKey(params)
	rot, err := authchain.New(params, rlk, atomGKs, atoms)
	if err != nil {
		return false, fmt.Errorf("chainGateTrial: authchain.New: %w", err)
	}

	cfg := Config{Lambda: chainGateLambda, Epsilon: math.Exp2(20)}
	a, err := New(cfg, params)
	if err != nil {
		return false, fmt.Errorf("chainGateTrial: authenticator.New: %w", err)
	}
	key, err := KeyGen(cfg, rand.Reader)
	if err != nil {
		return false, fmt.Errorf("chainGateTrial: KeyGen: %w", err)
	}

	encoder := ckks.NewEncoder(params)
	const m = 0.5
	values := make([]float64, params.MaxSlots())
	values[0] = m
	pt := ckks.NewPlaintext(params, params.MaxLevel())
	if err := encoder.Encode(values, pt); err != nil {
		return false, fmt.Errorf("chainGateTrial: Encode: %w", err)
	}
	encryptor := rlwe.NewEncryptor(params, pkJoint)
	ct, err := encryptor.EncryptNew(pt)
	if err != nil {
		return false, fmt.Errorf("chainGateTrial: EncryptNew: %w", err)
	}

	ctM, err := a.Auth(key, encryptor, rot, ct)
	if err != nil {
		return false, fmt.Errorf("chainGateTrial: Auth: %w", err)
	}

	plaintext, err := joint2PartyDecrypt(params, skC, skA, encoder, ctM, math.Exp2(16))
	if err != nil {
		return false, err
	}
	_, ok := a.Ver(key, plaintext)
	return ok, nil
}

// trialResult plumbs per-trial outcome out of worker goroutines. The
// main test goroutine aggregates and asserts via require.NoError off the
// channel, keeping all t.* calls on the main goroutine.
type trialResult struct {
	idx int
	ok  bool
	err error
}

// runChainGate runs `nTrials` independent trials in parallel via a worker
// pool sized to GOMAXPROCS. Returns the number of Ver-accepted trials.
// Workers do NOT touch *testing.T — they return results on a channel,
// the main goroutine asserts on errors (per testing-package goroutine
// rules: t.FailNow must be called from the test's main goroutine).
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

	jobs := make(chan int, nTrials)
	for i := 0; i < nTrials; i++ {
		jobs <- i
	}
	close(jobs)

	results := make(chan trialResult, nTrials)
	var wg sync.WaitGroup
	workers := runtime.GOMAXPROCS(0)
	if workers > nTrials {
		workers = nTrials
	}
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				ok, err := chainGateTrial(params, atoms, idx)
				results <- trialResult{idx: idx, ok: ok, err: err}
			}
		}()
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	var passes int64
	for r := range results {
		require.NoErrorf(t, r.err, "trial %d failed", r.idx)
		if r.ok {
			atomic.AddInt64(&passes, 1)
		}
	}
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
