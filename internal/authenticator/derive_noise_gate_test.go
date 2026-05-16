// σ_flood noise-budget gate for the design-A production path: Auth uses
// hierkeys-derived atom keys (negative-target derivation from a positive
// base-4 master set), not raw multi-party Galois keys.
//
// Why this exists alongside chain_noise_gate_test.go:
//   - The raw-key gate is the FLOOR reference (atom keys carry B_ks noise).
//   - This gate exercises what production actually ships: each atom key
//     carries √chain_length × B_ks noise (chain length 13–22 for negative
//     base-2 targets decomposed via positive base-4 atoms at LogN=14/16).
//   - σ_flood = 2¹⁶ may or may not still fit. This file is how we find out.
//
// Params: LogN=14, λ=128 (production). LLKN schedule mirrors
// `protocol.DefaultLLKN{LogPHK,Base}` so the test exercises the same key
// shape as the production deployment — but built inline to avoid the
// authenticator → protocol import cycle (protocol imports authenticator).
package authenticator

import (
	"crypto/rand"
	"fmt"
	"math"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/butvinm/lattigo-hierkeys"
	"github.com/butvinm/lattigo-hierkeys/llkn"
	"github.com/butvinm/ppiav/internal/authchain"
	"github.com/butvinm/ppiav/internal/testutil"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

var randReader = rand.Reader

// Mirror protocol.DefaultLLKN{LogPHK,Base} inline. Keep in sync if the
// production schedule ever moves (today both are pinned to LogN16_D15_P6).
var (
	deriveGateLLKNLogPHK = []int{55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55}
	deriveGateLLKNBase   = 4
)

// masterAtomsForGate returns the positive base-4 master set for the test's
// LogN. Mirrors protocol.Params.MasterAtoms() without importing protocol.
func masterAtomsForGate(eval ckks.Parameters) []int {
	return hierkeys.MasterRotationsForBase(deriveGateLLKNBase, eval.MaxSlots())
}

// gen2PartyMasterKeys runs the 2-party multi-party GaloisKeyGen handshake
// at the TOP-LEVEL master atom set and returns the aggregated MasterKeys.
// Mirrors what VClient + VAgent emit + aggregate in production.
func gen2PartyMasterKeys(
	topParams rlwe.Parameters,
	skCTop, skATop *rlwe.SecretKey,
	atoms []int,
	crsLabel []byte,
) (map[int]*hierkeys.MasterKey, error) {
	crs, err := sampling.NewKeyedPRNG(crsLabel)
	if err != nil {
		return nil, fmt.Errorf("gen2PartyMasterKeys: build CRS: %w", err)
	}

	gkg := multiparty.NewGaloisKeyGenProtocol(topParams)
	out := make(map[int]*hierkeys.MasterKey, len(atoms))
	for _, atom := range atoms {
		galEl := topParams.GaloisElement(atom)
		crp := gkg.SampleCRP(crs)

		shareC := gkg.AllocateShare()
		shareA := gkg.AllocateShare()
		if err := gkg.GenShare(skCTop, galEl, crp, &shareC); err != nil {
			return nil, fmt.Errorf("gen2PartyMasterKeys: GenShare skC atom %d: %w", atom, err)
		}
		if err := gkg.GenShare(skATop, galEl, crp, &shareA); err != nil {
			return nil, fmt.Errorf("gen2PartyMasterKeys: GenShare skA atom %d: %w", atom, err)
		}

		acc := gkg.AllocateShare()
		acc.GaloisElement = galEl
		if err := gkg.AggregateShares(shareC, shareA, &acc); err != nil {
			return nil, fmt.Errorf("gen2PartyMasterKeys: AggregateShares atom %d: %w", atom, err)
		}

		gk := rlwe.NewGaloisKey(topParams)
		if err := gkg.GenGaloisKey(acc, crp, gk); err != nil {
			return nil, fmt.Errorf("gen2PartyMasterKeys: GenGaloisKey atom %d: %w", atom, err)
		}
		mk, err := hierkeys.GaloisKeyToMasterKey(topParams, gk)
		if err != nil {
			return nil, fmt.Errorf("gen2PartyMasterKeys: GaloisKeyToMasterKey atom %d: %w", atom, err)
		}
		out[atom] = mk
	}
	return out, nil
}

// gen2PartyTopPK runs the 2-party top-level PK handshake.
func gen2PartyTopPK(
	topParams rlwe.Parameters,
	skCTop, skATop *rlwe.SecretKey,
	crsLabel []byte,
) (*rlwe.PublicKey, error) {
	crs, err := sampling.NewKeyedPRNG(crsLabel)
	if err != nil {
		return nil, fmt.Errorf("gen2PartyTopPK: build CRS: %w", err)
	}

	proto := multiparty.NewPublicKeyGenProtocol(topParams)
	crp := proto.SampleCRP(crs)

	shareC := proto.AllocateShare()
	shareA := proto.AllocateShare()
	proto.GenShare(skCTop, crp, &shareC)
	proto.GenShare(skATop, crp, &shareA)

	agg := proto.AllocateShare()
	proto.AggregateShares(shareC, shareA, &agg)

	pk := rlwe.NewPublicKey(topParams)
	proto.GenPublicKey(agg, crp, pk)
	return pk, nil
}

// deriveAuthAtomKeys mirrors vagent.deriveAuthGks: PubToRot + LevelExpansion
// + FinalizeKey across the negative auth atom targets.
func deriveAuthAtomKeys(
	llknParams llkn.Parameters,
	pkTop *rlwe.PublicKey,
	gksMaster map[int]*hierkeys.MasterKey,
	authAtoms []int,
) ([]*rlwe.GaloisKey, error) {
	evalParams := llknParams.Eval()
	topParams := llknParams.Top()
	shift0, err := hierkeys.PubToRot(evalParams, topParams, pkTop)
	if err != nil {
		return nil, fmt.Errorf("deriveAuthAtomKeys: PubToRot: %w", err)
	}
	authTargets := make([]int, len(authAtoms))
	for i, a := range authAtoms {
		authTargets[i] = -a
	}
	llknEval := llkn.NewEvaluator(llknParams)
	exp := llknEval.NewLevelExpansion(0, shift0, gksMaster, authTargets)

	gks := make([]*rlwe.GaloisKey, len(authTargets))
	derrs := make([]error, len(authTargets))

	workers := runtime.GOMAXPROCS(0)
	if workers < 1 {
		workers = 1
	}
	if workers > len(authTargets) {
		workers = len(authTargets)
	}
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for i, r := range authTargets {
		wg.Add(1)
		sem <- struct{}{}
		go func(i, r int) {
			defer wg.Done()
			defer func() { <-sem }()
			mk, err := exp.Derive(r)
			if err != nil {
				derrs[i] = fmt.Errorf("derive %d: %w", r, err)
				return
			}
			gk, err := llknEval.FinalizeKey(mk)
			if err != nil {
				derrs[i] = fmt.Errorf("finalize %d: %w", r, err)
				return
			}
			gks[i] = gk
		}(i, r)
	}
	wg.Wait()
	for _, e := range derrs {
		if e != nil {
			return nil, e
		}
	}
	return gks, nil
}

// derivedChainGateTrial runs one Auth → joint-decrypt → Ver trial using
// hierkeys-derived auth atom keys. Returns Ver acceptance + error.
//
// Mirrors chainGateTrial but builds atom keys via the production path
// (top-level master multi-party + LevelExpansion derivation). The Auth /
// joint-decrypt machinery is identical.
//
// Worker-goroutine-safe.
func derivedChainGateTrial(
	evalParams ckks.Parameters,
	llknParams llkn.Parameters,
	authAtoms []int,
	masterAtoms []int,
	trialIdx int,
) (bool, error) {
	topParams := llknParams.Top()

	// Both parties hold sk_top; sk_eval is the projection.
	kgenTop := rlwe.NewKeyGenerator(topParams)
	skCTop := kgenTop.GenSecretKeyNew()
	skATop := kgenTop.GenSecretKeyNew()
	skCEval, err := llknParams.ProjectToEvalKey(skCTop)
	if err != nil {
		return false, fmt.Errorf("derivedChainGateTrial: project skC: %w", err)
	}
	skAEval, err := llknParams.ProjectToEvalKey(skATop)
	if err != nil {
		return false, fmt.Errorf("derivedChainGateTrial: project skA: %w", err)
	}

	pkLabel := []byte("derive-gate-crs-pk-eval-" + strconv.Itoa(trialIdx))
	pkTopLabel := []byte("derive-gate-crs-pk-top-" + strconv.Itoa(trialIdx))
	masterLabel := []byte("derive-gate-crs-master-" + strconv.Itoa(trialIdx))

	// Eval-level joint pk (drives the v-encryptor in Auth).
	pkJoint, err := gen2PartyPK(evalParams, skCEval, skAEval, pkLabel)
	if err != nil {
		return false, err
	}
	// Top-level joint pk (seeds PubToRot for LevelExpansion).
	pkTop, err := gen2PartyTopPK(topParams, skCTop, skATop, pkTopLabel)
	if err != nil {
		return false, err
	}
	// Master atom keys (top-level multi-party).
	masterKeys, err := gen2PartyMasterKeys(topParams, skCTop, skATop, masterAtoms, masterLabel)
	if err != nil {
		return false, err
	}

	atomGKs, err := deriveAuthAtomKeys(llknParams, pkTop, masterKeys, authAtoms)
	if err != nil {
		return false, err
	}

	// Synthetic rlk — Auth never relinearizes; authchain.New needs non-nil rlk.
	rlk := rlwe.NewRelinearizationKey(evalParams)
	rot, err := authchain.New(evalParams, rlk, atomGKs, authAtoms)
	if err != nil {
		return false, fmt.Errorf("derivedChainGateTrial: authchain.New: %w", err)
	}

	cfg := Config{Lambda: chainGateLambda, Epsilon: math.Exp2(20)}
	a, err := New(cfg, evalParams)
	if err != nil {
		return false, fmt.Errorf("derivedChainGateTrial: authenticator.New: %w", err)
	}
	key, err := KeyGen(cfg, randReader)
	if err != nil {
		return false, fmt.Errorf("derivedChainGateTrial: KeyGen: %w", err)
	}

	encoder := ckks.NewEncoder(evalParams)
	const m = 0.5
	values := make([]float64, evalParams.MaxSlots())
	values[0] = m
	pt := ckks.NewPlaintext(evalParams, evalParams.MaxLevel())
	if err := encoder.Encode(values, pt); err != nil {
		return false, fmt.Errorf("derivedChainGateTrial: Encode: %w", err)
	}
	encryptor := rlwe.NewEncryptor(evalParams, pkJoint)
	ct, err := encryptor.EncryptNew(pt)
	if err != nil {
		return false, fmt.Errorf("derivedChainGateTrial: EncryptNew: %w", err)
	}

	ctM, err := a.Auth(key, encryptor, rot, ct)
	if err != nil {
		return false, fmt.Errorf("derivedChainGateTrial: Auth: %w", err)
	}

	plaintext, err := joint2PartyDecrypt(evalParams, skCEval, skAEval, encoder, ctM, math.Exp2(16))
	if err != nil {
		return false, err
	}

	_, ok := a.Ver(key, plaintext)
	return ok, nil
}

// runDerivedChainGate is the parallel-worker variant of runChainGate for
// the derived-key path. Same trial-result channel pattern; t.FailNow runs
// only from the main goroutine.
func runDerivedChainGate(t *testing.T, nTrials int) int {
	t.Helper()
	evalParams := testParams(t) // LogN=14

	llknParams, err := llkn.NewParameters(evalParams.Parameters, [][]int{deriveGateLLKNLogPHK})
	require.NoError(t, err)

	authAtoms := []int{}
	for a := 1; a < chainGateLambda; a <<= 1 {
		authAtoms = append(authAtoms, a)
	}
	masterAtoms := masterAtomsForGate(evalParams)

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
				ok, err := derivedChainGateTrial(evalParams, llknParams, authAtoms, masterAtoms, idx)
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

// TestDerivedAuthChainNoiseGate: design-A σ_flood gate. Fast variant —
// 100 trials of Auth+Ver with hierkeys-derived atom keys. Asserts every
// trial passes. This is what the user signed off on; if it fails, the
// derived-key noise overflows σ_flood = 2¹⁶ and recalibration is needed.
func TestDerivedAuthChainNoiseGate(t *testing.T) {
	if testing.Short() {
		t.Skip("derived-key σ_flood gate: skipped in -short mode")
	}
	passes := runDerivedChainGate(t, chainGateTrialsFast)
	require.Equalf(t, chainGateTrialsFast, passes,
		"derived-key σ_flood gate (fast): expected all %d trials to pass Ver, got %d",
		chainGateTrialsFast, passes)
}

// TestDerivedAuthChainNoiseGate_Full: 1000-trial canonical gate, gated
// behind PPIAV_RUN_HEAVY. Asserts ≥99.9% Ver pass rate.
func TestDerivedAuthChainNoiseGate_Full(t *testing.T) {
	testutil.RequireHeavy(t, "derived-key σ_flood 1000-trial gate")
	passes := runDerivedChainGate(t, chainGateTrialsFull)
	rate := float64(passes) / float64(chainGateTrialsFull)
	t.Logf("derived-key σ_flood gate (full): %d/%d trials passed (%.4f)", passes, chainGateTrialsFull, rate)
	require.GreaterOrEqualf(t, rate, chainGatePassRate,
		"derived-key σ_flood gate (full): Ver pass rate %.4f below threshold %.4f (%d/%d).",
		rate, chainGatePassRate, passes, chainGateTrialsFull)
}
