package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/butvinm/ppiav/internal/protocol"
	"github.com/butvinm/ppiav/internal/vagent"
	"github.com/butvinm/ppiav/internal/vclient"
	"github.com/butvinm/ppiav/internal/vservice"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// TestKeygenToMacToInferPipeline exercises the full Task-10 artifact
// pipeline at LogN=14: run the multi-party handshake in-process, write
// every artifact to a temp workdir via writeKeygenArtifacts, then rebuild
// VAgent + VService from the on-disk files via NewWithState and confirm
// they can run BuildAuthenticatedCt + Infer end-to-end.
//
// The test does NOT spawn the binary — it drives the same helpers the
// per-step subcommands use, which gives the same artifact-shape coverage
// at a fraction of the cost (no subprocess spawn, no per-step JSON write,
// no Orion dir).
func TestKeygenToMacToInferPipeline(t *testing.T) {
	params := smallCLIParams(t)
	dir := t.TempDir()

	// --- in-process keygen --------------------------------------------------
	agent, err := vagent.New(params)
	require.NoError(t, err)
	svc := vservice.New(params)
	sid, err := svc.OpenSession()
	require.NoError(t, err)
	require.NoError(t, agent.OpenSession(sid))
	client, err := vclient.New(params, sid)
	require.NoError(t, err)

	// PK — dual level handshake.
	cPK, err := client.GenPKShare()
	require.NoError(t, err)
	aPK, err := agent.GenPKShare(sid)
	require.NoError(t, err)
	require.NoError(t, agent.AggregatePK(sid, cPK))
	require.NoError(t, client.AggregatePK(aPK))

	// RLK rounds.
	cR1, err := client.GenRLKShareRound1()
	require.NoError(t, err)
	aR1, err := agent.GenRLKShareRound1(sid)
	require.NoError(t, err)
	require.NoError(t, agent.AggregateRLKRound1(sid, cR1))
	require.NoError(t, client.AggregateRLKRound1(aR1))
	cR2, err := client.GenRLKShareRound2()
	require.NoError(t, err)
	_, err = agent.GenRLKShareRound2(sid)
	require.NoError(t, err)
	require.NoError(t, agent.AggregateRLKRound2(sid, cR2))

	// Dual-atom-set Galois handshake.
	cAuthShares, cInferShares, _, _, err := client.GenAuthAndInferShares()
	require.NoError(t, err)
	_, _, _, _, err = agent.GenAuthAndInferShares(sid)
	require.NoError(t, err)
	clientShares := protocol.VClientGaloisShares{
		AuthAtomShares:  cAuthShares,
		InferAtomShares: cInferShares,
	}
	rlk, pkTop, gksMasterInfer, err := agent.AggregateGaloisShares(sid, clientShares)
	require.NoError(t, err)
	require.NoError(t, svc.StoreEvalKeys(sid, rlk, pkTop, gksMasterInfer))

	// --- persist via writeKeygenArtifacts -----------------------------------
	clientState, err := client.ExportState()
	require.NoError(t, err)
	agentState, err := agent.ExportState(sid)
	require.NoError(t, err)
	svcState, err := svc.ExportState(sid)
	require.NoError(t, err)
	require.NoError(t, writeKeygenArtifacts(dir, params, sid, clientState, agentState, svcState))

	// Every Task-10 artifact must land on disk. gks_infer.bin is written
	// in all modes — even synthetic-x² (no ExtraRotationIndices) produces
	// a well-formed empty container that the loader can read back.
	wantFiles := []string{
		artifactSID, artifactParams,
		artifactPKEval, artifactPKTop,
		artifactSKClient, artifactSKAgent,
		artifactRLK, artifactGKSAuth, artifactGKSMasterInfer, artifactGKSInfer,
		artifactMacKey,
	}
	for _, name := range wantFiles {
		info, err := os.Stat(filepath.Join(dir, name))
		require.NoError(t, err, "missing artifact %s", name)
		// gks_infer.bin may be the well-formed empty container (no
		// ExtraRotationIndices in synthetic-x² mode) — its byte count is
		// the MemEvaluationKeySet header; still non-zero in practice.
		assert.GreaterOrEqual(t, info.Size(), int64(0), "%s must exist", name)
	}

	// --- rebuild VAgent from disk (mac path) --------------------------------
	pkEval, err := readPublicKey(dir, artifactPKEval)
	require.NoError(t, err)
	pkTopDisk, err := readPublicKey(dir, artifactPKTop)
	require.NoError(t, err)
	rlkDisk, err := readRelinearizationKey(dir)
	require.NoError(t, err)
	gksAuth, err := readGaloisKeys(dir, artifactGKSAuth)
	require.NoError(t, err)
	gksMasterDisk, err := readMasterKeys(dir, artifactGKSMasterInfer)
	require.NoError(t, err)
	gksInfer, err := readGaloisKeys(dir, artifactGKSInfer)
	require.NoError(t, err)
	skA, err := readSecretKey(dir, artifactSKAgent)
	require.NoError(t, err)
	macKey, err := readMacKey(dir)
	require.NoError(t, err)
	skC, err := readSecretKey(dir, artifactSKClient)
	require.NoError(t, err)

	require.NotNil(t, pkEval)
	require.NotNil(t, pkTopDisk)
	require.NotNil(t, rlkDisk)
	require.NotEmpty(t, gksAuth, "gks_auth must round-trip a non-empty slice")
	require.NotEmpty(t, gksMasterDisk, "gks_master_infer must round-trip a non-empty map")
	// gksInfer may be nil in synthetic-x² mode (no ExtraRotationIndices).
	// Real Orion runs populate it; the pipeline test runs in synthetic mode.
	_ = gksInfer
	require.NotNil(t, skA)
	require.NotNil(t, skC)

	// Atom-set sanity check: the master-key bundle must cover the
	// canonical InferAtoms set.
	inferAtoms := params.InferAtoms()
	for _, a := range inferAtoms {
		_, ok := gksMasterDisk[a]
		assert.True(t, ok, "atom %d missing from gks_master_infer", a)
	}

	// loadParams() in production returns protocol.Defaults() (λ=128) with
	// CKKS overridden by params.json. The CLI only runs at default λ, so
	// this is acceptable — but the test uses smallCLIParams (λ=8), so we
	// re-use the live `params` directly to keep auth atom counts in sync.
	loadedParams := params
	{
		// Sanity: a real CLI subcommand would call loadParams here; verify
		// it at least succeeds against the persisted envelope.
		_, err := loadParams(dir)
		require.NoError(t, err)
	}

	macAgent, err := vagent.NewWithState(loadedParams, &vagent.ExportedState{
		SID:            sid,
		SkTop:          skA,
		MacKey:         macKey,
		PkAgg:          pkEval,
		PkTop:          pkTopDisk,
		Rlk:            rlkDisk,
		GksAuth:        gksAuth,
		GksMasterInfer: gksMasterDisk,
	})
	require.NoError(t, err)

	// Build an input ciphertext via the original (live) client so we have
	// something for Infer + mac to chew on. Encrypting a single
	// length-MaxSlots vector under pkEval.
	values := make([]float64, loadedParams.CKKS.MaxSlots())
	values[0] = 0.3
	encryptor := rlwe.NewEncryptor(loadedParams.CKKS, pkEval)
	enc := ckks.NewEncoder(loadedParams.CKKS)
	pt := ckks.NewPlaintext(loadedParams.CKKS, loadedParams.CKKS.MaxLevel())
	require.NoError(t, enc.Encode(values, pt))
	inputCt, err := encryptor.EncryptNew(pt)
	require.NoError(t, err)

	// --- rebuild VService from disk (infer path) ----------------------------
	inferSvc, err := vservice.NewWithState(loadedParams, "", &vservice.ExportedState{
		SID:            sid,
		Rlk:            rlkDisk,
		PKTop:          pkTopDisk,
		GksMasterInfer: gksMasterDisk,
		GksInfer:       gksInfer,
	})
	require.NoError(t, err)

	resultCt, err := inferSvc.Infer(sid, inputCt)
	require.NoError(t, err)
	require.NotNil(t, resultCt)

	// Correctness assertion (not just non-nil): synthetic-x² should produce
	// enc(0.09) at slot 0. Reconstruct the joint eval-level sk from the
	// per-party top-level sks loaded from disk, project each to eval, sum
	// the projections, decrypt resultCt, and verify the slot-0 value lands
	// within precision of 0.3² = 0.09. A bug that produces cryptographically
	// well-formed but wrong ciphertext would fail here.
	skCEval, err := loadedParams.ProjectSKToEval(skC)
	require.NoError(t, err)
	skAEval, err := loadedParams.ProjectSKToEval(skA)
	require.NoError(t, err)
	skJointEval := rlwe.NewSecretKey(loadedParams.CKKS)
	loadedParams.CKKS.RingQP().Add(skCEval.Value, skAEval.Value, skJointEval.Value)

	dec := rlwe.NewDecryptor(loadedParams.CKKS, skJointEval)
	decoded := make([]float64, loadedParams.CKKS.MaxSlots())
	require.NoError(t, enc.Decode(dec.DecryptNew(resultCt), decoded))
	assert.InDelta(t, 0.09, decoded[0], 1e-3, "synthetic-x² Infer must yield 0.3² at slot 0")

	// mac path must consume the rebuilt VAgent.
	authCt, err := macAgent.BuildAuthenticatedCt(sid, resultCt)
	require.NoError(t, err)
	require.NotNil(t, authCt)

	// Cross-check that gks_auth came back with the same atom count the
	// canonical AuthAtoms() set demands.
	require.Equal(t, len(loadedParams.AuthAtoms()), len(gksAuth))

	// Confirm gks_master_infer hierkeys cookie set survived round-trip.
	for atom, mk := range gksMasterDisk {
		require.NotNil(t, mk, "MasterKey for atom %d is nil after round-trip", atom)
	}
}
