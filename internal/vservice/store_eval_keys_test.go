package vservice

import (
	"testing"

	hierkeys "github.com/butvinm/lattigo-hierkeys"
	"github.com/butvinm/ppiav/internal/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

// buildMultiPartyTransmission generates a 2-party top-level handshake
// against the supplied params:
//
//   - Each party draws skTop_i; the ideal sk = sum is computed for
//     verification only.
//   - A collective `pkTop` is finalised via `multiparty.PublicKeyGenProtocol`.
//   - For each master atom (`params.InferAtoms()`), a collective
//     `*rlwe.GaloisKey` is finalised via `multiparty.GaloisKeyGenProtocol`
//     at the top-level params with `+atom` Galois elements, then converted
//     via `hierkeys.GaloisKeyToMasterKey` into the `gksMasterInfer` map.
//
// Returns `(pkTop, gksMasterInfer, skIdealTop)`. `skIdealTop` is the
// joint top-level secret-key (sum of per-party shares); the caller
// projects it down to eval level for decryption-side verification.
func buildMultiPartyTransmission(t *testing.T, params protocol.Params) (
	*rlwe.PublicKey,
	map[int]*hierkeys.MasterKey,
	*rlwe.SecretKey,
) {
	t.Helper()
	topParams := params.LLKN.Top()
	atoms := params.InferAtoms()

	crs, err := sampling.NewKeyedPRNG([]byte("ppiav-vservice-funceq-test-crs"))
	require.NoError(t, err)

	// Two parties' top-level secret-key shares.
	const N = 2
	sks := make([]*rlwe.SecretKey, N)
	for i := 0; i < N; i++ {
		sks[i] = rlwe.NewKeyGenerator(topParams).GenSecretKeyNew()
	}
	skIdeal := rlwe.NewSecretKey(topParams)
	for _, sk := range sks {
		topParams.RingQP().Add(skIdeal.Value, sk.Value, skIdeal.Value)
	}

	// Collective top-level public key.
	pkProto := multiparty.NewPublicKeyGenProtocol(topParams)
	pkCRP := pkProto.SampleCRP(crs)
	pkAgg := pkProto.AllocateShare()
	for _, sk := range sks {
		share := pkProto.AllocateShare()
		pkProto.GenShare(sk, pkCRP, &share)
		pkProto.AggregateShares(pkAgg, share, &pkAgg)
	}
	pkTop := rlwe.NewPublicKey(topParams)
	pkProto.GenPublicKey(pkAgg, pkCRP, pkTop)

	// Collective master rotation keys (one per infer atom).
	gkg := multiparty.NewGaloisKeyGenProtocol(topParams)
	gksMaster := make(map[int]*hierkeys.MasterKey, len(atoms))
	for _, atom := range atoms {
		galEl := topParams.GaloisElement(atom)
		crp := gkg.SampleCRP(crs)
		acc := gkg.AllocateShare()
		acc.GaloisElement = galEl
		for _, sk := range sks {
			share := gkg.AllocateShare()
			require.NoError(t, gkg.GenShare(sk, galEl, crp, &share))
			require.NoError(t, gkg.AggregateShares(acc, share, &acc))
		}
		gk := rlwe.NewGaloisKey(topParams)
		require.NoError(t, gkg.GenGaloisKey(acc, crp, gk))
		mk, err := hierkeys.GaloisKeyToMasterKey(topParams, gk)
		require.NoError(t, err)
		gksMaster[atom] = mk
	}

	return pkTop, gksMaster, skIdeal
}

// TestStoreEvalKeysFunctionalEquivalence drives the full Task-7 path on
// the synthetic-x² Service with a non-empty ExtraRotationIndices:
//
//  1. Run a 2-party top-level multi-party handshake to produce
//     `(pkTop, gksMasterInfer)`.
//  2. Project the ideal top-level sk down to eval level and synthesise
//     an eval-level relinearization key under that secret.
//  3. Call `StoreEvalKeys(sid, rlk, pkTop, gksMasterInfer)` — VService
//     runs `hierkeys.LevelExpansion + FinalizeKey` for every target.
//  4. Encrypt a fresh ciphertext under `skEval`, rotate it via the
//     in-process *ckks.Evaluator (built from the derived gks_infer),
//     decrypt under `skEval`, and verify the rotation matches the
//     plaintext rotated by `r` within the protocol's precision bound.
//
// Byte-equality with freshly-generated multi-party Galois keys is NOT
// asserted: hierarchical derivation produces a different `a`-part than
// per-rotation CRPs (see the Task 7 spec). The test asserts functional
// equivalence — the derived key correctly implements the target rotation.
func TestStoreEvalKeysFunctionalEquivalence(t *testing.T) {
	params := smallParams(t)
	// Pin a small set of target rotations to keep the LogN=14 test fast.
	// Both signs are exercised: positive (matches Orion's `+k`) and
	// negative (matches the authenticator's `-j`). The ExtraRotationIndices
	// slice carries the convention's pre-negated form, so:
	//   - extraIndex=-1  → derive +1  → key for GaloisElement(+1)
	//   - extraIndex=+1  → derive -1  → key for GaloisElement(-1)
	params.ExtraRotationIndices = []int{-1, -4, +1}

	svc := New(params)
	sid, err := svc.OpenSession()
	require.NoError(t, err)

	pkTop, gksMasterInfer, skIdealTop := buildMultiPartyTransmission(t, params)

	// Eval-level secret derived from the joint top-level sk.
	skEval, err := params.LLKN.ProjectToEvalKey(skIdealTop)
	require.NoError(t, err)
	rlk := rlwe.NewKeyGenerator(params.CKKS).GenRelinearizationKeyNew(skEval)

	require.NoError(t, svc.StoreEvalKeys(sid, rlk, pkTop, gksMasterInfer))

	// Verify timing was recorded (concurrent path runs in well under a
	// second at LogN=14 with 3 targets, but the elapsed counter must be
	// non-negative and the session must be marked as having derivation
	// metadata.)
	secs, ok := svc.DeriveGksInferSeconds(sid)
	require.True(t, ok, "DeriveGksInferSeconds must return ok for an active session")
	assert.GreaterOrEqual(t, secs, 0.0)

	// Reach into the session to drive the evaluator directly. Going
	// through Infer would re-run x² instead of a rotation, which doesn't
	// exercise the derived keys.
	svc.mu.Lock()
	sess := svc.sessions[sid]
	svc.mu.Unlock()
	require.NotNil(t, sess)
	require.NotNil(t, sess.eval, "session must hold a *ckks.Evaluator after StoreEvalKeys")
	require.Len(t, sess.gksInfer, len(params.ExtraRotationIndices),
		"derived gks_infer must have one entry per ExtraRotationIndices")

	// Encrypt fresh values under the joint skEval and rotate via the
	// derived key for each target. We use sk-encryption (instead of
	// rebuilding pkEval) — both produce ciphertexts decryptable under
	// the same sk.
	encoder := ckks.NewEncoder(params.CKKS)
	encryptor := rlwe.NewEncryptor(params.CKKS, skEval)
	decryptor := rlwe.NewDecryptor(params.CKKS, skEval)

	slots := params.CKKS.MaxSlots()
	values := make([]float64, slots)
	for i := range values {
		values[i] = float64(i+1) / float64(slots)
	}
	pt := ckks.NewPlaintext(params.CKKS, params.CKKS.MaxLevel())
	require.NoError(t, encoder.Encode(values, pt))
	inputCt, err := encryptor.EncryptNew(pt)
	require.NoError(t, err)

	// For each ExtraRotationIndices entry e, the derived key is for
	// `GaloisElement(-e)`. Calling RotateNew(ct, -e) lands on the same
	// element and yields the plaintext rotated by `-e` slots.
	for _, extraIndex := range params.ExtraRotationIndices {
		rotBy := -extraIndex
		out, err := sess.eval.RotateNew(inputCt, rotBy)
		require.NoErrorf(t, err, "RotateNew by %d must succeed via derived gks_infer", rotBy)

		decoded := make([]float64, slots)
		require.NoError(t, encoder.Decode(decryptor.DecryptNew(out), decoded))

		// 1e-4 is the published precision bound across the small CKKS
		// profiles used elsewhere in this package (see infer_test's
		// InDelta).
		for i := 0; i < slots; i++ {
			want := values[(i+rotBy+slots)%slots]
			assert.InDeltaf(t, want, decoded[i], 1e-4,
				"rotation by %d at slot %d: want %g got %g", rotBy, i, want, decoded[i])
		}
	}
}

// TestStoreEvalKeysRejectsEmptyMasterWithRotations checks the input
// validation: if the params declare rotations to derive but the caller
// supplies an empty gksMasterInfer (or nil pkTop), `StoreEvalKeys` must
// fail loudly instead of silently producing a Service without rotation
// keys.
func TestStoreEvalKeysRejectsEmptyMasterWithRotations(t *testing.T) {
	params := smallParams(t)
	params.ExtraRotationIndices = []int{-1}

	svc := New(params)
	sid, err := svc.OpenSession()
	require.NoError(t, err)

	kgen := rlwe.NewKeyGenerator(params.CKKS)
	rlk := kgen.GenRelinearizationKeyNew(kgen.GenSecretKeyNew())

	// nil pkTop with non-empty rotation list → error.
	err = svc.StoreEvalKeys(sid, rlk, nil, map[int]*hierkeys.MasterKey{})
	require.Error(t, err)

	// Open a fresh session — the first call left the existing one in a
	// half-set state (no evaluator built), and a second StoreEvalKeys on
	// the same sid would re-trigger derivation but not surface a clean
	// failure mode in the absence of `gksMasterInfer`.
	sid2, err := svc.OpenSession()
	require.NoError(t, err)
	topKgen := rlwe.NewKeyGenerator(params.LLKN.Top())
	pkTop := topKgen.GenPublicKeyNew(topKgen.GenSecretKeyNew())
	err = svc.StoreEvalKeys(sid2, rlk, pkTop, nil)
	require.Error(t, err, "nil gksMasterInfer with non-empty rotations must fail")
}
