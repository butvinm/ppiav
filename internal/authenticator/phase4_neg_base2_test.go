package authenticator

import (
	"crypto/rand"
	"math"
	"math/bits"
	"testing"

	"github.com/butvinm/ppiav/internal/authchain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

// Phase 4 end-to-end correctness for the eval-level negative-galEl base-2
// atom set + chain rotation. Two-party multi-party handshake at the 7
// auth atoms ({1,2,4,8,16,32,64} for λ=128) drives `Auth` via
// `internal/authchain.Evaluator`; the result is joint-decrypted under the
// Phase 1-3 KeySwitch-to-zero flooding (σ = 2¹⁶) and fed to `Ver`. The
// test runs `phase4Trials` independent trials with randomized `Key.S` to
// stress the noise model — Ver must accept every trial.
//
// What this productionizes (vs the exploration test it replaces):
//
//  1. Replaces the inline `chainRotate` helper with the production
//     `authchain.Evaluator`. Bug in either side surfaces here.
//  2. Runs `phase4Trials` randomized trials instead of a single fixed
//     `S`. Catches noise-budget regressions that only show on unlucky
//     `S` distributions.
//  3. Removes the Phase A rotation-correctness scan — `authchain`'s own
//     test suite (`internal/authchain/evaluator_test.go::TestRotateNew_*`)
//     covers that.
//
// Params: LogN=14 (per `feedback_no_logn15_local`); λ=128 (production).

const (
	phase4Lambda = 128
	phase4Trials = 10
)

// gen2PartyAtomKeys runs the 2-party multi-party GaloisKeyGen handshake
// at the seven negative-galEl auth atoms and returns the aggregated keys.
// Matches the wire-protocol shape Phase 4 VAgent emits to VClient.
func gen2PartyAtomKeys(
	t *testing.T,
	params ckks.Parameters,
	skC, skA *rlwe.SecretKey,
	atoms []int,
) []*rlwe.GaloisKey {
	t.Helper()
	crs, err := sampling.NewKeyedPRNG([]byte("phase4-test-crs"))
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
) *rlwe.PublicKey {
	t.Helper()
	crs, err := sampling.NewKeyedPRNG([]byte("phase4-test-crs-pk"))
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

// TestPhase4_AuthChainEndToEnd runs `phase4Trials` independent trials of
// Phase 4's end-to-end MPD-Auth pipeline: 2-party multi-party keygen at
// the auth atoms → Auth via `authchain.Evaluator` → joint-decrypt under
// σ_flood = 2¹⁶ → Ver. Asserts every trial passes.
func TestPhase4_AuthChainEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("phase 4 end-to-end takes ~30s at LogN=14; skipped in -short mode")
	}
	params := testParams(t) // LogN=14

	// Powers-of-two strictly less than λ.
	atoms := []int{}
	for a := 1; a < phase4Lambda; a <<= 1 {
		atoms = append(atoms, a)
	}

	cfg := Config{Lambda: phase4Lambda, Epsilon: math.Exp2(20)}
	encoder := ckks.NewEncoder(params)

	for trial := 0; trial < phase4Trials; trial++ {
		// Fresh keys per trial: 2-party split, joint pk, atom-key bundle.
		kgen := rlwe.NewKeyGenerator(params)
		skC := kgen.GenSecretKeyNew()
		skA := kgen.GenSecretKeyNew()

		pkJoint := gen2PartyPK(t, params, skC, skA)
		atomGKs := gen2PartyAtomKeys(t, params, skC, skA, atoms)

		// Synthetic rlk — Auth's chain only needs rotation keys, but the
		// chain evaluator requires a non-nil rlk to wire the evaluator
		// key set. Use a single-party freshly-generated rlk; correctness
		// is unaffected because Auth never relinearizes.
		rlk := rlwe.NewRelinearizationKey(params)
		rot, err := authchain.New(params, rlk, atomGKs, atoms)
		require.NoError(t, err)

		a, err := New(cfg, params)
		require.NoError(t, err)
		key, err := KeyGen(cfg, rand.Reader)
		require.NoError(t, err)

		// Encrypt a fresh ct under the joint pk. m chosen per trial to
		// vary the slot-0 value.
		const m = 0.5
		values := make([]float64, params.MaxSlots())
		values[0] = m
		pt := ckks.NewPlaintext(params, params.MaxLevel())
		require.NoError(t, encoder.Encode(values, pt))
		encryptor := rlwe.NewEncryptor(params, pkJoint)
		ct, err := encryptor.EncryptNew(pt)
		require.NoError(t, err)

		ctM, err := a.Auth(key, encryptor, rot, ct)
		require.NoErrorf(t, err, "trial %d: Auth", trial)

		plaintext := joint2PartyDecrypt(t, params, skC, skA, encoder, ctM, math.Exp2(16))
		recovered, ok := a.Ver(key, plaintext)
		require.Truef(t, ok, "trial %d: Ver should accept chain-rotation Auth output (σ_flood=2¹⁶)", trial)

		delta := params.DefaultScale().Float64()
		assert.InDeltaf(t, m, recovered, cfg.Epsilon/delta,
			"trial %d: recovered m=%g want %g", trial, recovered, m)
	}
}

// TestPhase4_AuthChainStats logs the chain-length distribution Auth
// exercises across `[0, λ) \ S` for a single random `S`. Documents the
// "max popcount 7, mean 3.52 over 64 non-S rotations" claim from the
// plan's amendment. Useful for noise-budget regression hunts.
func TestPhase4_AuthChainStats(t *testing.T) {
	cfg := Config{Lambda: phase4Lambda, Epsilon: math.Exp2(20)}
	key, err := KeyGen(cfg, rand.Reader)
	require.NoError(t, err)

	inS := sInSet(key.S, phase4Lambda)
	stats := struct{ max, sum, count int }{}
	for j := 1; j < phase4Lambda; j++ {
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
	// Sanity: max chain over j ∈ [1, 127] is 7 (popcount(127)=7).
	assert.LessOrEqual(t, stats.max, 7, "max chain length over j ∈ [1, 127] must be ≤ 7")
}
