package authchain

import (
	"math"
	"math/bits"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

// testParams returns the unit-test CKKS profile used by every authchain
// test. LogN=14 keeps memory low locally; the LogN=16 gate runs on the VPS
// (per `feedback_no_logn15_local`).
func testParams(t *testing.T) ckks.Parameters {
	t.Helper()
	lit := ckks.ParametersLiteral{
		LogN:            14,
		LogQ:            []int{55, 40, 40},
		LogP:            []int{55, 55},
		LogDefaultScale: 40,
		RingType:        ring.Standard,
	}
	p, err := ckks.NewParametersFromLiteral(lit)
	require.NoError(t, err)
	return p
}

// testAtoms returns the canonical eval-level base-2 atoms for λ=128
// trimmed to the test's actual λ. Mirrors `Params.AuthAtoms()` without
// importing `internal/protocol` (avoids a test-only import cycle if the
// protocol package ever pulls authchain in).
func testAtoms(lambda int) []int {
	if lambda <= 1 {
		return nil
	}
	max := lambda - 1
	out := make([]int, 0, bits.UintSize)
	for a := 1; a <= max; a <<= 1 {
		out = append(out, a)
	}
	return out
}

// genAtomKeysMultiparty runs a 2-party multi-party `GaloisKeyGenProtocol`
// handshake at the supplied atoms (negative galEls, eval level) and
// returns the aggregated `*rlwe.GaloisKey` per atom. Replicates the same
// shape VAgent's `AggregateGaloisShares` produces.
func genAtomKeysMultiparty(
	t *testing.T,
	params ckks.Parameters,
	skC, skA *rlwe.SecretKey,
	atoms []int,
) []*rlwe.GaloisKey {
	t.Helper()
	crs, err := sampling.NewKeyedPRNG([]byte("authchain-test-crs"))
	require.NoError(t, err)

	gkg := multiparty.NewGaloisKeyGenProtocol(params)
	out := make([]*rlwe.GaloisKey, len(atoms))
	for i, atom := range atoms {
		galEl := params.GaloisElement(-atom)
		crp := gkg.SampleCRP(crs)

		shareC := gkg.AllocateShare()
		shareA := gkg.AllocateShare()
		require.NoError(t, gkg.GenShare(skC, galEl, crp, &shareC))
		require.NoError(t, gkg.GenShare(skA, galEl, crp, &shareA))

		agg := gkg.AllocateShare()
		require.NoError(t, gkg.AggregateShares(shareC, shareA, &agg))

		gk := rlwe.NewGaloisKey(params)
		require.NoError(t, gkg.GenGaloisKey(agg, crp, gk))
		out[i] = gk
	}
	return out
}

func TestDecompose(t *testing.T) {
	cases := []struct {
		j        int
		expected []int
	}{
		{0, nil},
		{1, []int{1}},
		{2, []int{2}},
		{3, []int{1, 2}},
		{5, []int{1, 4}},
		{7, []int{1, 2, 4}},
		{8, []int{8}},
		{127, []int{1, 2, 4, 8, 16, 32, 64}},
		// Negative cases: sign is stripped; we only assert popcount
		// (binary expansion order matches |j|, but the test guards the
		// popcount invariant explicitly below).
		{-1, nil},
		{-127, nil},
	}
	for _, c := range cases {
		got := Decompose(c.j)
		assert.Equal(t, bits.OnesCount(uint(absInt(c.j))), len(got), "popcount mismatch for j=%d", c.j)
		if c.expected != nil {
			assert.Equal(t, c.expected, got, "binary expansion mismatch for j=%d", c.j)
		}
	}
}

func absInt(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func TestRotateNew_MatchesDirectKey(t *testing.T) {
	params := testParams(t)
	const lambda = 128
	atoms := testAtoms(lambda)

	// Two-party multi-party handshake to mint atom keys + a joint sk for
	// decryption. Matches the production VAgent + VClient handshake shape
	// under the lattigo-hierkeys split.
	kgen := rlwe.NewKeyGenerator(params)
	skC := kgen.GenSecretKeyNew()
	skA := kgen.GenSecretKeyNew()
	atomGKs := genAtomKeysMultiparty(t, params, skC, skA, atoms)

	rlk := rlwe.NewRelinearizationKey(params)
	ev, err := New(params, rlk, atomGKs, atoms)
	require.NoError(t, err)

	// Joint sk = sk_c + sk_a (single combined key for single-party
	// decryption — matches the chain-rotation correctness test in the
	// authenticator's chain_noise_gate_test.go).
	skJoint := rlwe.NewSecretKey(params)
	params.RingQP().Add(skC.Value, skA.Value, skJoint.Value)
	dec := rlwe.NewDecryptor(params, skJoint)

	// Encrypt a ciphertext with non-zero values across slots so a
	// rotation is observable on multiple slots.
	encoder := ckks.NewEncoder(params)
	// Use sk-encryption so we don't have to run the multi-party PK gen
	// just for a correctness baseline.
	encryptor := rlwe.NewEncryptor(params, skJoint)
	values := make([]float64, params.MaxSlots())
	for i := 0; i < lambda; i++ {
		values[i] = 0.01 * float64(i+1)
	}
	pt := ckks.NewPlaintext(params, params.MaxLevel())
	require.NoError(t, encoder.Encode(values, pt))
	ct, err := encryptor.EncryptNew(pt)
	require.NoError(t, err)

	// Sample representative j values (sparse coverage; the
	// authenticator's end-to-end test exercises all `j ∈ [1, λ)`).
	js := []int{1, 2, 3, 5, 7, 17, 64, 100, 127}
	for _, j := range js {
		rotated, err := ev.RotateNew(ct, -j)
		require.NoErrorf(t, err, "RotateNew(-%d)", j)

		got := make([]float64, params.MaxSlots())
		require.NoError(t, encoder.Decode(dec.DecryptNew(rotated), got))

		// Chain-rotation by -j: slot 0 lands at slot j; slot k lands at
		// slot (k+j) mod (N/2). The Lattigo `RotateNew(ct, -j)`
		// convention.
		nSlots := params.MaxSlots()
		for k := 0; k < lambda; k++ {
			dst := (k + j) % nSlots
			assert.InDelta(t, values[k], got[dst], 1e-2,
				"j=%d chain-rotate: slot %d should land at slot %d (popcount=%d)",
				j, k, dst, bits.OnesCount(uint(j)))
		}
	}
}

func TestRotateNew_ZeroIsIdentity(t *testing.T) {
	params := testParams(t)
	const lambda = 8
	atoms := testAtoms(lambda)

	kgen := rlwe.NewKeyGenerator(params)
	skC := kgen.GenSecretKeyNew()
	skA := kgen.GenSecretKeyNew()
	atomGKs := genAtomKeysMultiparty(t, params, skC, skA, atoms)
	rlk := rlwe.NewRelinearizationKey(params)
	ev, err := New(params, rlk, atomGKs, atoms)
	require.NoError(t, err)

	skJoint := rlwe.NewSecretKey(params)
	params.RingQP().Add(skC.Value, skA.Value, skJoint.Value)
	encryptor := rlwe.NewEncryptor(params, skJoint)
	encoder := ckks.NewEncoder(params)
	values := make([]float64, params.MaxSlots())
	values[0] = 0.5
	pt := ckks.NewPlaintext(params, params.MaxLevel())
	require.NoError(t, encoder.Encode(values, pt))
	ct, err := encryptor.EncryptNew(pt)
	require.NoError(t, err)

	rotated, err := ev.RotateNew(ct, 0)
	require.NoError(t, err)
	require.NotNil(t, rotated)

	dec := rlwe.NewDecryptor(params, skJoint)
	got := make([]float64, params.MaxSlots())
	require.NoError(t, encoder.Decode(dec.DecryptNew(rotated), got))
	assert.InDelta(t, 0.5, got[0], 1e-3, "RotateNew(ct, 0) must preserve slot 0")
}

func TestNew_RejectsMismatch(t *testing.T) {
	params := testParams(t)
	rlk := rlwe.NewRelinearizationKey(params)

	_, err := New(params, nil, nil, []int{1})
	require.Error(t, err, "nil rlk must error")

	_, err = New(params, rlk, nil, nil)
	require.Error(t, err, "empty atoms must error")

	_, err = New(params, rlk, []*rlwe.GaloisKey{rlwe.NewGaloisKey(params)}, []int{1, 2})
	require.Error(t, err, "atom/key count mismatch must error")
}

// Ensure that no spurious errors arise even when math.Exp2(20)-level
// epsilon-scale plaintext values are rotated. Defensive: catches
// surprising ckks evaluator failures at level boundaries.
func TestRotateNew_HighSlotMagnitudes(t *testing.T) {
	params := testParams(t)
	const lambda = 8
	atoms := testAtoms(lambda)

	kgen := rlwe.NewKeyGenerator(params)
	skC := kgen.GenSecretKeyNew()
	skA := kgen.GenSecretKeyNew()
	atomGKs := genAtomKeysMultiparty(t, params, skC, skA, atoms)
	rlk := rlwe.NewRelinearizationKey(params)
	ev, err := New(params, rlk, atomGKs, atoms)
	require.NoError(t, err)

	skJoint := rlwe.NewSecretKey(params)
	params.RingQP().Add(skC.Value, skA.Value, skJoint.Value)
	encryptor := rlwe.NewEncryptor(params, skJoint)
	encoder := ckks.NewEncoder(params)
	values := make([]float64, params.MaxSlots())
	for i := 0; i < lambda; i++ {
		values[i] = math.Exp2(8) * float64(i+1)
	}
	pt := ckks.NewPlaintext(params, params.MaxLevel())
	require.NoError(t, encoder.Encode(values, pt))
	ct, err := encryptor.EncryptNew(pt)
	require.NoError(t, err)

	rotated, err := ev.RotateNew(ct, -3)
	require.NoError(t, err)
	require.NotNil(t, rotated)
}
