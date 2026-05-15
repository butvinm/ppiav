package protocol

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

// smallCKKS returns the smallest CKKS parameter set used by the Phase-3
// wire-format unit tests. LogN=10 keeps each round-trip fast while still
// exercising the same code paths as production LogN=16.
func smallCKKS(t *testing.T) ckks.Parameters {
	t.Helper()
	lit := ckks.ParametersLiteral{
		LogN:            10,
		LogQ:            []int{40, 40},
		LogP:            []int{40},
		LogDefaultScale: 30,
		RingType:        ring.Standard,
	}
	params, err := ckks.NewParametersFromLiteral(lit)
	require.NoError(t, err)
	return params
}

// testCRS returns a fresh KeyedPRNG with a deterministic seed for CRP
// sampling. The exact seed does not matter — round-trip tests just need
// any reproducible CRS source.
func testCRS(t *testing.T) *sampling.KeyedPRNG {
	t.Helper()
	prng, err := sampling.NewKeyedPRNG([]byte("ppiav-wire-test-seed"))
	require.NoError(t, err)
	return prng
}

func TestVClientPKShareBinaryRoundTrip(t *testing.T) {
	params := smallCKKS(t)
	kgen := rlwe.NewKeyGenerator(params)
	sk := kgen.GenSecretKeyNew()

	pkg := multiparty.NewPublicKeyGenProtocol(params)
	crp := pkg.SampleCRP(testCRS(t))
	share := pkg.AllocateShare()
	pkg.GenShare(sk, crp, &share)

	original := VClientPKShare{Share: share}
	data, err := original.MarshalBinary()
	require.NoError(t, err)
	require.NotEmpty(t, data)

	var got VClientPKShare
	require.NoError(t, got.UnmarshalBinary(data))

	again, err := got.MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t, data, again)
}

func TestVAgentPKShareBinaryRoundTrip(t *testing.T) {
	params := smallCKKS(t)
	kgen := rlwe.NewKeyGenerator(params)
	sk := kgen.GenSecretKeyNew()

	pkg := multiparty.NewPublicKeyGenProtocol(params)
	crp := pkg.SampleCRP(testCRS(t))
	share := pkg.AllocateShare()
	pkg.GenShare(sk, crp, &share)

	original := VAgentPKShare{Share: share}
	data, err := original.MarshalBinary()
	require.NoError(t, err)

	var got VAgentPKShare
	require.NoError(t, got.UnmarshalBinary(data))
	again, err := got.MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t, data, again)
}

func TestVClientRLKRound1BinaryRoundTrip(t *testing.T) {
	params := smallCKKS(t)
	kgen := rlwe.NewKeyGenerator(params)
	sk := kgen.GenSecretKeyNew()

	proto := multiparty.NewRelinearizationKeyGenProtocol(params)
	crp := proto.SampleCRP(testCRS(t))
	ephSk, share1, _ := proto.AllocateShare()
	proto.GenShareRoundOne(sk, crp, ephSk, &share1)

	original := VClientRLKRound1{Share: share1}
	data, err := original.MarshalBinary()
	require.NoError(t, err)
	require.NotEmpty(t, data)

	var got VClientRLKRound1
	require.NoError(t, got.UnmarshalBinary(data))
	again, err := got.MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t, data, again)
}

func TestVAgentRLKRound1BinaryRoundTrip(t *testing.T) {
	params := smallCKKS(t)
	kgen := rlwe.NewKeyGenerator(params)
	sk := kgen.GenSecretKeyNew()

	proto := multiparty.NewRelinearizationKeyGenProtocol(params)
	crp := proto.SampleCRP(testCRS(t))
	ephSk, share1, _ := proto.AllocateShare()
	proto.GenShareRoundOne(sk, crp, ephSk, &share1)

	original := VAgentRLKRound1{Share: share1}
	data, err := original.MarshalBinary()
	require.NoError(t, err)

	var got VAgentRLKRound1
	require.NoError(t, got.UnmarshalBinary(data))
	again, err := got.MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t, data, again)
}

func TestVClientRLKRound2BinaryRoundTrip(t *testing.T) {
	params := smallCKKS(t)
	kgen := rlwe.NewKeyGenerator(params)
	sk := kgen.GenSecretKeyNew()

	proto := multiparty.NewRelinearizationKeyGenProtocol(params)
	crp := proto.SampleCRP(testCRS(t))
	ephSk, share1, share2 := proto.AllocateShare()
	proto.GenShareRoundOne(sk, crp, ephSk, &share1)
	// Use share1 as the aggregated round-1 input for round 2 (single party
	// here is sufficient to produce a well-formed round-2 share for the
	// wire-format test).
	proto.GenShareRoundTwo(ephSk, sk, share1, &share2)

	original := VClientRLKRound2{Share: share2}
	data, err := original.MarshalBinary()
	require.NoError(t, err)

	var got VClientRLKRound2
	require.NoError(t, got.UnmarshalBinary(data))
	again, err := got.MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t, data, again)
}

func TestVClientGaloisKeyShareBinaryRoundTrip(t *testing.T) {
	params := smallCKKS(t)
	kgen := rlwe.NewKeyGenerator(params)
	sk := kgen.GenSecretKeyNew()

	proto := multiparty.NewGaloisKeyGenProtocol(params)
	crs := testCRS(t)
	labels := []int{-1, -2, -3}
	shares := make([]multiparty.GaloisKeyGenShare, len(labels))
	for i, j := range labels {
		crp := proto.SampleCRP(crs)
		s := proto.AllocateShare()
		require.NoError(t, proto.GenShare(sk, params.GaloisElement(j), crp, &s))
		shares[i] = s
	}

	original := VClientGaloisKeyShare{Shares: shares}
	data, err := original.MarshalBinary()
	require.NoError(t, err)
	require.NotEmpty(t, data)

	var got VClientGaloisKeyShare
	require.NoError(t, got.UnmarshalBinary(data))
	require.Len(t, got.Shares, len(labels))

	again, err := got.MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t, data, again, "VClientGaloisKeyShare.MarshalBinary must be deterministic across round-trips")
}

func TestVClientGaloisKeyShareUnmarshalShortHeader(t *testing.T) {
	var got VClientGaloisKeyShare
	require.Error(t, got.UnmarshalBinary([]byte{0x00, 0x01}))
}

func TestVClientGaloisKeyShareUnmarshalEmpty(t *testing.T) {
	original := VClientGaloisKeyShare{Shares: nil}
	data, err := original.MarshalBinary()
	require.NoError(t, err)

	var got VClientGaloisKeyShare
	require.NoError(t, got.UnmarshalBinary(data))
	assert.Empty(t, got.Shares)
}

// A malicious header that claims many more shares than the remaining
// payload can possibly contain must be rejected before the
// `make([]GaloisKeyGenShare, count)` allocation runs. Without the
// upper-bound guard a 5-byte body could request a multi-GiB slice.
func TestVClientGaloisKeyShareUnmarshalCountExceedsPayload(t *testing.T) {
	// count = 0xFFFFFFFF, no further bytes → 1 byte after the header.
	data := []byte{0xff, 0xff, 0xff, 0xff, 0x00}
	var got VClientGaloisKeyShare
	require.Error(t, got.UnmarshalBinary(data))
}

func TestInferEvalKeysBinaryRoundTrip(t *testing.T) {
	// LogN=10 keeps the test fast; the marshaling code is the same for
	// production LogN=16. Two small rotation indices are enough to exercise
	// the GKS slice path.
	lit := ckks.ParametersLiteral{
		LogN:            10,
		LogQ:            []int{40, 40},
		LogP:            []int{40},
		LogDefaultScale: 30,
		RingType:        ring.Standard,
	}
	params, err := ckks.NewParametersFromLiteral(lit)
	require.NoError(t, err)

	kgen := rlwe.NewKeyGenerator(params)
	sk := kgen.GenSecretKeyNew()
	rlk := kgen.GenRelinearizationKeyNew(sk)

	galEls := params.GaloisElements([]int{-1, -2})
	gks := kgen.GenGaloisKeysNew(galEls, sk)
	require.Len(t, gks, 2)

	original := InferEvalKeys{RLK: rlk, GKS: gks}
	data, err := original.MarshalBinary()
	require.NoError(t, err)
	require.NotEmpty(t, data)

	var got InferEvalKeys
	require.NoError(t, got.UnmarshalBinary(data))
	require.NotNil(t, got.RLK)
	require.Len(t, got.GKS, 2)

	// Galois elements survive the round trip; order is ascending after
	// unmarshal regardless of input order.
	wantElements := map[uint64]bool{}
	for _, gk := range gks {
		wantElements[gk.GaloisElement] = true
	}
	for _, gk := range got.GKS {
		assert.True(t, wantElements[gk.GaloisElement], "Galois element %d should round-trip", gk.GaloisElement)
		assert.Equal(t, gks[0].NthRoot, gk.NthRoot)
	}

	// Re-marshal: deterministic order means the bytes match a second pass.
	again, err := got.MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t, data, again, "InferEvalKeys.MarshalBinary must be deterministic across round-trips")
}

func TestInferEvalKeysUnmarshalTruncated(t *testing.T) {
	var got InferEvalKeys
	require.Error(t, got.UnmarshalBinary([]byte{0x00}))
}

func TestInferEvalKeysEmptyGKS(t *testing.T) {
	lit := ckks.ParametersLiteral{
		LogN:            10,
		LogQ:            []int{40, 40},
		LogP:            []int{40},
		LogDefaultScale: 30,
		RingType:        ring.Standard,
	}
	params, err := ckks.NewParametersFromLiteral(lit)
	require.NoError(t, err)

	kgen := rlwe.NewKeyGenerator(params)
	sk := kgen.GenSecretKeyNew()
	rlk := kgen.GenRelinearizationKeyNew(sk)

	original := InferEvalKeys{RLK: rlk, GKS: nil}
	data, err := original.MarshalBinary()
	require.NoError(t, err)

	var got InferEvalKeys
	require.NoError(t, got.UnmarshalBinary(data))
	assert.NotNil(t, got.RLK)
	assert.Empty(t, got.GKS)
}

// EncryptedImage and AuthenticatedResult marshal as the bare
// `*rlwe.Ciphertext` (no JSON envelope) per the wire convention in
// internal/vservice/http.go's handleImage and internal/vagent/http.go's
// SSE handler. The two messages have no `MarshalBinary` of their own —
// callers serialise `.Ct` directly. Verify the ciphertext round-trips
// here so future drift breaks the build rather than the wire.
func TestEncryptedImageBinaryRoundTrip(t *testing.T) {
	params := smallCKKS(t)
	ct := rlwe.NewCiphertext(params, 1, params.MaxLevel())
	data, err := ct.MarshalBinary()
	require.NoError(t, err)
	require.NotEmpty(t, data)
	got := &rlwe.Ciphertext{}
	require.NoError(t, got.UnmarshalBinary(data))
	again, err := got.MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t, data, again)
}

func TestAuthenticatedResultBinaryRoundTrip(t *testing.T) {
	params := smallCKKS(t)
	ct := rlwe.NewCiphertext(params, 1, params.MaxLevel())
	data, err := ct.MarshalBinary()
	require.NoError(t, err)
	require.NotEmpty(t, data)
	got := &rlwe.Ciphertext{}
	require.NoError(t, got.UnmarshalBinary(data))
	again, err := got.MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t, data, again)
}

func TestPartialDecryptionBinaryRoundTrip(t *testing.T) {
	params := smallCKKS(t)
	kgen := rlwe.NewKeyGenerator(params)
	sk := kgen.GenSecretKeyNew()
	zeroSk := rlwe.NewSecretKey(params)

	// Build a dummy ciphertext at the max level so the KeySwitchProtocol
	// can allocate a level-matching share — Lattigo's GenShare consumes
	// the ciphertext's level when sampling.
	ct := rlwe.NewCiphertext(params, 1, params.MaxLevel())
	proto, err := multiparty.NewKeySwitchProtocol(params, ring.DiscreteGaussian{Sigma: 0, Bound: 0})
	require.NoError(t, err)
	share := proto.AllocateShare(ct.Level())
	proto.GenShare(sk, zeroSk, ct, &share)

	original := PartialDecryption{Share: share}
	data, err := original.MarshalBinary()
	require.NoError(t, err)
	require.NotEmpty(t, data)

	var got PartialDecryption
	require.NoError(t, got.UnmarshalBinary(data))
	again, err := got.MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t, data, again)
}

// VerdictNotification travels as JSON across `POST /api/callback/:sid`.
// Round-trip via encoding/json so handler-side wire shape is locked.
func TestVerdictNotificationJSONRoundTrip(t *testing.T) {
	cases := []Verdict{VerdictAccept, VerdictReject, VerdictUnknown}
	for _, v := range cases {
		original := VerdictNotification{Verdict: v}
		data, err := json.Marshal(original)
		require.NoError(t, err)
		var got VerdictNotification
		require.NoError(t, json.Unmarshal(data, &got))
		assert.Equal(t, original, got)
	}
}
