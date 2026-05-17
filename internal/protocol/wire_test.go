package protocol

import (
	"encoding/json"
	"testing"

	hierkeys "github.com/butvinm/lattigo-hierkeys"
	"github.com/butvinm/lattigo-hierkeys/llkn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

// smallCKKS returns the smallest CKKS parameter set used by the
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

// smallLLKN returns a 2-level LLKN hierarchy on top of `smallCKKS`,
// matching the shape `Defaults()` builds at production sizes. A single
// 40-bit master P-prime is enough to exercise the top-level CRP/share
// machinery without ballooning test runtime.
func smallLLKN(t *testing.T, eval ckks.Parameters) llkn.Parameters {
	t.Helper()
	p, err := llkn.NewParameters(eval.Parameters, [][]int{{40}})
	require.NoError(t, err)
	return p
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

// dualPKShares returns a freshly generated (ShareEval, ShareTop) pair
// drawn from independent eval-level and top-level multiparty PK protocols
// against the same `smallCKKS` / `smallLLKN` pair. Used by both the
// VClient and VAgent PK-share round-trip tests below.
func dualPKShares(t *testing.T) (multiparty.PublicKeyGenShare, multiparty.PublicKeyGenShare) {
	t.Helper()
	eval := smallCKKS(t)
	top := smallLLKN(t, eval)

	crs := testCRS(t)

	// Eval-level share.
	skEval := rlwe.NewKeyGenerator(eval).GenSecretKeyNew()
	pkgEval := multiparty.NewPublicKeyGenProtocol(eval)
	crpEval := pkgEval.SampleCRP(crs)
	shareEval := pkgEval.AllocateShare()
	pkgEval.GenShare(skEval, crpEval, &shareEval)

	// Top-level share.
	skTop := rlwe.NewKeyGenerator(top.Top()).GenSecretKeyNew()
	pkgTop := multiparty.NewPublicKeyGenProtocol(top.Top())
	crpTop := pkgTop.SampleCRP(crs)
	shareTop := pkgTop.AllocateShare()
	pkgTop.GenShare(skTop, crpTop, &shareTop)

	return shareEval, shareTop
}

func TestVClientPKShareBinaryRoundTrip(t *testing.T) {
	shareEval, shareTop := dualPKShares(t)

	original := VClientPKShare{ShareEval: shareEval, ShareTop: shareTop}
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
	shareEval, shareTop := dualPKShares(t)

	original := VAgentPKShare{ShareEval: shareEval, ShareTop: shareTop}
	data, err := original.MarshalBinary()
	require.NoError(t, err)

	var got VAgentPKShare
	require.NoError(t, got.UnmarshalBinary(data))
	again, err := got.MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t, data, again)
}

// A truncated dual-PK payload (only the eval section, no top length
// prefix) must error out rather than silently leaving `ShareTop` zeroed.
func TestVClientPKShareUnmarshalShortTop(t *testing.T) {
	shareEval, _ := dualPKShares(t)
	evalBytes, err := shareEval.MarshalBinary()
	require.NoError(t, err)

	// Header + eval body, missing the top length prefix.
	buf := make([]byte, 0, 4+len(evalBytes))
	buf = append(buf, 0, 0, 0, 0)
	// Patch the 4-byte length to len(evalBytes).
	buf[0] = byte(len(evalBytes) >> 24)
	buf[1] = byte(len(evalBytes) >> 16)
	buf[2] = byte(len(evalBytes) >> 8)
	buf[3] = byte(len(evalBytes))
	buf = append(buf, evalBytes...)

	var got VClientPKShare
	require.Error(t, got.UnmarshalBinary(buf))
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

// galoisSharesForAtoms returns one `GaloisKeyGenShare` per atom, drawn
// against `params` for `GaloisElement(sign * atom)`. The shares are
// produced from a single secret-key share (single-party handshake);
// the wire-format tests only need well-formed share bodies, not a
// multi-party aggregation.
func galoisSharesForAtoms(t *testing.T, params rlwe.Parameters, atoms []int, sign int) []multiparty.GaloisKeyGenShare {
	t.Helper()
	sk := rlwe.NewKeyGenerator(params).GenSecretKeyNew()
	proto := multiparty.NewGaloisKeyGenProtocol(params)
	crs := testCRS(t)
	shares := make([]multiparty.GaloisKeyGenShare, len(atoms))
	for i, a := range atoms {
		crp := proto.SampleCRP(crs)
		s := proto.AllocateShare()
		require.NoError(t, proto.GenShare(sk, params.GaloisElement(sign*a), crp, &s))
		shares[i] = s
	}
	return shares
}

func TestVClientGaloisSharesBinaryRoundTrip(t *testing.T) {
	eval := smallCKKS(t)
	top := smallLLKN(t, eval)

	master := galoisSharesForAtoms(t, top.Top(), []int{1, 4, 16}, +1)

	original := VClientGaloisShares{MasterShares: master}
	data, err := original.MarshalBinary()
	require.NoError(t, err)
	require.NotEmpty(t, data)

	var got VClientGaloisShares
	require.NoError(t, got.UnmarshalBinary(data))
	require.Len(t, got.MasterShares, len(master))

	again, err := got.MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t, data, again, "VClientGaloisShares.MarshalBinary must be deterministic across round-trips")
}

func TestVClientGaloisSharesUnmarshalShortHeader(t *testing.T) {
	var got VClientGaloisShares
	require.Error(t, got.UnmarshalBinary([]byte{0x00, 0x01}))
}

// An empty share list must round-trip cleanly (4 zero bytes — master count 0).
func TestVClientGaloisSharesUnmarshalEmpty(t *testing.T) {
	original := VClientGaloisShares{}
	data, err := original.MarshalBinary()
	require.NoError(t, err)
	require.Equal(t, []byte{0, 0, 0, 0}, data)

	var got VClientGaloisShares
	require.NoError(t, got.UnmarshalBinary(data))
	assert.Empty(t, got.MasterShares)
}

// A malicious header that claims many more shares than the remaining
// payload can possibly contain must be rejected before the
// `make([]GaloisKeyGenShare, count)` allocation runs.
func TestVClientGaloisSharesUnmarshalCountExceedsPayload(t *testing.T) {
	// master count = 0xFFFFFFFF, no further bytes → 1 byte after the header.
	data := []byte{0xff, 0xff, 0xff, 0xff, 0x00}
	var got VClientGaloisShares
	require.Error(t, got.UnmarshalBinary(data))
}

// buildInferEvalKeysFixture builds a complete `InferEvalKeys` payload
// using single-party multiparty handshakes — RLK at eval level, PKTop at
// top level, plus one `*hierkeys.MasterKey` per supplied infer atom drawn
// against the top-level params with the standard `+atom` convention. The
// returned eval/top params are kept around for tests that want to assert
// shape (e.g. checking that the round-tripped Galois elements match the
// freshly-generated atoms).
func buildInferEvalKeysFixture(t *testing.T, atoms []int) (InferEvalKeys, ckks.Parameters, llkn.Parameters) {
	t.Helper()
	eval := smallCKKS(t)
	top := smallLLKN(t, eval)

	// RLK at eval level (single-party shortcut; the wire format only
	// requires a marshal-able relinearization key, not a multi-party one).
	skEval := rlwe.NewKeyGenerator(eval).GenSecretKeyNew()
	rlk := rlwe.NewKeyGenerator(eval).GenRelinearizationKeyNew(skEval)

	// PKTop at top level (also single-party here).
	skTop := rlwe.NewKeyGenerator(top.Top()).GenSecretKeyNew()
	pkTop := rlwe.NewKeyGenerator(top.Top()).GenPublicKeyNew(skTop)

	// One MasterKey per atom — derive a raw Galois key at top level and
	// convert via `GaloisKeyToMasterKey`.
	masterKeys := make(map[int]*hierkeys.MasterKey, len(atoms))
	topKgen := rlwe.NewKeyGenerator(top.Top())
	for _, a := range atoms {
		galEl := top.Top().GaloisElement(a)
		gk := topKgen.GenGaloisKeyNew(galEl, skTop)
		mk, err := hierkeys.GaloisKeyToMasterKey(top.Top(), gk)
		require.NoError(t, err)
		masterKeys[a] = mk
	}

	return InferEvalKeys{RLK: rlk, PKTop: pkTop, GKSMaster: masterKeys}, eval, top
}

func TestInferEvalKeysBinaryRoundTrip(t *testing.T) {
	atoms := []int{1, 4, 16}
	original, _, top := buildInferEvalKeysFixture(t, atoms)

	data, err := original.MarshalBinary()
	require.NoError(t, err)
	require.NotEmpty(t, data)

	var got InferEvalKeys
	require.NoError(t, got.UnmarshalBinary(data))
	require.NotNil(t, got.RLK)
	require.NotNil(t, got.PKTop)
	require.Len(t, got.GKSMaster, len(atoms))

	// Each atom survives round-trip, keyed identically, and its underlying
	// Galois element matches `top.GaloisElement(+atom)`.
	for _, a := range atoms {
		mk, ok := got.GKSMaster[a]
		require.Truef(t, ok, "atom %d missing after round-trip", a)
		require.NotNil(t, mk)
		assert.Equalf(t, top.Top().GaloisElement(a), mk.GaloisElement(),
			"MasterKey for atom %d has wrong Galois element", a)
	}

	// Deterministic: re-marshaling produces the same bytes (atoms are
	// sorted on the wire so the iteration order is stable).
	again, err := got.MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t, data, again, "InferEvalKeys.MarshalBinary must be deterministic across round-trips")
}

func TestInferEvalKeysUnmarshalTruncated(t *testing.T) {
	var got InferEvalKeys
	require.Error(t, got.UnmarshalBinary([]byte{0x00}))
}

func TestInferEvalKeysMarshalRejectsNilRLK(t *testing.T) {
	_, _, top := buildInferEvalKeysFixture(t, nil)
	skTop := rlwe.NewKeyGenerator(top.Top()).GenSecretKeyNew()
	pkTop := rlwe.NewKeyGenerator(top.Top()).GenPublicKeyNew(skTop)

	k := InferEvalKeys{RLK: nil, PKTop: pkTop, GKSMaster: map[int]*hierkeys.MasterKey{}}
	_, err := k.MarshalBinary()
	require.Error(t, err)
}

func TestInferEvalKeysMarshalRejectsNilPKTop(t *testing.T) {
	eval := smallCKKS(t)
	sk := rlwe.NewKeyGenerator(eval).GenSecretKeyNew()
	rlk := rlwe.NewKeyGenerator(eval).GenRelinearizationKeyNew(sk)

	k := InferEvalKeys{RLK: rlk, PKTop: nil, GKSMaster: map[int]*hierkeys.MasterKey{}}
	_, err := k.MarshalBinary()
	require.Error(t, err)
}

func TestInferEvalKeysEmptyMasterMap(t *testing.T) {
	original, _, _ := buildInferEvalKeysFixture(t, nil)

	data, err := original.MarshalBinary()
	require.NoError(t, err)

	var got InferEvalKeys
	require.NoError(t, got.UnmarshalBinary(data))
	assert.NotNil(t, got.RLK)
	assert.NotNil(t, got.PKTop)
	assert.Empty(t, got.GKSMaster)
}

// EncryptedImage, InferenceResult and AuthenticatedResult marshal as the
// bare `*rlwe.Ciphertext` (no JSON envelope) per the wire convention in
// internal/vservice/http.go's handleInfer and internal/vagent/http.go's
// SSE handler. The three messages have no `MarshalBinary` of their own —
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
	cases := []Verdict{VerdictAccept, VerdictReject, VerdictUnknown, VerdictResultAuthFailed}
	for _, v := range cases {
		original := VerdictNotification{Verdict: v}
		data, err := json.Marshal(original)
		require.NoError(t, err)
		var got VerdictNotification
		require.NoError(t, json.Unmarshal(data, &got))
		assert.Equal(t, original, got)
	}
}
