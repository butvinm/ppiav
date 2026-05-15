package ppiav

import (
	"encoding/json"
	"math"
	"testing"

	"github.com/butvinm/ppiav/internal/authenticator"
	"github.com/butvinm/ppiav/internal/protocol"
	"github.com/butvinm/ppiav/internal/vclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// smallParams mirrors the unit-test profile from
// internal/vclient/client_test.go: LogN=14 (8192 slots), λ=8, FloodSigma=2^16.
// The bridge tests cannot import vclient's _test.go helpers, so we replicate
// the literal here. Drift between the two is fine — these tests only need a
// CKKS profile small enough to run quickly under -race.
func smallParams(t *testing.T) protocol.Params {
	t.Helper()
	lit := ckks.ParametersLiteral{
		LogN:            14,
		LogQ:            []int{55, 40, 40},
		LogP:            []int{55, 55},
		LogDefaultScale: 40,
		RingType:        ring.Standard,
	}
	ckksParams, err := ckks.NewParametersFromLiteral(lit)
	require.NoError(t, err)
	return protocol.Params{
		CKKS: ckksParams,
		Authenticator: authenticator.Config{
			Lambda:  8,
			Epsilon: math.Exp2(20),
		},
		FloodSigma: math.Exp2(16),
	}
}

// paramsJSON encodes a protocol.Params into the wire shape produced by
// vservice.writeParams (internal/vservice/http.go's paramsWire). Tests use
// this to feed NewClient through ParseParamsJSON, exercising the same code
// path the browser will use.
func paramsJSON(t *testing.T, p protocol.Params) []byte {
	t.Helper()
	ckksBytes, err := p.CKKS.MarshalJSON()
	require.NoError(t, err)
	out, err := json.Marshal(paramsWire{
		CKKS:                 ckksBytes,
		AuthenticatorLambda:  p.Authenticator.Lambda,
		AuthenticatorEpsilon: p.Authenticator.Epsilon,
		FloodSigma:           p.FloodSigma,
		ExtraRotationIndices: p.ExtraRotationIndices,
		InputLevel:           p.InputLevel,
	})
	require.NoError(t, err)
	return out
}

func TestParseParamsJSONRoundTrip(t *testing.T) {
	want := smallParams(t)
	js := paramsJSON(t, want)
	got, err := ParseParamsJSON(js)
	require.NoError(t, err)
	assert.Equal(t, want.CKKS.LogN(), got.CKKS.LogN())
	assert.Equal(t, want.CKKS.MaxLevel(), got.CKKS.MaxLevel())
	assert.Equal(t, want.Authenticator.Lambda, got.Authenticator.Lambda)
	assert.InDelta(t, want.Authenticator.Epsilon, got.Authenticator.Epsilon, 0)
	assert.InDelta(t, want.FloodSigma, got.FloodSigma, 0)
}

func TestParseParamsJSONRejectsBadInput(t *testing.T) {
	_, err := ParseParamsJSON([]byte("not json"))
	require.Error(t, err)
	_, err = ParseParamsJSON([]byte(`{"ckks": "garbage"}`))
	require.Error(t, err)
}

func TestNewClientStoresHandle(t *testing.T) {
	params := smallParams(t)
	h, err := NewClient(paramsJSON(t, params), "sid-1")
	require.NoError(t, err)
	require.NotZero(t, h)
	defer DeleteClient(h)

	c, err := loadClient(h)
	require.NoError(t, err)
	assert.Equal(t, protocol.SessionID("sid-1"), c.SessionID())
}

func TestNewClientDistinctHandles(t *testing.T) {
	params := smallParams(t)
	js := paramsJSON(t, params)
	h1, err := NewClient(js, "sid-a")
	require.NoError(t, err)
	defer DeleteClient(h1)
	h2, err := NewClient(js, "sid-b")
	require.NoError(t, err)
	defer DeleteClient(h2)
	assert.NotEqual(t, h1, h2, "each NewClient call must yield a fresh handle")
}

func TestDeleteClientIdempotent(t *testing.T) {
	params := smallParams(t)
	h, err := NewClient(paramsJSON(t, params), "sid-del")
	require.NoError(t, err)
	DeleteClient(h)
	DeleteClient(h) // no panic
	_, err = loadClient(h)
	require.Error(t, err, "handle must be gone after DeleteClient")
}

// loadOps for handle-not-found errors on every method.
func TestUnknownHandleErrors(t *testing.T) {
	const bogus uint64 = 999_999_999
	_, err := GenPKShare(bogus)
	require.Error(t, err)
	require.Error(t, AggregatePK(bogus, []byte{0}))
	_, err = GenRLKShareRound1(bogus)
	require.Error(t, err)
	require.Error(t, AggregateRLKRound1(bogus, []byte{0}))
	_, err = GenRLKShareRound2(bogus)
	require.Error(t, err)
	_, err = GenGaloisShares(bogus)
	require.Error(t, err)
	_, err = EncryptImage(bogus, make([]float64, vclient.ImageLen))
	require.Error(t, err)
	_, err = PartialDecrypt(bogus, []byte{0})
	require.Error(t, err)
}

func TestGenPKShareRoundTrip(t *testing.T) {
	params := smallParams(t)
	h, err := NewClient(paramsJSON(t, params), "sid-pk")
	require.NoError(t, err)
	defer DeleteClient(h)

	out, err := GenPKShare(h)
	require.NoError(t, err)
	require.NotEmpty(t, out)

	var got protocol.VClientPKShare
	require.NoError(t, got.UnmarshalBinary(out))
	require.NotNil(t, got.Share)
}

func TestAggregatePKRejectsMalformed(t *testing.T) {
	params := smallParams(t)
	h, err := NewClient(paramsJSON(t, params), "sid-agg-pk")
	require.NoError(t, err)
	defer DeleteClient(h)
	_, err = GenPKShare(h)
	require.NoError(t, err)

	err = AggregatePK(h, []byte{0, 1, 2}) // not a valid VAgentPKShare
	require.Error(t, err)
}

// fullKeygenRoundTrip drives the entire VClient side through the bridge
// against an in-test VAgent stub, then verifies the marshaled wire shapes
// decode back into types Lattigo can aggregate. The point is to prove the
// bridge is a lossless wrapper around vclient, not to reproduce vclient's
// own keygen tests.
func TestFullKeygenRoundTripThroughBridge(t *testing.T) {
	params := smallParams(t)
	sid := protocol.SessionID("sid-full")
	h, err := NewClient(paramsJSON(t, params), string(sid))
	require.NoError(t, err)
	defer DeleteClient(h)

	// Build a matching VAgent stub: same params, same CRS, fresh sk_a.
	crs, err := protocol.NewSessionCRS(sid)
	require.NoError(t, err)
	skA := rlwe.NewKeyGenerator(params.CKKS).GenSecretKeyNew()

	// --- Stage 2b: PK ---
	clientPKBytes, err := GenPKShare(h)
	require.NoError(t, err)
	var clientPK protocol.VClientPKShare
	require.NoError(t, clientPK.UnmarshalBinary(clientPKBytes))

	pkProto := multiparty.NewPublicKeyGenProtocol(params.CKKS)
	agentCRP := pkProto.SampleCRP(crs)
	agentPKShare := pkProto.AllocateShare()
	pkProto.GenShare(skA, agentCRP, &agentPKShare)

	agentPKBytes, err := protocol.VAgentPKShare{Share: agentPKShare}.MarshalBinary()
	require.NoError(t, err)
	require.NoError(t, AggregatePK(h, agentPKBytes))

	// --- Stage 2c round 1: RLK ---
	clientRLK1Bytes, err := GenRLKShareRound1(h)
	require.NoError(t, err)
	var clientRLK1 protocol.VClientRLKRound1
	require.NoError(t, clientRLK1.UnmarshalBinary(clientRLK1Bytes))

	rlkProto := multiparty.NewRelinearizationKeyGenProtocol(params.CKKS)
	agentRLKCRP := rlkProto.SampleCRP(crs)
	agentEphSk, agentRLK1, _ := rlkProto.AllocateShare()
	rlkProto.GenShareRoundOne(skA, agentRLKCRP, agentEphSk, &agentRLK1)

	agentRLK1Bytes, err := protocol.VAgentRLKRound1{Share: agentRLK1}.MarshalBinary()
	require.NoError(t, err)
	require.NoError(t, AggregateRLKRound1(h, agentRLK1Bytes))

	// --- Stage 2c round 2 ---
	clientRLK2Bytes, err := GenRLKShareRound2(h)
	require.NoError(t, err)
	var clientRLK2 protocol.VClientRLKRound2
	require.NoError(t, clientRLK2.UnmarshalBinary(clientRLK2Bytes))

	// --- Stage 2d: Galois shares ---
	galSharesBytes, err := GenGaloisShares(h)
	require.NoError(t, err)
	var galShares protocol.VClientGaloisKeyShare
	require.NoError(t, galShares.UnmarshalBinary(galSharesBytes))
	assert.Equal(t, len(params.RotationIndices()), len(galShares.Shares),
		"bridge must emit one Galois share per rotation label")
}

func TestEncryptImageRequiresAggregatedPK(t *testing.T) {
	params := smallParams(t)
	h, err := NewClient(paramsJSON(t, params), "sid-img-noagg")
	require.NoError(t, err)
	defer DeleteClient(h)

	_, err = EncryptImage(h, make([]float64, vclient.ImageLen))
	require.Error(t, err, "EncryptImage without AggregatePK must fail cleanly")
}

func TestEncryptImageWrongLength(t *testing.T) {
	params := smallParams(t)
	sid := protocol.SessionID("sid-img-len")
	h, err := NewClient(paramsJSON(t, params), string(sid))
	require.NoError(t, err)
	defer DeleteClient(h)

	// Run PK aggregation so the encryptor is wired.
	clientPKBytes, err := GenPKShare(h)
	require.NoError(t, err)
	var clientPK protocol.VClientPKShare
	require.NoError(t, clientPK.UnmarshalBinary(clientPKBytes))
	crs, err := protocol.NewSessionCRS(sid)
	require.NoError(t, err)
	skA := rlwe.NewKeyGenerator(params.CKKS).GenSecretKeyNew()
	pkProto := multiparty.NewPublicKeyGenProtocol(params.CKKS)
	agentCRP := pkProto.SampleCRP(crs)
	agentPKShare := pkProto.AllocateShare()
	pkProto.GenShare(skA, agentCRP, &agentPKShare)
	agentPKBytes, err := protocol.VAgentPKShare{Share: agentPKShare}.MarshalBinary()
	require.NoError(t, err)
	require.NoError(t, AggregatePK(h, agentPKBytes))

	_, err = EncryptImage(h, []float64{1.0, 2.0, 3.0})
	require.Error(t, err, "wrong-length tensor must be rejected by vclient.EncryptImage")
}

func TestEncryptImageProducesValidCiphertext(t *testing.T) {
	params := smallParams(t)
	sid := protocol.SessionID("sid-img-ok")
	h, err := NewClient(paramsJSON(t, params), string(sid))
	require.NoError(t, err)
	defer DeleteClient(h)

	// Aggregate PK first.
	clientPKBytes, err := GenPKShare(h)
	require.NoError(t, err)
	var clientPK protocol.VClientPKShare
	require.NoError(t, clientPK.UnmarshalBinary(clientPKBytes))
	crs, err := protocol.NewSessionCRS(sid)
	require.NoError(t, err)
	skA := rlwe.NewKeyGenerator(params.CKKS).GenSecretKeyNew()
	pkProto := multiparty.NewPublicKeyGenProtocol(params.CKKS)
	agentCRP := pkProto.SampleCRP(crs)
	agentPKShare := pkProto.AllocateShare()
	pkProto.GenShare(skA, agentCRP, &agentPKShare)
	agentPKBytes, err := protocol.VAgentPKShare{Share: agentPKShare}.MarshalBinary()
	require.NoError(t, err)
	require.NoError(t, AggregatePK(h, agentPKBytes))

	tensor := make([]float64, vclient.ImageLen)
	for i := range tensor {
		tensor[i] = float64(i%256) / 255.0
	}
	out, err := EncryptImage(h, tensor)
	require.NoError(t, err)
	require.NotEmpty(t, out)

	var ct rlwe.Ciphertext
	require.NoError(t, ct.UnmarshalBinary(out))
	assert.GreaterOrEqual(t, ct.Level(), 0)
}

func TestPartialDecryptRoundTrip(t *testing.T) {
	params := smallParams(t)
	sid := protocol.SessionID("sid-pd")
	h, err := NewClient(paramsJSON(t, params), string(sid))
	require.NoError(t, err)
	defer DeleteClient(h)

	// Aggregate PK so we can encrypt something to feed back in as a
	// stand-in for an authenticated ciphertext (we are only testing the
	// bridge round-trip, not MPD-Auth correctness — that's covered in
	// internal/vclient/partial_decrypt_test.go).
	_, err = GenPKShare(h)
	require.NoError(t, err)
	crs, err := protocol.NewSessionCRS(sid)
	require.NoError(t, err)
	skA := rlwe.NewKeyGenerator(params.CKKS).GenSecretKeyNew()
	pkProto := multiparty.NewPublicKeyGenProtocol(params.CKKS)
	agentCRP := pkProto.SampleCRP(crs)
	agentPKShare := pkProto.AllocateShare()
	pkProto.GenShare(skA, agentCRP, &agentPKShare)
	agentPKBytes, err := protocol.VAgentPKShare{Share: agentPKShare}.MarshalBinary()
	require.NoError(t, err)
	require.NoError(t, AggregatePK(h, agentPKBytes))

	tensor := make([]float64, vclient.ImageLen)
	encBytes, err := EncryptImage(h, tensor)
	require.NoError(t, err)

	// Use the encrypted image as the authenticated ciphertext input —
	// the bridge is type-blind, so any valid ciphertext exercises the
	// marshal path.
	pdBytes, err := PartialDecrypt(h, encBytes)
	require.NoError(t, err)
	require.NotEmpty(t, pdBytes)

	var pd protocol.PartialDecryption
	require.NoError(t, pd.UnmarshalBinary(pdBytes))
}

func TestPartialDecryptRejectsMalformedCiphertext(t *testing.T) {
	params := smallParams(t)
	h, err := NewClient(paramsJSON(t, params), "sid-pd-bad")
	require.NoError(t, err)
	defer DeleteClient(h)

	_, err = PartialDecrypt(h, []byte{0, 1, 2, 3})
	require.Error(t, err)
}
