package protocol

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// Binary round-trip tests for wire messages are deferred to Phase 3
// (HTTP transport). The Phase 1–2 in-process orchestrator passes these
// structs by value/pointer and never marshals. Tests are kept as skipped
// placeholders so the gap remains visible.

func TestSessionOpenBinaryRoundTrip(t *testing.T) {
	t.Skip("binary round-trip is a Phase-3 HTTP-transport concern; Phase 1–2 pass these structs in-process")
}

func TestVerificationSessionBinaryRoundTrip(t *testing.T) {
	t.Skip("binary round-trip is a Phase-3 HTTP-transport concern; Phase 1–2 pass these structs in-process")
}

func TestVClientPKShareBinaryRoundTrip(t *testing.T) {
	t.Skip("binary round-trip is a Phase-3 HTTP-transport concern; Phase 1–2 pass these structs in-process")
}

func TestVAgentPKShareBinaryRoundTrip(t *testing.T) {
	t.Skip("binary round-trip is a Phase-3 HTTP-transport concern; Phase 1–2 pass these structs in-process")
}

func TestVClientRLKRound1BinaryRoundTrip(t *testing.T) {
	t.Skip("binary round-trip is a Phase-3 HTTP-transport concern; Phase 1–2 pass these structs in-process")
}

func TestVAgentRLKRound1BinaryRoundTrip(t *testing.T) {
	t.Skip("binary round-trip is a Phase-3 HTTP-transport concern; Phase 1–2 pass these structs in-process")
}

func TestVClientRLKRound2BinaryRoundTrip(t *testing.T) {
	t.Skip("binary round-trip is a Phase-3 HTTP-transport concern; Phase 1–2 pass these structs in-process")
}

func TestVClientGaloisKeyShareBinaryRoundTrip(t *testing.T) {
	t.Skip("binary round-trip is a Phase-3 HTTP-transport concern; Phase 1–2 pass these structs in-process")
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

func TestEncryptedImageBinaryRoundTrip(t *testing.T) {
	t.Skip("binary round-trip is a Phase-3 HTTP-transport concern; Phase 1–2 pass these structs in-process")
}

func TestAuthenticatedResultBinaryRoundTrip(t *testing.T) {
	t.Skip("binary round-trip is a Phase-3 HTTP-transport concern; Phase 1–2 pass these structs in-process")
}

func TestPartialDecryptionBinaryRoundTrip(t *testing.T) {
	t.Skip("binary round-trip is a Phase-3 HTTP-transport concern; Phase 1–2 pass these structs in-process")
}

func TestVerdictNotificationBinaryRoundTrip(t *testing.T) {
	t.Skip("binary round-trip is a Phase-3 HTTP-transport concern; Phase 1–2 pass these structs in-process")
}
