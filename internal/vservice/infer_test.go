package vservice

import (
	"math"
	"testing"

	"github.com/butvinm/ppiav/internal/authenticator"
	"github.com/butvinm/ppiav/internal/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// smallParams builds a LogN=14 Params bundle for the in-process x² test.
// We deliberately skip protocol.Defaults() (LogN=16) so the unit suite
// stays fast; the multi-party handshake is exercised in Task 8.
//
// The LLKN hierarchy is built via `protocol.BuildLLKNParams` so the wire
// schedule matches the strict `DefaultLLKNLogPHK` check in
// `writeManifest` — tests must drive the same canonical builder production
// uses or the /params HTTP path will reject the response.
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
	llknParams, err := protocol.BuildLLKNParams(ckksParams)
	require.NoError(t, err)
	return protocol.Params{
		CKKS:          ckksParams,
		LLKN:          llknParams,
		LLKNBase:      protocol.DefaultLLKNBase,
		Authenticator: authenticator.DefaultConfig(),
		FloodSigma:    math.Exp2(16),
	}
}

func TestInferSquaresInputAndDropsOneLevel(t *testing.T) {
	params := smallParams(t)
	svc := New(params)

	sid, err := svc.OpenSession()
	require.NoError(t, err)

	// Single-party keys are enough for the x² circuit — the multi-party
	// handshake is the orchestrator's job. x² uses no rotations, so we
	// pass nil pkTop / nil gksMaster; deriveGksInfer short-circuits
	// when ExtraRotationIndices is empty.
	kgen := rlwe.NewKeyGenerator(params.CKKS)
	sk, pk := kgen.GenKeyPairNew()
	rlk := kgen.GenRelinearizationKeyNew(sk)
	require.NoError(t, svc.StoreEvalKeys(sid, rlk, nil, nil))

	encoder := ckks.NewEncoder(params.CKKS)
	encryptor := rlwe.NewEncryptor(params.CKKS, pk)
	decryptor := rlwe.NewDecryptor(params.CKKS, sk)

	// Encrypt m=0.3 at slot 0 (zeros elsewhere) at the max level.
	values := make([]float64, params.CKKS.MaxSlots())
	values[0] = 0.3
	pt := ckks.NewPlaintext(params.CKKS, params.CKKS.MaxLevel())
	require.NoError(t, encoder.Encode(values, pt))
	inputCt, err := encryptor.EncryptNew(pt)
	require.NoError(t, err)

	inputLevel := inputCt.Level()
	outCt, err := svc.Infer(sid, inputCt)
	require.NoError(t, err)
	assert.Equal(t, inputLevel-1, outCt.Level(), "x² + rescale must consume exactly one level")

	decoded := make([]float64, params.CKKS.MaxSlots())
	require.NoError(t, encoder.Decode(decryptor.DecryptNew(outCt), decoded))
	assert.InDelta(t, 0.09, decoded[0], 1e-4, "decrypted slot 0 should equal 0.3² within ε")
}

func TestInferUnknownSid(t *testing.T) {
	params := smallParams(t)
	svc := New(params)

	_, err := svc.Infer(protocol.SessionID("nope"), nil)
	require.Error(t, err)
}

func TestInferRequiresStoreEvalKeys(t *testing.T) {
	params := smallParams(t)
	svc := New(params)

	sid, err := svc.OpenSession()
	require.NoError(t, err)
	// No StoreEvalKeys call → Infer must error cleanly.
	_, err = svc.Infer(sid, nil)
	require.Error(t, err)
}
