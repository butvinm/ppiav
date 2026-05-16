package vclient

import (
	"math"
	"testing"

	"github.com/butvinm/lattigo-hierkeys/llkn"
	"github.com/butvinm/ppiav/internal/authenticator"
	"github.com/butvinm/ppiav/internal/protocol"
	"github.com/butvinm/ppiav/internal/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// imageParams is the LogN=15 profile used for the image round-trip test:
// N/2 = 16384 slots ≥ ImageLen=12288. The smallParams() LogN=14 profile
// (8192 slots) cannot hold the full image — see docs/DESIGN.md
// §`internal/vclient`. Length-rejection tests still use smallParams since
// they bail out before encoding.
func imageParams(t *testing.T) protocol.Params {
	t.Helper()
	lit := ckks.ParametersLiteral{
		LogN:            15,
		LogQ:            []int{55, 40, 40},
		LogP:            []int{55, 55},
		LogDefaultScale: 40,
		RingType:        ring.Standard,
	}
	ckksParams, err := ckks.NewParametersFromLiteral(lit)
	require.NoError(t, err)
	llknParams, err := llkn.NewParameters(ckksParams.Parameters, [][]int{{40}})
	require.NoError(t, err)
	return protocol.Params{
		CKKS:          ckksParams,
		LLKN:          llknParams,
		LLKNBase:      protocol.DefaultLLKNBase,
		Authenticator: authenticator.Config{Lambda: 8, Epsilon: math.Exp2(20)},
		FloodSigma:    math.Exp2(16),
	}
}

func TestEncryptImageRejectsWrongLength(t *testing.T) {
	params := smallParams(t)
	c, err := New(params, protocol.SessionID("img-sid"))
	require.NoError(t, err)
	// Even without keygen, length-validation runs first.
	cases := map[string]int{
		"empty":     0,
		"one short": ImageLen - 1,
		"one long":  ImageLen + 1,
	}
	for name, n := range cases {
		t.Run(name, func(t *testing.T) {
			input := make([]float64, n)
			_, err := c.EncryptImage(input)
			require.Error(t, err)
		})
	}
}

func TestEncryptImageRequiresAggregatePK(t *testing.T) {
	params := smallParams(t)
	c, err := New(params, protocol.SessionID("img-sid-2"))
	require.NoError(t, err)
	input := make([]float64, ImageLen)
	// Length is fine but no encryptor is wired yet.
	_, err = c.EncryptImage(input)
	require.Error(t, err)
}

func TestEncryptImageRoundTripsUnderJointSk(t *testing.T) {
	testutil.RequireHeavy(t, "LogN=15 image round-trip")
	params := imageParams(t)
	c, err := New(params, protocol.SessionID("img-sid-3"))
	require.NoError(t, err)
	stub := newVAgentStub(t, params, protocol.SessionID("img-sid-3"))
	joint, _, _ := runFullKeygen(t, c, stub)

	input := make([]float64, ImageLen)
	for i := range input {
		input[i] = float64(i%128) / 256.0 // bounded, non-trivial pattern
	}
	ct, err := c.EncryptImage(input)
	require.NoError(t, err)
	// Synthetic-x² contract: encrypt at MaxLevel.
	assert.Equal(t, params.CKKS.MaxLevel(), ct.Level())

	dec := rlwe.NewDecryptor(params.CKKS, joint)
	enc := ckks.NewEncoder(params.CKKS)
	got := make([]float64, params.CKKS.MaxSlots())
	require.NoError(t, enc.Decode(dec.DecryptNew(ct), got))

	for i := 0; i < ImageLen; i++ {
		assert.InDelta(t, input[i], got[i], 1e-3, "decrypted slot %d", i)
	}
	// Tail must be zero-padded (within CKKS noise tolerance).
	for i := ImageLen; i < params.CKKS.MaxSlots(); i++ {
		assert.InDelta(t, 0.0, got[i], 1e-3, "padded slot %d", i)
	}
}
