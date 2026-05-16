package vclient

import (
	"math"
	"testing"

	"github.com/butvinm/lattigo-hierkeys/llkn"
	"github.com/butvinm/ppiav/internal/authenticator"
	"github.com/butvinm/ppiav/internal/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// smallParams builds the unit-test profile: LogN=14 (8192 slots), λ=8 so
// |S|=4 and 3 auth atoms ({1,2,4}, since AuthAtoms returns powers of two
// strictly less than λ; at λ=8 that's {1,2,4}), FloodSigma=2^16. The LLKN
// hierarchy is a 1-level extension with a single 40-bit P prime, just
// enough to exercise the dual atom-set keygen path (`InferAtoms` returns
// `{1,4,16,...}` up to half-slots, ascending). Kept here (not in test
// helpers) so each *_test.go file in the package can import it directly.
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
	llknParams, err := llkn.NewParameters(ckksParams.Parameters, [][]int{{40}})
	require.NoError(t, err)
	return protocol.Params{
		CKKS:     ckksParams,
		LLKN:     llknParams,
		LLKNBase: protocol.DefaultLLKNBase,
		Authenticator: authenticator.Config{
			Lambda:  8,
			Epsilon: math.Exp2(20),
		},
		FloodSigma: math.Exp2(16),
	}
}

func TestNewClientPopulatesFields(t *testing.T) {
	params := smallParams(t)
	c, err := New(params, protocol.SessionID("test-sid"))
	require.NoError(t, err)
	assert.Equal(t, protocol.SessionID("test-sid"), c.SessionID())
	assert.NotNil(t, c.skTop, "sk_c (top level) must be generated in New")
	assert.NotNil(t, c.encoder, "encoder must be wired in New")
	assert.Nil(t, c.encryptor, "encryptor must wait for AggregatePK")
	assert.Equal(t, params.Authenticator.Lambda, c.Params().Authenticator.Lambda)
}

func TestNewClientWithEmptySidStillWorks(t *testing.T) {
	// Empty sid → CRS domain is "ppiav-crs/v1|"; deterministic but distinct
	// from any non-empty sid. New does not validate sid format (that's
	// vservice's responsibility per docs/DESIGN.md §`internal/vservice`).
	params := smallParams(t)
	c, err := New(params, protocol.SessionID(""))
	require.NoError(t, err)
	require.NotNil(t, c)
}
