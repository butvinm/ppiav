package vclient

import (
	"math"
	"testing"

	"github.com/butvinm/ppiav/internal/authenticator"
	"github.com/butvinm/ppiav/internal/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// smallParams builds the unit-test profile: LogN=14 (8192 slots), λ=8 so
// |S|=4 and 7 rotation keys, FloodSigma=2^16. Kept here (not in test
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
	return protocol.Params{
		CKKS: ckksParams,
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
	assert.NotNil(t, c.skShare, "sk_c must be generated in New")
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
