package protocol

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaults(t *testing.T) {
	params, err := Defaults()
	require.NoError(t, err)

	assert.Equal(t, 16, params.CKKS.LogN())
	assert.Equal(t, 1<<15, params.CKKS.MaxSlots())
	assert.Equal(t, 15, params.CKKS.MaxLevel())
	assert.InDelta(t, math.Exp2(40), params.CKKS.DefaultScale().Float64(), 1e-3)

	assert.Equal(t, 128, params.Authenticator.Lambda)
	assert.InDelta(t, math.Exp2(20), params.Authenticator.Epsilon, 1e-9)
	assert.InDelta(t, math.Exp2(16), params.FloodSigma, 1e-9)
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	assert.Equal(t, 128, cfg.Lambda)
	assert.InDelta(t, math.Exp2(20), cfg.Epsilon, 1e-9)
}
