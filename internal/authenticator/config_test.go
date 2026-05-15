package authenticator

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	assert.Equal(t, 128, cfg.Lambda)
	assert.InDelta(t, math.Exp2(20), cfg.Epsilon, 1e-9)
}

func TestConfigValidate(t *testing.T) {
	cases := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{name: "default ok", cfg: DefaultConfig(), wantErr: false},
		{name: "lambda=2 ok", cfg: Config{Lambda: 2, Epsilon: 1}, wantErr: false},
		{name: "lambda=16 ok", cfg: Config{Lambda: 16, Epsilon: 1}, wantErr: false},
		{name: "lambda=0", cfg: Config{Lambda: 0, Epsilon: 1}, wantErr: true},
		{name: "lambda<0", cfg: Config{Lambda: -2, Epsilon: 1}, wantErr: true},
		{name: "lambda odd 7", cfg: Config{Lambda: 7, Epsilon: 1}, wantErr: true},
		{name: "lambda odd 1", cfg: Config{Lambda: 1, Epsilon: 1}, wantErr: true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.validate()
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestNewRejectsInvalidConfig(t *testing.T) {
	params := testParams(t)
	_, err := New(Config{Lambda: 7, Epsilon: 1}, params)
	require.Error(t, err)
	_, err = New(Config{Lambda: 0, Epsilon: 1}, params)
	require.Error(t, err)
	_, err = New(Config{Lambda: 16, Epsilon: 1}, params)
	require.NoError(t, err)
}

// testParams builds a small CKKS parameter set for tests (LogN=14).
// Shared across the authenticator package's tests.
func testParams(t *testing.T) ckks.Parameters {
	t.Helper()
	logQ := []int{55, 40, 40, 40}
	logP := []int{55, 55}
	p, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            14,
		LogQ:            logQ,
		LogP:            logP,
		LogDefaultScale: 40,
		RingType:        ring.Standard,
	})
	require.NoError(t, err)
	return p
}
