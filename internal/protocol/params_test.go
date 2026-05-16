package protocol

import (
	"math"
	"testing"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"

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

	// LLKN hierarchy: top-level Q = Q_eval (16) ∪ P_eval (6) = 22 primes,
	// P_top = DefaultLLKNLogPHK (11 primes).
	assert.Equal(t, DefaultLLKNBase, params.LLKNBase)
	require.Equal(t, 2, params.LLKN.NumLevels(), "LLKN hierarchy must be 2-level")
	top := params.LLKN.Top()
	assert.Equal(t, 22, top.QCount(), "top-level QCount = Q_eval + P_eval")
	assert.Equal(t, 11, top.PCount(), "top-level PCount = len(DefaultLLKNLogPHK)")
}

func TestDefaultFloodSigma(t *testing.T) {
	assert.InDelta(t, math.Exp2(16), DefaultFloodSigma, 1e-9)
}

func TestParams_AuthAtoms_DefaultLambda128(t *testing.T) {
	params, err := Defaults()
	require.NoError(t, err)

	// λ=128 → atoms strictly less than 128 → {1, 2, 4, 8, 16, 32, 64}.
	assert.Equal(t, []int{1, 2, 4, 8, 16, 32, 64}, params.AuthAtoms())
}

func TestParams_AuthAtoms_VariedLambda(t *testing.T) {
	params, err := Defaults()
	require.NoError(t, err)

	cases := []struct {
		lambda int
		want   []int
	}{
		{lambda: 0, want: nil},
		{lambda: 1, want: nil},
		{lambda: 2, want: []int{1}},
		{lambda: 3, want: []int{1, 2}},
		{lambda: 8, want: []int{1, 2, 4}},
		{lambda: 16, want: []int{1, 2, 4, 8}},
		{lambda: 64, want: []int{1, 2, 4, 8, 16, 32}},
		{lambda: 128, want: []int{1, 2, 4, 8, 16, 32, 64}},
		{lambda: 129, want: []int{1, 2, 4, 8, 16, 32, 64, 128}},
		{lambda: 256, want: []int{1, 2, 4, 8, 16, 32, 64, 128}},
	}
	for _, c := range cases {
		params.Authenticator.Lambda = c.lambda
		assert.Equalf(t, c.want, params.AuthAtoms(), "lambda=%d", c.lambda)
	}
}

func TestParams_InferAtoms_DefaultsBase4LogN16(t *testing.T) {
	params, err := Defaults()
	require.NoError(t, err)

	// MaxSlots=32768, base=4 → {1,4,16,64,256,1024,4096,16384}.
	want := []int{1, 4, 16, 64, 256, 1024, 4096, 16384}
	assert.Equal(t, want, params.InferAtoms())
}

func TestParams_InferAtoms_PanicsWhenBaseUnset(t *testing.T) {
	params, err := Defaults()
	require.NoError(t, err)
	params.LLKNBase = 0
	// Constructed-from-scratch params with LLKNBase < 2 is a programmer
	// error — every production site stamps LLKNBase: DefaultLLKNBase.
	assert.Panics(t, func() { _ = params.InferAtoms() })
}

func TestParams_ProjectSKToEval_RoundTrip(t *testing.T) {
	params, err := Defaults()
	require.NoError(t, err)

	skTop := rlwe.NewKeyGenerator(params.LLKN.Top()).GenSecretKeyNew()
	skEval, err := params.ProjectSKToEval(skTop)
	require.NoError(t, err)

	// Projected key lives at eval level: QCount=16, PCount=6.
	assert.Equal(t, 16, skEval.LevelQ()+1, "projected sk_eval QCount")
	assert.Equal(t, 6, skEval.LevelP()+1, "projected sk_eval PCount")

	// The first 16 Q-coefficient rows of sk_top are copied byte-identically
	// into the projected sk_eval's Q ring; the next 6 rows are reused as
	// sk_eval.P (the LLKN projection routes Q_top[16..22] → P_eval[0..6]).
	for q := 0; q <= skEval.LevelQ(); q++ {
		assert.Equalf(t, skTop.Value.Q.Coeffs[q], skEval.Value.Q.Coeffs[q],
			"sk_eval.Q row %d must match sk_top.Q row %d byte-for-byte", q, q)
	}
	for p := 0; p <= skEval.LevelP(); p++ {
		assert.Equalf(t, skTop.Value.Q.Coeffs[skEval.LevelQ()+1+p], skEval.Value.P.Coeffs[p],
			"sk_eval.P row %d must match sk_top.Q row %d byte-for-byte", p, skEval.LevelQ()+1+p)
	}
}
