package protocol

import (
	"math"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadOrionParams(t *testing.T) {
	path := filepath.Join("testdata", "orion_manifest.json")
	params, err := LoadOrionParams(path)
	require.NoError(t, err)

	// CKKS shape matches the documented logn16 profile in
	// ~/Dev/orion/examples/c3ae-demo/models/params.py:51.
	assert.Equal(t, 16, params.CKKS.LogN())
	assert.Equal(t, 16, len(params.CKKS.LogQi()))
	assert.Equal(t, 15, params.CKKS.MaxLevel())
	assert.InDelta(t, math.Exp2(40), params.CKKS.DefaultScale().Float64(), 1e-3)

	// Default authenticator + flooding settings carry over unchanged.
	assert.Equal(t, 128, params.Authenticator.Lambda)
	assert.InDelta(t, math.Exp2(20), params.Authenticator.Epsilon, 1e-9)
	assert.InDelta(t, math.Exp2(16), params.FloodSigma, 1e-9)

	// InputLevel pulled from the manifest verbatim.
	assert.Equal(t, 15, params.InputLevel)

	// Extras stashed for the inference-side handshake. The fixture stores
	// raw Orion k_orion values; LoadOrionParams negates them on ingest
	// (signed-label convention — see protocol.Params doc).
	assert.Equal(t, []int{-1, -4, -16, -64, -128, -256, -512, -1024}, params.ExtraRotationIndices)

	// LLKN hierarchy is stamped identically to Defaults(). The manifest
	// itself does not constrain LLKN params (they're hierarchy-only).
	defaults, err := Defaults()
	require.NoError(t, err)
	assert.Equal(t, defaults.LLKNBase, params.LLKNBase)
	require.Equal(t, defaults.LLKN.NumLevels(), params.LLKN.NumLevels())
	assert.Equal(t, defaults.LLKN.Top().QCount(), params.LLKN.Top().QCount())
	assert.Equal(t, defaults.LLKN.Top().PCount(), params.LLKN.Top().PCount())
	assert.Equal(t, defaults.AuthAtoms(), params.AuthAtoms())
	assert.Equal(t, defaults.InferAtoms(), params.InferAtoms())
}

func TestLoadOrionParams_MissingFile(t *testing.T) {
	_, err := LoadOrionParams(filepath.Join("testdata", "does_not_exist.json"))
	assert.Error(t, err)
}

func TestLoadOrionParams_InvalidJSON(t *testing.T) {
	// Reuse the testdata fixture filename pattern: write nothing, just
	// point at the package source file as a not-JSON payload.
	_, err := LoadOrionParams("orion_params.go")
	assert.Error(t, err)
}

