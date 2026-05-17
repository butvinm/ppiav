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

	// Manifest declares the model's own chain (LogN16_D15_P6: 16 Q primes,
	// input_level=15). LoadOrionParams extends by ProtocolReserveLevels=1
	// 40-bit prime on top so MAC has level-1 headroom — the resulting
	// CKKS shape is 17 Q primes, MaxLevel=16, InputLevel=16.
	assert.Equal(t, 16, params.CKKS.LogN())
	assert.Equal(t, 16+ProtocolReserveLevels, len(params.CKKS.LogQi()))
	assert.Equal(t, 15+ProtocolReserveLevels, params.CKKS.MaxLevel())
	assert.InDelta(t, math.Exp2(40), params.CKKS.DefaultScale().Float64(), 1e-3)

	// Default authenticator + flooding settings carry over unchanged.
	assert.Equal(t, 128, params.Authenticator.Lambda)
	assert.InDelta(t, math.Exp2(20), params.Authenticator.Epsilon, 1e-9)
	assert.InDelta(t, math.Exp2(16), params.FloodSigma, 1e-9)

	// InputLevel = manifest.InputLevel + ProtocolReserveLevels so encrypt
	// uses the extended chain's higher level; after the model's rescales
	// the ciphertext lands at level ProtocolReserveLevels.
	assert.Equal(t, 15+ProtocolReserveLevels, params.InputLevel)

	// Extras stashed for the inference-side handshake. The fixture stores
	// raw Orion k_orion values; LoadOrionParams negates them on ingest
	// (signed-label convention — see protocol.Params doc).
	assert.Equal(t, []int{-1, -4, -16, -64, -128, -256, -512, -1024}, params.ExtraRotationIndices)

	// LLKN-hierarchy shape (level count, base, atom sets) is identical
	// to Defaults(). The Q/P prime counts are NOT compared here: with
	// orion-v2-compiler >=2.1.6's reserve_output_levels baked at compile
	// time, the Orion path's Q chain length differs from Defaults() (the
	// synthetic-x² path's CKKS shape is decoupled from whatever the
	// compiled Orion manifest declares).
	defaults, err := Defaults()
	require.NoError(t, err)
	assert.Equal(t, defaults.LLKNBase, params.LLKNBase)
	require.Equal(t, defaults.LLKN.NumLevels(), params.LLKN.NumLevels())
	assert.Equal(t, defaults.AuthAtoms(), params.AuthAtoms())
	assert.Equal(t, defaults.MasterAtoms(), params.MasterAtoms())
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

