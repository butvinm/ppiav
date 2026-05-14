package protocol

import (
	"math"
	"path/filepath"
	"sort"
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

	// Phase-1 authenticator + flooding defaults carry over unchanged.
	assert.Equal(t, 128, params.Authenticator.Lambda)
	assert.InDelta(t, math.Exp2(20), params.Authenticator.Epsilon, 1e-9)
	assert.InDelta(t, math.Exp2(16), params.FloodSigma, 1e-9)

	// InputLevel pulled from the manifest verbatim.
	assert.Equal(t, 15, params.InputLevel)

	// Extras stashed for RotationIndices() to union later.
	assert.Equal(t, []int{1, 4, 16, 64, 128, 256, 512, 1024}, params.ExtraRotationIndices)
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

func TestParams_RotationIndices_DefaultsCanonicalOnly(t *testing.T) {
	params, err := Defaults()
	require.NoError(t, err)
	got := params.RotationIndices()

	// Phase-1 defaults have no extras: RotationIndices() = canonical [1, λ).
	want := CanonicalRotationIndices(params.Authenticator.Lambda)
	assert.Equal(t, want, got)
	assert.Len(t, got, 127)
	assert.Equal(t, 1, got[0])
	assert.Equal(t, 127, got[126])
}

func TestParams_RotationIndices_UnionWithExtras(t *testing.T) {
	params, err := LoadOrionParams(filepath.Join("testdata", "orion_manifest.json"))
	require.NoError(t, err)

	got := params.RotationIndices()

	// Sorted ascending.
	assert.True(t, sort.IntsAreSorted(got), "rotation indices must be ascending: %v", got)

	// Deduplicated — `1` appears in both canonical and the manifest extras.
	seen := map[int]int{}
	for _, j := range got {
		seen[j]++
	}
	for j, n := range seen {
		assert.Equalf(t, 1, n, "rotation index %d appears %d times; want 1", j, n)
	}

	// Canonical [1..127] is a subset of the result.
	canonical := CanonicalRotationIndices(params.Authenticator.Lambda)
	canonSet := map[int]struct{}{}
	for _, j := range canonical {
		canonSet[j] = struct{}{}
	}
	resultSet := map[int]struct{}{}
	for _, j := range got {
		resultSet[j] = struct{}{}
	}
	for j := range canonSet {
		_, ok := resultSet[j]
		assert.Truef(t, ok, "canonical index %d missing from result", j)
	}

	// Manifest extras above the canonical range are present too.
	for _, j := range []int{128, 256, 512, 1024} {
		_, ok := resultSet[j]
		assert.Truef(t, ok, "manifest extra %d missing from result", j)
	}
}

func TestParams_RotationIndices_RoundTrip(t *testing.T) {
	params, err := LoadOrionParams(filepath.Join("testdata", "orion_manifest.json"))
	require.NoError(t, err)

	first := params.RotationIndices()
	second := params.RotationIndices()
	assert.Equal(t, first, second, "RotationIndices must be deterministic across calls")
}

func TestParams_RotationIndices_DropsNonPositive(t *testing.T) {
	params, err := Defaults()
	require.NoError(t, err)
	// Inject some bogus values; method must drop them.
	params.ExtraRotationIndices = []int{0, -1, 200, 5}

	got := params.RotationIndices()
	for _, j := range got {
		assert.Greaterf(t, j, 0, "rotation index %d must be positive", j)
	}
	// `5` is already in canonical [1..127], so it should appear exactly once;
	// `200` is a new addition above canonical and must be present.
	resultSet := map[int]struct{}{}
	for _, j := range got {
		resultSet[j] = struct{}{}
	}
	_, has200 := resultSet[200]
	_, has5 := resultSet[5]
	assert.True(t, has200, "200 must be in union")
	assert.True(t, has5, "5 (canonical) must be in union")
}
