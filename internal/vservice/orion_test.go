package vservice

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// orionTestDirEnv is the env var that points at a built Orion model
// directory containing `model.orion`. Empty/unset → the smoke test skips
// so CI without Orion artifacts still passes. Local dev points it at
// e.g. `/home/butvinm/Dev/orion/examples/c3ae-demo/out/logn15`.
const orionTestDirEnv = "PPIAV_ORION_DIR"

func TestLoadOrionModelSmoke(t *testing.T) {
	orionTestDir := os.Getenv(orionTestDirEnv)
	if orionTestDir == "" {
		t.Skipf("%s not set; skipping Orion smoke test (point it at a directory containing model.orion to run)", orionTestDirEnv)
	}
	modelPath := filepath.Join(orionTestDir, "model.orion")
	if _, err := os.Stat(modelPath); err != nil {
		t.Skipf("Orion model not found at %s; skipping smoke test", modelPath)
	}

	model, ckksParams, inputLevel, rotations, err := loadOrionModel(orionTestDir)
	require.NoError(t, err, "loadOrionModel must succeed for a present .orion file")
	require.NotNil(t, model, "model must be non-nil on success")

	// CKKS sanity: LogN positive, modulus chain non-empty, slot count >0.
	assert.Greater(t, ckksParams.LogN(), 0, "model's CKKS params must have LogN > 0")
	assert.Greater(t, ckksParams.MaxLevel(), 0, "model's modulus chain must have at least one step")
	assert.Greater(t, ckksParams.MaxSlots(), 0, "model's slot count must be > 0")

	// Input level must be a valid index into the modulus chain.
	assert.GreaterOrEqual(t, inputLevel, 0)
	assert.LessOrEqual(t, inputLevel, ckksParams.MaxLevel())

	// C3AE uses linear transforms and polynomials → it must declare
	// rotation keys. Empty rotations would mean a degenerate model.
	assert.NotEmpty(t, rotations, "C3AE manifest must declare at least one rotation")
}

func TestLoadOrionModelMissingDir(t *testing.T) {
	_, _, _, _, err := loadOrionModel("/this/path/does/not/exist")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read Orion model")
}
