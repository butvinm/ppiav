package vservice

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/tuneinsight/lattigo/v6/schemes/ckks"

	orioneval "github.com/butvinm/orion/v2/evaluator"
)

// orionModelFile is the canonical filename for the compiled Orion circuit
// inside an orionDir. NewWithOrion resolves `<orionDir>/model.orion`.
const orionModelFile = "model.orion"

// loadOrionModel reads and parses a compiled `.orion` container from disk,
// returns the loaded Model (immutable & goroutine-safe per Orion's doc.go),
// the CKKS parameters extracted from the model's client params, the input
// ciphertext level the model expects, and the rotation indices (raw `k`
// values, not Galois elements) that the inference circuit consumes.
//
// The rotation indices are recovered from the manifest's Galois elements
// by `params.SolveDiscreteLogGaloisElement(galEl)`. The returned slice is
// not deduplicated against the authenticator's `[1, Lambda)` set —
// `protocol.Params.RotationIndices()` does that downstream.
func loadOrionModel(orionDir string) (*orioneval.Model, ckks.Parameters, int, []int, error) {
	path := filepath.Join(orionDir, orionModelFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, ckks.Parameters{}, 0, nil, fmt.Errorf("vservice: read Orion model %q: %w", path, err)
	}
	model, err := orioneval.LoadModel(data)
	if err != nil {
		return nil, ckks.Parameters{}, 0, nil, fmt.Errorf("vservice: parse Orion model %q: %w", path, err)
	}

	// ClientParams returns (orion.Params, orion.Manifest, inputLevel). We
	// build the matching ckks.Parameters via the orion.Params helper so the
	// parameter object is bit-identical to the one the model was compiled
	// for — that's what its Forward path expects.
	clientParams, manifest, inputLevel := model.ClientParams()
	ckksParams, err := clientParams.NewCKKSParameters()
	if err != nil {
		return nil, ckks.Parameters{}, 0, nil, fmt.Errorf("vservice: build CKKS params from Orion manifest: %w", err)
	}

	// Invert each Galois element back to its rotation label k so the
	// caller can union it with the authenticator's [1, Lambda) set.
	rotations := make([]int, 0, len(manifest.GaloisElements))
	for _, ge := range manifest.GaloisElements {
		k := ckksParams.SolveDiscreteLogGaloisElement(ge)
		// k == 0 corresponds to the identity (no rotation key needed);
		// negative values are valid (right rotations). The authenticator
		// itself iterates positive k; manifest entries that map to
		// non-positive k are kept here verbatim because the Orion
		// evaluator may invoke them via the underlying Galois set.
		rotations = append(rotations, k)
	}

	return model, ckksParams, inputLevel, rotations, nil
}
