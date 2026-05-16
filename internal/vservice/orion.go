package vservice

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/butvinm/ppiav/internal/protocol"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"

	orioneval "github.com/butvinm/orion/v2/evaluator"
)

// orionModelFile is the canonical filename for the compiled Orion circuit
// inside an orionDir. NewWithOrion resolves `<orionDir>/model.orion`.
const orionModelFile = "model.orion"

// loadOrionModel reads and parses a compiled `.orion` container from disk,
// returns the loaded Model (immutable & goroutine-safe per Orion's doc.go),
// the CKKS parameters extracted from the model's client params, the input
// ciphertext level the model expects, and the rotation labels (in the
// signed-label convention documented on `protocol.Params`) that the
// inference circuit consumes.
//
// Sign convention (load-bearing — verified against Orion's evaluator):
//
//   - Orion's compiled circuit calls `eval.RotateNew(ct, +k_orion)` (see
//     `~/Dev/orion/evaluator/evaluator.go:346`), which internally invokes
//     `Automorphism(GaloisElement(+k_orion))`. The Galois key Orion needs
//     is therefore for element `params.GaloisElement(+k_orion)`.
//   - The manifest stores Galois elements `ge = GaloisElement(+k_orion)`
//     directly (no inversion). `SolveDiscreteLogGaloisElement(ge)` returns
//     the same positive `k_orion`.
//   - Our keygen mints a key for `GaloisElement(-label)` (see
//     `internal/vclient/keygen.go:105`, `internal/vagent/keygen.go:171`)
//     because the authenticator's `RotateNew(ct, -j)` is the dominant
//     consumer. To get a single keygen path to land on
//     `GaloisElement(+k_orion)` we therefore store the label as
//     `-k_orion`.
//
// Identity (k_orion == 0) is dropped — Lattigo short-circuits
// `Automorphism(galEl=1)` so no key is required (see
// `~/Dev/3rd-party/lattigo/core/rlwe/evaluator_automorphism.go:19`). The
// returned slice carries the inference-side labels only; the
// authenticator's `[1, Lambda)` atom set is a disjoint mechanism handled
// independently by `Params.AuthAtoms()`.
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

	rotations := make([]int, 0, len(manifest.GaloisElements))
	for _, ge := range manifest.GaloisElements {
		k := ckksParams.SolveDiscreteLogGaloisElement(ge)
		if k == 0 {
			// Identity: Lattigo's Automorphism(galEl=1) short-circuits to a
			// copy. Skip so we don't waste a CRS draw on an unused key.
			continue
		}
		// Store -k so our keygen's GaloisElement(-label) lands on
		// GaloisElement(+k_orion) — what Orion's RotateNew(ct, +k) needs.
		rotations = append(rotations, -k)
	}

	return model, ckksParams, inputLevel, rotations, nil
}

// mergeOrionParams loads the compiled Orion model at `orionDir` and folds
// its CKKS / InputLevel / rotation-index overrides into `params`. The LLKN
// hierarchy is rebuilt against the Orion-overridden CKKS — the caller's
// `params.LLKN` was built against `Defaults().CKKS` (or whatever CKKS the
// caller passed in) and is stale post-override. The multi-party top-level
// Galois handshake CRPs are sampled over the LLKN top ring; if VClient
// rebuilds LLKN from the wire CKKS while VService keeps a stale LLKN, the
// two sides draw CRPs over different rings and the aggregated keys
// silently mismatch.
//
// `params.ExtraRotationIndices` is preserved (a defensive copy is taken so
// appending to the merged slice does not mutate the caller's slice — the
// params value is passed by-value but the underlying array is shared).
//
// Shared by `NewWithOrion` and `NewWithState` (Orion branch) so the two
// constructors stay byte-for-byte identical in their parameter merge.
func mergeOrionParams(params protocol.Params, orionDir string) (protocol.Params, *orioneval.Model, error) {
	model, ckksParams, inputLevel, rotations, err := loadOrionModel(orionDir)
	if err != nil {
		return protocol.Params{}, nil, err
	}

	merged := params
	merged.CKKS = ckksParams
	merged.InputLevel = inputLevel

	llknParams, err := protocol.BuildLLKNParams(ckksParams)
	if err != nil {
		return protocol.Params{}, nil, fmt.Errorf("vservice: rebuild LLKN against Orion CKKS: %w", err)
	}
	merged.LLKN = llknParams

	if len(params.ExtraRotationIndices) > 0 || len(rotations) > 0 {
		combined := make([]int, 0, len(params.ExtraRotationIndices)+len(rotations))
		combined = append(combined, params.ExtraRotationIndices...)
		combined = append(combined, rotations...)
		merged.ExtraRotationIndices = combined
	}

	return merged, model, nil
}
