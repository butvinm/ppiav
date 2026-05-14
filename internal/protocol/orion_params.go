package protocol

import (
	"encoding/json"
	"fmt"
	"math"
	"os"

	"github.com/butvinm/ppiav/internal/authenticator"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// orionManifest mirrors the JSON metadata block Orion emits when it writes
// a compiled model (see `~/Dev/orion/python/orion-compiler/orion_compiler/
// compiled_model.py:_build_metadata`). We only decode the fields needed to
// drive Phase 2 — CKKS parameters, the input level, and the rotation index
// set. Bootstrap fields and the per-node graph payload are out of scope
// for `LoadOrionParams`; the Orion Go runtime consumes those at Inference
// time in Task 14.
//
// The schema below is a clean subset of Orion's wire format with one
// deliberate addition: `rotation_indices` carries raw rotation labels
// (integers in `[1, slots)`), not Galois elements. Orion's manifest stores
// Galois elements (`5^k mod 2N`); for Task 13 we sidestep the inversion
// step by having the fixture (and Task 14's loader) materialise raw
// indices directly. The inversion via
// `params.SolveDiscreteLogGaloisElement` is a Task-14 concern when reading
// the actual `.orion` container.
type orionManifest struct {
	Params struct {
		LogN            int    `json:"logn"`
		LogQ            []int  `json:"logq"`
		LogP            []int  `json:"logp"`
		LogDefaultScale int    `json:"log_default_scale"`
		RingType        string `json:"ring_type"`
	} `json:"params"`
	InputLevel       int   `json:"input_level"`
	RotationIndices  []int `json:"rotation_indices"`
}

// LoadOrionParams reads an Orion compiled-circuit manifest from disk and
// builds the Phase-2 `Params`. It pulls CKKS parameters (LogN/LogQ/LogP/
// scale/ring type), the per-circuit `InputLevel`, and the rotation index
// set required to evaluate the circuit. The authenticator config and
// flooding sigma come from the same defaults the Phase-1 `Defaults()` uses
// — Phase 2 only changes the source of the CKKS knobs and unions the
// Orion rotation indices into `RotationIndices()`.
//
// File format: see `orionManifest`. The fixture under
// `internal/protocol/testdata/orion_manifest.json` documents the exact
// shape this function consumes.
func LoadOrionParams(manifestPath string) (Params, error) {
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return Params{}, fmt.Errorf("protocol: read Orion manifest %q: %w", manifestPath, err)
	}
	var m orionManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return Params{}, fmt.Errorf("protocol: parse Orion manifest %q: %w", manifestPath, err)
	}
	if m.Params.LogN <= 0 {
		return Params{}, fmt.Errorf("protocol: Orion manifest %q has invalid LogN=%d", manifestPath, m.Params.LogN)
	}
	if len(m.Params.LogQ) == 0 {
		return Params{}, fmt.Errorf("protocol: Orion manifest %q has empty LogQ", manifestPath)
	}
	if len(m.Params.LogP) == 0 {
		return Params{}, fmt.Errorf("protocol: Orion manifest %q has empty LogP", manifestPath)
	}

	ringType, err := parseOrionRingType(m.Params.RingType)
	if err != nil {
		return Params{}, fmt.Errorf("protocol: Orion manifest %q: %w", manifestPath, err)
	}

	ckksParams, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            m.Params.LogN,
		LogQ:            m.Params.LogQ,
		LogP:            m.Params.LogP,
		LogDefaultScale: m.Params.LogDefaultScale,
		RingType:        ringType,
	})
	if err != nil {
		return Params{}, fmt.Errorf("protocol: build CKKS parameters from Orion manifest %q: %w", manifestPath, err)
	}

	if m.InputLevel < 0 || m.InputLevel > ckksParams.MaxLevel() {
		return Params{}, fmt.Errorf(
			"protocol: Orion manifest %q has InputLevel=%d outside [0, %d]",
			manifestPath, m.InputLevel, ckksParams.MaxLevel(),
		)
	}

	// Defensive copy so the caller can't mutate the slice we stash on Params.
	extras := make([]int, len(m.RotationIndices))
	copy(extras, m.RotationIndices)

	return Params{
		CKKS:                 ckksParams,
		Authenticator:        authenticator.DefaultConfig(),
		FloodSigma:           math.Exp2(16),
		ExtraRotationIndices: extras,
		InputLevel:           m.InputLevel,
	}, nil
}

// parseOrionRingType maps Orion's `ring_type` strings to Lattigo's ring
// constants. Orion accepts {"standard", "conjugate_invariant"} (see
// `CKKSParams.__post_init__`); both Phase-2 C3AE profiles
// (`logn15`/`logn16`) use "standard".
func parseOrionRingType(s string) (ring.Type, error) {
	switch s {
	case "standard":
		return ring.Standard, nil
	case "conjugate_invariant":
		return ring.ConjugateInvariant, nil
	default:
		return 0, fmt.Errorf("unsupported ring_type %q", s)
	}
}
