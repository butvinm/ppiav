package protocol

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/butvinm/ppiav/internal/authenticator"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// orionManifestSchemaVersion is the schema version this loader understands.
// Bumped together with `orionManifest` when fields are renamed/removed.
const orionManifestSchemaVersion = 2

// orionManifest mirrors the JSON metadata block Orion emits when it writes
// a compiled model (see `~/Dev/orion/python/orion-compiler/orion_compiler/
// compiled_model.py:_build_metadata`). We only decode the fields needed to
// drive the JSON-fixture loader — CKKS parameters, the input level, and a
// rotation index set. Bootstrap fields and the per-node graph payload are
// out of scope here; the production path consumes the `.orion` binary
// container via `internal/vservice/orion.go::loadOrionModel`, which reads
// Galois elements directly from `model.ClientParams()` and inverts them.
//
// The JSON `rotation_indices` field carries raw Orion `k_orion` values —
// the positive offsets Orion calls `RotateNew(ct, +k_orion)` with. The
// loader negates them on ingest to fit the signed-label convention
// documented on `protocol.Params` (so the keygen's `GaloisElement(-label)`
// lands on `GaloisElement(+k_orion)`).
type orionManifest struct {
	Version int `json:"version"`
	Params  struct {
		LogN            int    `json:"logn"`
		LogQ            []int  `json:"logq"`
		LogP            []int  `json:"logp"`
		LogDefaultScale int    `json:"log_default_scale"`
		RingType        string `json:"ring_type"`
	} `json:"params"`
	InputLevel      int   `json:"input_level"`
	RotationIndices []int `json:"rotation_indices"`
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
	if m.Version != orionManifestSchemaVersion {
		return Params{}, fmt.Errorf(
			"protocol: Orion manifest %q has schema version %d, expected %d",
			manifestPath, m.Version, orionManifestSchemaVersion,
		)
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

	if m.InputLevel < 1 || m.InputLevel > ckksParams.MaxLevel() {
		// InputLevel == 0 would leave the inference circuit with no levels
		// remaining for multiplication — silently fatal at Forward time.
		// Phase-1 callers (`Defaults()`) get the "use MaxLevel" behaviour
		// via the zero-default on the Params struct; an Orion manifest must
		// commit to a real level.
		return Params{}, fmt.Errorf(
			"protocol: Orion manifest %q has InputLevel=%d outside [1, %d]",
			manifestPath, m.InputLevel, ckksParams.MaxLevel(),
		)
	}

	// Negate raw Orion k values on ingest to fit the signed-label
	// convention documented on `protocol.Params`. k == 0 (identity) is
	// dropped — Lattigo short-circuits `Automorphism(galEl=1)`.
	extras := make([]int, 0, len(m.RotationIndices))
	for _, k := range m.RotationIndices {
		if k == 0 {
			continue
		}
		extras = append(extras, -k)
	}

	return Params{
		CKKS:                 ckksParams,
		Authenticator:        authenticator.DefaultConfig(),
		FloodSigma:           DefaultFloodSigma,
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
