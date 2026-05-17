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

// ProtocolReserveLevels is the number of CKKS Q-chain primes the protocol
// layer adds on top of what the model declares in its Orion manifest. The
// model declares the multiplicative depth it needs (input_level = K, K
// rescales); the protocol layer adds one extra prime + bumps input_level
// by 1 so result_ct lands at level 1 with the headroom MAC's slot-mask
// `Auth.MulNew` requires. Mirrors how PHK primes live outside the model's
// view: the model is oblivious, the protocol owns the headroom budget.
// See `internal/authenticator/level_reservation_test.go` for the
// architectural invariant locked in as a unit test.
const ProtocolReserveLevels = 1

// protocolReserveLogBits is the bit-size of each extra Q prime appended for
// MAC headroom. Matches the model's evaluation-prime bit-size (40 in the
// logn16 profile) so the scale arithmetic stays uniform across the chain.
const protocolReserveLogBits = 40

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
// builds an Orion-mode `Params`. It pulls CKKS parameters (LogN/LogQ/LogP/
// scale/ring type), the per-circuit `InputLevel`, and the rotation index
// set required to evaluate the circuit. The authenticator config and
// flooding sigma come from the same defaults `Defaults()` uses — the Orion
// path only changes the source of the CKKS knobs and stamps the Orion
// rotation indices onto `ExtraRotationIndices` for the inference-side
// handshake.
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

	// Extend the model's Q chain by ProtocolReserveLevels extra eval-level
	// primes so MAC's slot-mask multiply has level ≥ 1 headroom after the
	// circuit consumes `InputLevel` rescales. The extension is invisible
	// to the model: the manifest's declared InputLevel is bumped by the
	// same amount so encrypt uses the extended chain's higher level.
	logQ := make([]int, 0, len(m.Params.LogQ)+ProtocolReserveLevels)
	logQ = append(logQ, m.Params.LogQ...)
	for i := 0; i < ProtocolReserveLevels; i++ {
		logQ = append(logQ, protocolReserveLogBits)
	}
	inputLevel := m.InputLevel + ProtocolReserveLevels

	ckksParams, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            m.Params.LogN,
		LogQ:            logQ,
		LogP:            m.Params.LogP,
		LogDefaultScale: m.Params.LogDefaultScale,
		RingType:        ringType,
	})
	if err != nil {
		return Params{}, fmt.Errorf("protocol: build CKKS parameters from Orion manifest %q: %w", manifestPath, err)
	}

	if inputLevel < 1 || inputLevel > ckksParams.MaxLevel() {
		// InputLevel == 0 would leave the inference circuit with no levels
		// remaining for multiplication — silently fatal at Forward time.
		// `Defaults()` callers get the "use MaxLevel" behaviour via the
		// zero-default on the Params struct; an Orion manifest must commit
		// to a real level.
		return Params{}, fmt.Errorf(
			"protocol: Orion manifest %q has extended InputLevel=%d outside [1, %d] (manifest=%d, reserve=%d)",
			manifestPath, inputLevel, ckksParams.MaxLevel(), m.InputLevel, ProtocolReserveLevels,
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

	llknParams, err := BuildLLKNParams(ckksParams)
	if err != nil {
		return Params{}, fmt.Errorf("protocol: Orion manifest %q: %w", manifestPath, err)
	}

	return Params{
		CKKS:                 ckksParams,
		LLKN:                 llknParams,
		LLKNBase:             DefaultLLKNBase,
		Authenticator:        authenticator.DefaultConfig(),
		FloodSigma:           DefaultFloodSigma,
		ExtraRotationIndices: extras,
		InputLevel:           inputLevel,
	}, nil
}

// parseOrionRingType maps Orion's `ring_type` strings to Lattigo's ring
// constants. Orion accepts {"standard", "conjugate_invariant"} (see
// `CKKSParams.__post_init__`); the C3AE profile (`logn16`) uses
// "standard".
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
