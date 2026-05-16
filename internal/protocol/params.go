package protocol

import (
	"fmt"
	"math"
	"sort"

	"github.com/butvinm/ppiav/internal/authenticator"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// DefaultFloodSigma is the discrete-Gaussian flooding σ applied by VClient
// during partial decryption (and the value `Defaults()` / `LoadOrionParams()`
// both stamp into Params.FloodSigma). See docs/DESIGN.md
// §`internal/vclient` and `internal/vclient/partial_decrypt.go`.
var DefaultFloodSigma = math.Exp2(16)

// Params bundles the CKKS parameters, MPD-Auth configuration, and the
// VClient flooding sigma used during partial decryption.
//
// Rotation labels carry a SIGN: a label `j` (positive or negative) means
// the keygen handshake must mint a Galois key for element
// `params.CKKS.GaloisElement(-j)`. The authenticator emits positive labels
// `j ∈ [1, Lambda)` because Auth's step 4 calls `RotateNew(ct, -j)`
// (right-rotation by j → `GaloisElement(-j)`). Orion's compiled circuit
// calls `RotateNew(ct, +k)` for positive `k`, which needs
// `GaloisElement(+k)`; to make a single keygen path produce that, the
// Orion loader stores those labels as `-k` so the `GaloisElement(-(-k))`
// path lands on `GaloisElement(+k)`. Identity (label 0) needs no Galois
// key — Lattigo short-circuits `Automorphism(galEl=1)` — and is dropped.
//
// `ExtraRotationIndices` carries the inference-circuit labels (already in
// the signed-label convention above) on top of the authenticator's
// canonical positive set. The `Defaults()` caller leaves it nil; the
// Orion path populates it via `vservice.NewWithOrion`.
// `RotationIndices()` returns the sorted union; VClient/VAgent iterate
// that union when running the collaborative GaloisKeyGen handshake.
//
// `InputLevel` is the ciphertext level at which `EncryptImage` produces
// the encrypted input. The synthetic-x² path leaves it zero, which
// `EncryptImage` interprets as "max level" — there is no compiled model to
// constrain the budget. The Orion path sets it from the manifest so the
// inference circuit runs at the level it was compiled for.
type Params struct {
	CKKS                 ckks.Parameters
	Authenticator        authenticator.Config
	FloodSigma           float64
	ExtraRotationIndices []int
	InputLevel           int
}

// Defaults returns the synthetic-x² parameter set from docs/DESIGN.md
// §`Implementation/Layout`. LogN=16, LogQ=[55]+[40]×15, LogP=[55]×6,
// LogDefaultScale=40, RingType=Standard. FloodSigma=2^16. No extra
// rotation indices; `RotationIndices()` returns the canonical
// `[1, Lambda)` set. InputLevel=0 makes `EncryptImage` build the
// plaintext at MaxLevel (no compiled circuit to constrain the budget).
func Defaults() (Params, error) {
	logQ := make([]int, 1+15)
	logQ[0] = 55
	for i := 1; i < len(logQ); i++ {
		logQ[i] = 40
	}
	logP := make([]int, 6)
	for i := range logP {
		logP[i] = 55
	}
	params, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            16,
		LogQ:            logQ,
		LogP:            logP,
		LogDefaultScale: 40,
		RingType:        ring.Standard,
	})
	if err != nil {
		return Params{}, fmt.Errorf("protocol: build CKKS parameters: %w", err)
	}
	return Params{
		CKKS:          params,
		Authenticator: authenticator.DefaultConfig(),
		FloodSigma:    DefaultFloodSigma,
	}, nil
}

// RotationIndices returns the sorted-ascending union of the canonical
// authenticator rotation set `[1, Lambda)` and any `ExtraRotationIndices`
// pulled from the inference-circuit manifest. Duplicates are removed.
// Label 0 (identity) is dropped — Lattigo short-circuits
// `Automorphism(galEl=1)` so no Galois key is required. Negative labels
// are kept verbatim: see the `Params` doc for the signed-label convention
// (Orion stores `-k_orion` so the keygen's `GaloisElement(-label)` lands
// on `GaloisElement(+k_orion)`).
//
// VClient and VAgent iterate this slice in lockstep when running the
// collaborative GaloisKeyGen handshake; identical inputs guarantee the
// same CRP draw order on both sides.
func (p Params) RotationIndices() []int {
	seen := map[int]struct{}{}
	for j := 1; j < p.Authenticator.Lambda; j++ {
		seen[j] = struct{}{}
	}
	for _, j := range p.ExtraRotationIndices {
		if j == 0 {
			continue
		}
		seen[j] = struct{}{}
	}
	out := make([]int, 0, len(seen))
	for j := range seen {
		out = append(out, j)
	}
	sort.Ints(out)
	return out
}
