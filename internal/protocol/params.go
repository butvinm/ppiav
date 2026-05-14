package protocol

import (
	"fmt"
	"math"
	"sort"

	"github.com/butvinm/ppiav/internal/authenticator"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// DefaultConfig re-exports the authenticator's defaults so callers building
// Params manually don't need a second import in the common case.
func DefaultConfig() authenticator.Config {
	return authenticator.DefaultConfig()
}

// Params bundles the CKKS parameters, MPD-Auth configuration, and the
// VClient flooding sigma used during partial decryption.
//
// `ExtraRotationIndices` carries rotation labels required by the inference
// circuit beyond the authenticator's canonical `[1, Lambda)` set. Phase-1
// callers (`Defaults`) leave it nil; Phase-2 callers (`LoadOrionParams`)
// populate it from the Orion manifest. `RotationIndices()` returns the
// sorted union; VClient/VAgent iterate that union when running the
// collaborative GaloisKeyGen handshake.
//
// `InputLevel` is the ciphertext level at which `EncryptImage` produces
// the encrypted input. Phase 1 leaves it zero, which `EncryptImage`
// interprets as "max level" — there is no compiled model to constrain the
// budget. Phase 2 sets it from the Orion manifest so the inference circuit
// runs at the level it was compiled for.
type Params struct {
	CKKS                 ckks.Parameters
	Authenticator        authenticator.Config
	FloodSigma           float64
	ExtraRotationIndices []int
	InputLevel           int
}

// Defaults returns the Phase-1 parameter set from docs/DESIGN.md
// §`Implementation/Layout`. LogN=16, LogQ=[55]+[40]×15, LogP=[55]×6,
// LogDefaultScale=40, RingType=Standard. FloodSigma=2^16. No extra
// rotation indices; `RotationIndices()` returns the canonical
// `[1, Lambda)` set. InputLevel=0 means "use MaxLevel" downstream.
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
		FloodSigma:    math.Exp2(16),
	}, nil
}

// RotationIndices returns the sorted-ascending union of the canonical
// authenticator rotation set `[1, Lambda)` and any `ExtraRotationIndices`
// pulled from the inference-circuit manifest. Duplicates are removed.
// Zero and negative indices are dropped (j=0 is identity / no Galois key).
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
		if j <= 0 {
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
