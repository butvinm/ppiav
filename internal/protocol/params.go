package protocol

import (
	"fmt"
	"math"

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
type Params struct {
	CKKS          ckks.Parameters
	Authenticator authenticator.Config
	FloodSigma    float64
}

// Defaults returns the Phase-1 parameter set from docs/DESIGN.md
// §`Implementation/Layout`. LogN=16, LogQ=[55]+[40]×15, LogP=[55]×6,
// LogDefaultScale=40, RingType=Standard. FloodSigma=2^16.
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
