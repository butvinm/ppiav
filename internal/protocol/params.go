package protocol

import (
	"fmt"
	"math"

	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// Config is a stub of internal/authenticator's configuration.
// TODO(task 3): move to internal/authenticator and import here.
type Config struct {
	Lambda  int
	Epsilon float64
}

// DefaultConfig returns the Phase-1 authenticator defaults.
// TODO(task 3): move to internal/authenticator.
func DefaultConfig() Config {
	return Config{
		Lambda:  128,
		Epsilon: math.Exp2(20),
	}
}

// Params bundles the CKKS parameters, MPD-Auth configuration, and the
// VClient flooding sigma used during partial decryption.
type Params struct {
	CKKS          ckks.Parameters
	Authenticator Config
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
		Authenticator: DefaultConfig(),
		FloodSigma:    math.Exp2(16),
	}, nil
}
