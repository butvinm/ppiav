// Package authenticator implements MPD-Auth (multiparty decryption with
// authentication). See docs/DESIGN.md §`Multiparty decryption with
// authentication` for the algorithm and §`internal/authenticator` for the
// API contract.
package authenticator

import (
	"fmt"
	"math"
)

// Config holds the authenticator parameters. Lambda is the security
// parameter; |S| = Lambda/2 is derived. Epsilon is the Ver tolerance in
// scaled-message space (units of the ring coefficient, before the decoder
// divides by Δ). Defaults come from docs/DESIGN.md §`Parameters`.
type Config struct {
	Lambda  int
	Epsilon float64
}

// DefaultConfig returns the authenticator defaults: Lambda=128,
// Epsilon=2^20.
func DefaultConfig() Config {
	return Config{
		Lambda:  128,
		Epsilon: math.Exp2(20),
	}
}

// validate checks Lambda is positive and even so that |S|=Lambda/2 is exact.
func (c Config) validate() error {
	if c.Lambda <= 0 {
		return fmt.Errorf("authenticator: Lambda must be > 0, got %d", c.Lambda)
	}
	if c.Lambda%2 != 0 {
		return fmt.Errorf("authenticator: Lambda must be even, got %d", c.Lambda)
	}
	return nil
}
