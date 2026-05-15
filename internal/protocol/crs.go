package protocol

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

// crsDomain is the KDF domain separator for the session-scoped CRS seed.
const crsDomain = "ppiav-crs/v1"

// NewSessionCRS returns a `sampling.KeyedPRNG` seeded deterministically
// from the session id. Both VClient and VAgent construct it identically;
// no CRS material crosses the wire. See docs/DESIGN.md §`internal/protocol`.
func NewSessionCRS(sid SessionID) (*sampling.KeyedPRNG, error) {
	prng, err := sampling.NewKeyedPRNG([]byte(crsDomain + "|" + string(sid)))
	if err != nil {
		return nil, fmt.Errorf("protocol: build session CRS: %w", err)
	}
	return prng, nil
}

// CanonicalRotationIndices returns the rotation indices the MPD-Auth
// `Auth` step may need to rotate by: [1, lambda). j=0 is identity and
// requires no Galois key. Phase 2 unions this with the inference-circuit
// rotation set.
func CanonicalRotationIndices(lambda int) []int {
	if lambda <= 1 {
		return nil
	}
	out := make([]int, 0, lambda-1)
	for j := 1; j < lambda; j++ {
		out = append(out, j)
	}
	return out
}
