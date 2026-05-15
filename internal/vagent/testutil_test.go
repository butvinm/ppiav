package vagent

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"math/big"
)

// buildSSet mirrors authenticator.sInSet: returns a Lambda-sized boolean
// mask where inS[i] is true iff i ∈ S. Replicated here because the
// authenticator's helper is unexported and the test only needs read-only
// view of the same logic.
func buildSSet(s []int, lambda int) []bool {
	out := make([]bool, lambda)
	for _, idx := range s {
		if idx >= 0 && idx < lambda {
			out[idx] = true
		}
	}
	return out
}

// buildExpectedVRaw mirrors authenticator.vRawValues — the deterministic
// AES-CTR + rejection-sampling pipeline keyed by seedF. The test uses
// this to compare ct_M's S-slot contents against the expected v[i] / Δ.
// Any divergence here vs. the authenticator's pipeline would invalidate
// the test (ledger of the contract: PRG draws come out byte-for-byte the
// same between Auth and Ver).
func buildExpectedVRaw(seed [32]byte, lambda int, s []int, q0Half *big.Int) (map[int]float64, error) {
	if lambda <= 0 {
		return nil, fmt.Errorf("buildExpectedVRaw: lambda must be > 0")
	}
	block, err := aes.NewCipher(seed[:16])
	if err != nil {
		return nil, fmt.Errorf("buildExpectedVRaw: AES init: %w", err)
	}
	var iv [16]byte
	copy(iv[:], seed[16:])
	stream := cipher.NewCTR(block, iv[:])

	inS := buildSSet(s, lambda)
	span := new(big.Int).Lsh(q0Half, 1)
	span.Add(span, big.NewInt(1))
	byteLen := (span.BitLen() + 7) / 8
	if byteLen <= 0 {
		byteLen = 1
	}
	maxRange := new(big.Int).Lsh(big.NewInt(1), uint(8*byteLen))
	limit := new(big.Int).Sub(maxRange, new(big.Int).Mod(maxRange, span))

	out := map[int]float64{}
	buf := make([]byte, byteLen)
	zero := make([]byte, byteLen)
	for i := 0; i < lambda; i++ {
		if !inS[i] {
			continue
		}
		var sampled *big.Int
		for tries := 0; tries < 1000; tries++ {
			for k := range zero {
				zero[k] = 0
			}
			stream.XORKeyStream(buf, zero)
			r := new(big.Int).SetBytes(buf)
			if r.Cmp(limit) < 0 {
				r.Mod(r, span)
				r.Sub(r, q0Half)
				sampled = r
				break
			}
		}
		if sampled == nil {
			return nil, fmt.Errorf("buildExpectedVRaw: rejection sampler exhausted")
		}
		vF, _ := new(big.Float).SetInt(sampled).Float64()
		out[i] = vF
	}
	return out, nil
}
