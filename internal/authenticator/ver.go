package authenticator

import "math"

// Ver runs §MPD-Auth/Ver against the decrypted plaintext slot vector P.
// Returns (m, true) iff both checks pass:
//
//  1. For all i ∈ S: |P[i]·Δ - v[i]| < cfg.Epsilon.
//  2. For all i ∈ [0, Lambda) \ S: |P[i]·Δ - P[j*]·Δ| < cfg.Epsilon, where
//     j* is the smallest index in [0, Lambda) \ S.
//
// On pass, m is P[j*]. Pure function — no state mutation, no Key zeroize.
func (a *Authenticator) Ver(key Key, plaintext []float64) (float64, bool) {
	if a == nil {
		return 0, false
	}
	if a.cfg.validate() != nil {
		return 0, false
	}
	lambda := a.cfg.Lambda
	if len(plaintext) < lambda {
		return 0, false
	}
	if len(key.S) != lambda/2 {
		return 0, false
	}

	inS := sInSet(key.S, lambda)

	// Pick j* = smallest index in [0, Lambda) \ S.
	jStar := -1
	for i := 0; i < lambda; i++ {
		if !inS[i] {
			jStar = i
			break
		}
	}
	if jStar == -1 {
		return 0, false
	}

	// Re-derive v[i] (raw, in scaled-message space) from the seed.
	vRaw, err := vRawValues(key.SeedF, lambda, key.S, a.q0Half)
	if err != nil {
		return 0, false
	}

	delta := a.deltaF64
	pJStarScaled := plaintext[jStar] * delta

	// Check 1: verification-slot match for i ∈ S.
	for i := 0; i < lambda; i++ {
		if !inS[i] {
			continue
		}
		if math.Abs(plaintext[i]*delta-vRaw[i]) >= a.cfg.Epsilon {
			return 0, false
		}
	}
	// Check 2: value-slot pairwise agreement for i ∈ [0, Lambda) \ S.
	for i := 0; i < lambda; i++ {
		if inS[i] {
			continue
		}
		if math.Abs(plaintext[i]*delta-pJStarScaled) >= a.cfg.Epsilon {
			return 0, false
		}
	}
	return plaintext[jStar], true
}
