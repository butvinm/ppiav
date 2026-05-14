package vclient

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/ring"
)

// PartialDecrypt produces VClient's KeySwitchShare for the authenticated
// ciphertext, with discrete-Gaussian flooding at σ = params.FloodSigma
// (and a 6σ bound per Lattigo convention). Per docs/DESIGN.md
// §`Joint decryption + Ver`, VClient acts as if performing a key-switch
// from sk_c to a zero secret key; aggregated with VAgent's matching share
// (key-switch from sk_a to a zero secret key) the combined share, after
// KeySwitch, recovers the plaintext as if decrypted under the joint
// secret sk = sk_c + sk_a → 0.
//
// Smudging rationale (CKKS IND-CPA^D, Li–Micciancio 2021): without σ_flood
// VClient's share leaks `c1 · sk_c + e_fresh`, and CKKS decryption noise
// is deterministic in (c, sk), so an adversary that learns the recovered
// plaintext alongside the share can statistically extract sk_c across
// sessions. σ_flood = 2^16 dominates the intrinsic decryption noise and
// breaks the leak.
func (c *Client) PartialDecrypt(authenticatedCt *rlwe.Ciphertext) (multiparty.KeySwitchShare, error) {
	if authenticatedCt == nil {
		return multiparty.KeySwitchShare{}, fmt.Errorf("vclient: authenticatedCt is nil")
	}
	proto, err := multiparty.NewKeySwitchProtocol(c.params.CKKS, ring.DiscreteGaussian{
		Sigma: c.params.FloodSigma,
		Bound: 6 * c.params.FloodSigma,
	})
	if err != nil {
		return multiparty.KeySwitchShare{}, fmt.Errorf("vclient: build KeySwitchProtocol: %w", err)
	}

	share := proto.AllocateShare(authenticatedCt.Level())
	zeroSk := rlwe.NewSecretKey(c.params.CKKS)
	proto.GenShare(c.skShare, zeroSk, authenticatedCt, &share)
	return share, nil
}
