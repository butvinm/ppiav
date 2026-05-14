package vclient

import (
	"fmt"

	"github.com/butvinm/ppiav/internal/protocol"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
)

// GenPKShare runs the client side of Stage 2b. It instantiates the
// multiparty PK protocol, draws the first CRP from the session CRS, and
// produces sk_c's share. The CRP and the local share are stashed for
// AggregatePK.
//
// CRS order: this is the FIRST draw from c.crs — RLK and Galois CRPs
// follow in order. See docs/DESIGN.md §`internal/protocol`.
func (c *Client) GenPKShare() (multiparty.PublicKeyGenShare, error) {
	c.pkProto = multiparty.NewPublicKeyGenProtocol(c.params.CKKS)
	c.pkCRP = c.pkProto.SampleCRP(c.crs)
	c.pkShareLocal = c.pkProto.AllocateShare()
	c.pkProto.GenShare(c.skShare, c.pkCRP, &c.pkShareLocal)
	return c.pkShareLocal, nil
}

// AggregatePK combines the client share stashed by GenPKShare with
// VAgent's matching share, finalises the aggregated public key, and
// builds the per-session encryptor. EncryptImage is callable after this.
func (c *Client) AggregatePK(agentShare multiparty.PublicKeyGenShare) error {
	if c.pkCRP.Value.Q.Coeffs == nil {
		return fmt.Errorf("vclient: AggregatePK called before GenPKShare")
	}
	agg := c.pkProto.AllocateShare()
	c.pkProto.AggregateShares(c.pkShareLocal, agentShare, &agg)

	pk := rlwe.NewPublicKey(c.params.CKKS)
	c.pkProto.GenPublicKey(agg, c.pkCRP, pk)
	c.pkAgg = pk
	c.encryptor = rlwe.NewEncryptor(c.params.CKKS, pk)
	return nil
}

// GenRLKShareRound1 runs the client side of Stage 2c, round 1. It draws
// the SECOND CRP from the session CRS (single CRP reused for both rounds,
// per Lattigo's protocol shape) and produces sk_c's round-1 share. The
// CRP, the ephemeral sk_c, and the local share are stashed.
func (c *Client) GenRLKShareRound1() (multiparty.RelinearizationKeyGenShare, error) {
	c.rlkProto = multiparty.NewRelinearizationKeyGenProtocol(c.params.CKKS)
	c.rlkCRP = c.rlkProto.SampleCRP(c.crs)
	ephSk, share1, _ := c.rlkProto.AllocateShare()
	c.rlkEphSk = ephSk
	c.rlkShare1Loc = share1
	c.rlkProto.GenShareRoundOne(c.skShare, c.rlkCRP, c.rlkEphSk, &c.rlkShare1Loc)
	return c.rlkShare1Loc, nil
}

// AggregateRLKRound1 aggregates VAgent's round-1 share with the client's.
// The result is cached so round 2 has both inputs it needs.
func (c *Client) AggregateRLKRound1(agentShare multiparty.RelinearizationKeyGenShare) error {
	_, agg, _ := c.rlkProto.AllocateShare()
	c.rlkProto.AggregateShares(c.rlkShare1Loc, agentShare, &agg)
	c.rlkShare1Agg = agg
	return nil
}

// GenRLKShareRound2 runs the client side of Stage 2c, round 2. It uses
// the cached round-1 aggregate and the stashed ephemeral sk. VClient does
// not finalise the rlk locally — only VAgent and VService need it (per
// docs/DESIGN.md §`internal/vclient`).
func (c *Client) GenRLKShareRound2() (multiparty.RelinearizationKeyGenShare, error) {
	if c.rlkEphSk == nil {
		return multiparty.RelinearizationKeyGenShare{}, fmt.Errorf("vclient: GenRLKShareRound2 called before round 1")
	}
	_, _, share2 := c.rlkProto.AllocateShare()
	c.rlkProto.GenShareRoundTwo(c.rlkEphSk, c.skShare, c.rlkShare1Agg, &share2)
	return share2, nil
}

// GenGaloisShares produces one share per rotation label in
// `protocol.CanonicalRotationIndices(lambda)` (i.e., [1, lambda)) in
// ascending order. The CRPs are drawn from c.crs in label order — the
// THIRD-and-onward draws.
//
// Galois-element mapping: docs/DESIGN.md §`Implementation notes` and
// internal/authenticator/authenticator.go validateGaloisKeys document that
// Auth's step 4 uses `eval.RotateNew(ct, -j)` to place slot 0 at slot j
// (Lattigo's RotateNew is LEFT-rotation). The required Galois element per
// label j is therefore `params.GaloisElement(-j)` — VAgent applies the
// same convention so the aggregated key matches what `Auth` expects.
//
// The returned `labels` slice is parallel to `shares`: shares[k] is the
// share for rotation label labels[k]. VAgent uses these labels when
// aggregating and when binding each finalised GaloisKey to its element.
func (c *Client) GenGaloisShares() ([]multiparty.GaloisKeyGenShare, []int, error) {
	labels := protocol.CanonicalRotationIndices(c.params.Authenticator.Lambda)
	if len(labels) == 0 {
		return nil, nil, nil
	}
	gkg := multiparty.NewGaloisKeyGenProtocol(c.params.CKKS)
	shares := make([]multiparty.GaloisKeyGenShare, len(labels))
	for i, j := range labels {
		// Ascending-label CRP draw — order is part of the protocol contract.
		crp := gkg.SampleCRP(c.crs)
		share := gkg.AllocateShare()
		galEl := c.params.CKKS.GaloisElement(-j)
		if err := gkg.GenShare(c.skShare, galEl, crp, &share); err != nil {
			return nil, nil, fmt.Errorf("vclient: GenShare for rotation label %d: %w", j, err)
		}
		shares[i] = share
	}
	return shares, labels, nil
}
