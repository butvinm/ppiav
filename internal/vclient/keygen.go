package vclient

import (
	"fmt"

	"github.com/butvinm/ppiav/internal/protocol"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
)

// GenPKShare runs the client side of Stage 2b. It instantiates TWO
// multiparty PK protocols — one at eval level, one at top level — draws
// their CRPs from the session CRS in fixed order (eval first, then top),
// and produces sk_c's shares against each. The CRPs and the local shares
// are stashed for AggregatePK.
//
// Why dual: the eval-level PK powers VClient's session encryptor and the
// authenticator-side encryptor inside Auth. The top-level PK seeds
// VService's `hierkeys.PubToRot` LevelExpansion (lattigo-hierkeys
// hierarchical key derivation) — see docs/DESIGN.md §`internal/vservice`.
//
// CRS order: these are the FIRST TWO draws from c.crs (pk_eval, then
// pk_top); RLK and per-atom Galois CRPs follow. See docs/DESIGN.md
// §`internal/protocol`.
func (c *Client) GenPKShare() (protocol.VClientPKShare, error) {
	skEval, err := c.skEval()
	if err != nil {
		return protocol.VClientPKShare{}, err
	}

	// Eval-level PK share.
	c.pkProtoEval = multiparty.NewPublicKeyGenProtocol(c.params.CKKS)
	c.pkCRPEval = c.pkProtoEval.SampleCRP(c.crs)
	c.pkShareLocalEval = c.pkProtoEval.AllocateShare()
	c.pkProtoEval.GenShare(skEval, c.pkCRPEval, &c.pkShareLocalEval)

	// Top-level PK share. The protocol/CRP/share are locals: VClient does
	// not aggregate pk_top on its own side (VAgent owns that), so there is
	// nothing to stash between GenPKShare and AggregatePK.
	topParams := c.params.LLKN.Top()
	pkProtoTop := multiparty.NewPublicKeyGenProtocol(topParams)
	pkCRPTop := pkProtoTop.SampleCRP(c.crs)
	pkShareLocalTop := pkProtoTop.AllocateShare()
	pkProtoTop.GenShare(c.skTop, pkCRPTop, &pkShareLocalTop)

	return protocol.VClientPKShare{
		ShareEval: c.pkShareLocalEval,
		ShareTop:  pkShareLocalTop,
	}, nil
}

// AggregatePK combines the dual client shares stashed by GenPKShare with
// VAgent's matching shares, finalises both the eval-level and top-level
// aggregated public keys, and builds the per-session encryptor (against
// the eval-level pk). EncryptImage is callable after this.
func (c *Client) AggregatePK(agentShare protocol.VAgentPKShare) error {
	if c.pkCRPEval.Value.Q.Coeffs == nil {
		return fmt.Errorf("vclient: AggregatePK called before GenPKShare")
	}

	// Aggregate eval-level shares → pkEval (wires the encryptor).
	aggEval := c.pkProtoEval.AllocateShare()
	c.pkProtoEval.AggregateShares(c.pkShareLocalEval, agentShare.ShareEval, &aggEval)
	pkEval := rlwe.NewPublicKey(c.params.CKKS)
	c.pkProtoEval.GenPublicKey(aggEval, c.pkCRPEval, pkEval)
	c.pkAgg = pkEval
	c.encryptor = rlwe.NewEncryptor(c.params.CKKS, pkEval)

	// Top-level shares are emitted to VAgent inside VClientPKShare; VAgent
	// owns the pk_top aggregation and ships the result to VService.
	// VClient itself does not need pk_top after GenPKShare — the encryptor
	// runs only at eval level — so agentShare.ShareTop is not consumed here.

	return nil
}

// GenRLKShareRound1 runs the client side of Stage 2c, round 1. It draws
// the next CRP from the session CRS (single CRP reused for both rounds,
// per Lattigo's protocol shape) and produces sk_eval's round-1 share. The
// CRP, the ephemeral sk_c, and the local share are stashed.
//
// The RLK protocol is EVAL-LEVEL — `skEval` (projected from `skTop`) is
// the right secret-key arg; passing `skTop` would mismatch the protocol's
// parameters and silently desync against VAgent.
func (c *Client) GenRLKShareRound1() (multiparty.RelinearizationKeyGenShare, error) {
	skEval, err := c.skEval()
	if err != nil {
		return multiparty.RelinearizationKeyGenShare{}, err
	}
	c.rlkProto = multiparty.NewRelinearizationKeyGenProtocol(c.params.CKKS)
	c.rlkCRP = c.rlkProto.SampleCRP(c.crs)
	ephSk, share1, _ := c.rlkProto.AllocateShare()
	c.rlkEphSk = ephSk
	c.rlkShare1Loc = share1
	c.rlkProto.GenShareRoundOne(skEval, c.rlkCRP, c.rlkEphSk, &c.rlkShare1Loc)
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
// the cached round-1 aggregate, the stashed ephemeral sk, and the
// eval-level projected `skEval`. VClient does not finalise the rlk locally
// — only VAgent and VService need it (per docs/DESIGN.md §`internal/vclient`).
func (c *Client) GenRLKShareRound2() (multiparty.RelinearizationKeyGenShare, error) {
	if c.rlkEphSk == nil {
		return multiparty.RelinearizationKeyGenShare{}, fmt.Errorf("vclient: GenRLKShareRound2 called before round 1")
	}
	skEval, err := c.skEval()
	if err != nil {
		return multiparty.RelinearizationKeyGenShare{}, err
	}
	_, _, share2 := c.rlkProto.AllocateShare()
	c.rlkProto.GenShareRoundTwo(c.rlkEphSk, skEval, c.rlkShare1Agg, &share2)
	return share2, nil
}

// GenMasterShares produces the single master-atom share list VAgent's
// Galois handshake consumes:
//
//   - One share per atom in `c.params.MasterAtoms()` (e.g. `{1,4,...,16384}`
//     at LogN=16, base=4). `gkg = multiparty.NewGaloisKeyGenProtocol(c.params.LLKN.Top())`.
//     Secret-key arg is `skTop`. Each call uses
//     `c.params.LLKN.Top().GaloisElement(+atom)`. The aggregated keys are
//     converted via `hierkeys.GaloisKeyToMasterKey` (VAgent's job) into
//     the master-key bundle used by BOTH VAgent (locally derives the
//     negative auth-atom keys for the authenticator chain) and VService
//     (locally derives the Orion-circuit signed-label rotation set).
//
// CRS draw order: per the package contract, draws here follow pk_eval,
// pk_top, rlk. All `len(MasterAtoms())` master CRPs are drawn at top
// level in ascending atom order. VAgent draws in lockstep.
//
// The returned label slice is parallel to the share slice: `shares[k]`
// corresponds to `labels[k]`.
func (c *Client) GenMasterShares() (
	shares []multiparty.GaloisKeyGenShare,
	labels []int,
	err error,
) {
	labels = c.params.MasterAtoms()
	shares = make([]multiparty.GaloisKeyGenShare, len(labels))
	if len(labels) == 0 {
		return shares, labels, nil
	}
	topParams := c.params.LLKN.Top()
	gkgTop := multiparty.NewGaloisKeyGenProtocol(topParams)
	for i, a := range labels {
		crp := gkgTop.SampleCRP(c.crs)
		share := gkgTop.AllocateShare()
		galEl := topParams.GaloisElement(+a)
		if err := gkgTop.GenShare(c.skTop, galEl, crp, &share); err != nil {
			return nil, nil, fmt.Errorf("vclient: GenShare for master atom %d: %w", a, err)
		}
		shares[i] = share
	}
	return shares, labels, nil
}
