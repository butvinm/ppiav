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

// GenAuthAndInferShares produces the two parallel share lists VAgent's
// dual-atom-set Galois handshake consumes:
//
//   - Auth atoms (eval level, NEGATIVE Galois elements). One share per
//     atom in `c.params.AuthAtoms()` (e.g. `{1,2,4,8,16,32,64}` for λ=128).
//     `gkg = multiparty.NewGaloisKeyGenProtocol(c.params.CKKS)`. Secret-key
//     arg is `skEval`. Each call uses `c.params.CKKS.GaloisElement(-atom)`.
//     The aggregated keys are raw `*rlwe.GaloisKey`s used directly by the
//     authenticator chain-rotation (no hierkeys conversion).
//   - Infer atoms (top level, POSITIVE Galois elements). One share per
//     atom in `c.params.InferAtoms()` (e.g. `{1,4,...,16384}` at LogN=16,
//     base=4). `gkg = multiparty.NewGaloisKeyGenProtocol(c.params.LLKN.Top())`.
//     Secret-key arg is `skTop`. Each call uses
//     `c.params.LLKN.Top().GaloisElement(+atom)`. The aggregated keys are
//     converted via `hierkeys.GaloisKeyToMasterKey` (VAgent's job) into
//     the master-key bundle VService runs `hierkeys.LevelExpansion` over.
//
// CRS draw order: per the package contract, draws here follow pk_eval,
// pk_top, rlk. First all `len(AuthAtoms())` auth CRPs are drawn at eval
// level in ascending atom order, then all `len(InferAtoms())` infer CRPs
// at top level in ascending atom order. VAgent draws in lockstep.
//
// The returned label slices are parallel to the share slices: `authShares[k]`
// corresponds to `authLabels[k]`, similarly for infer.
func (c *Client) GenAuthAndInferShares() (
	authShares []multiparty.GaloisKeyGenShare,
	inferShares []multiparty.GaloisKeyGenShare,
	authLabels []int,
	inferLabels []int,
	err error,
) {
	skEval, err := c.skEval()
	if err != nil {
		return nil, nil, nil, nil, err
	}

	authLabels = c.params.AuthAtoms()
	authShares = make([]multiparty.GaloisKeyGenShare, len(authLabels))
	if len(authLabels) > 0 {
		gkgEval := multiparty.NewGaloisKeyGenProtocol(c.params.CKKS)
		for i, a := range authLabels {
			crp := gkgEval.SampleCRP(c.crs)
			share := gkgEval.AllocateShare()
			galEl := c.params.CKKS.GaloisElement(-a)
			if err := gkgEval.GenShare(skEval, galEl, crp, &share); err != nil {
				return nil, nil, nil, nil, fmt.Errorf("vclient: GenShare for auth atom %d: %w", a, err)
			}
			authShares[i] = share
		}
	}

	inferLabels = c.params.InferAtoms()
	inferShares = make([]multiparty.GaloisKeyGenShare, len(inferLabels))
	if len(inferLabels) > 0 {
		topParams := c.params.LLKN.Top()
		gkgTop := multiparty.NewGaloisKeyGenProtocol(topParams)
		for i, a := range inferLabels {
			crp := gkgTop.SampleCRP(c.crs)
			share := gkgTop.AllocateShare()
			galEl := topParams.GaloisElement(+a)
			if err := gkgTop.GenShare(c.skTop, galEl, crp, &share); err != nil {
				return nil, nil, nil, nil, fmt.Errorf("vclient: GenShare for infer atom %d: %w", a, err)
			}
			inferShares[i] = share
		}
	}

	return authShares, inferShares, authLabels, inferLabels, nil
}
