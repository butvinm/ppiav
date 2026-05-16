// Package vclient is the subject-side crypto half of the protocol. It
// holds the client's secret-key share `sk_c` at TOP level (`params.LLKN.Top()`),
// drives the keygen handshake against VAgent's matching share (generating
// dual PK shares at eval+top levels, RLK, and dual atom-set Galois shares
// for auth + inference), encrypts the preprocessed image under the
// aggregated eval-level `pk`, and contributes the client's partial
// decryption with noise flooding during joint decryption. VClient never
// decrypts on its own — there is no `*rlwe.Decryptor` here. See
// docs/DESIGN.md §`internal/vclient` and §`Multiparty decryption with
// authentication`.
//
// Secret-key levels: `skTop` is generated at top level and used for
// top-level protocol calls (top PK gen, infer-atom Galois gen). The
// projected `skEval = params.ProjectSKToEval(skTop)` is cached lazily and
// reused by every eval-level protocol call: RLK gen, KeySwitch /
// partial-decrypt, eval-level PK gen, and auth-atom Galois gen.
//
// CRS draw order: every protocol's CRP comes from the same session-scoped
// `*sampling.KeyedPRNG` so VClient and VAgent see the same uniform stream.
// The order is fixed (docs/DESIGN.md §`internal/protocol`): pk_eval →
// pk_top → RLK (single CRP for both rounds) → auth atoms (eval level,
// ascending) → infer atoms (top level, ascending). Any deviation
// desynchronises the two sides silently.
package vclient

import (
	"fmt"

	"github.com/butvinm/ppiav/internal/protocol"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

// Client carries the per-session VClient state. New sessions allocate a
// fresh `Client`; the type is not safe for concurrent use across goroutines
// (single-session at a time per VClient, per docs/DESIGN.md §`internal/vclient`).
type Client struct {
	params protocol.Params
	sid    protocol.SessionID

	// crs is the session-scoped CRS the multiparty protocols draw their
	// CRPs from. The draw order is documented at the package level and is
	// load-bearing — VClient and VAgent must consume in lockstep.
	crs *sampling.KeyedPRNG

	// skTop is sk_c at TOP level (`params.LLKN.Top()`). The joint top-level
	// secret is sk_top = sk_c_top + sk_a_top (per docs/DESIGN.md §`Stage 2`).
	skTop *rlwe.SecretKey

	// skEvalCached is the lazy projection of skTop to eval level. Computed
	// on first call to skEval(); the projection is linear so each party
	// derives it independently from their own skTop.
	skEvalCached *rlwe.SecretKey

	// pkAgg is the eval-level aggregated public key (used to wire the
	// encryptor). The top-level aggregated public key is computed during
	// AggregatePK but VClient does not retain it — VAgent owns the
	// downstream wire path (the pk_top is aggregated independently by
	// VAgent and shipped to VService inside InferEvalKeys).
	pkAgg     *rlwe.PublicKey
	encryptor *rlwe.Encryptor
	encoder   *ckks.Encoder

	// Stashed per-protocol state. PK and RLK protocols are stateless across
	// calls, but the CRPs and the client-side shares need to survive
	// between Gen* and Aggregate* calls. Two PK protocols run — one per
	// level — each with its own CRP and local share.
	pkProtoEval      multiparty.PublicKeyGenProtocol
	pkCRPEval        multiparty.PublicKeyGenCRP
	pkShareLocalEval multiparty.PublicKeyGenShare
	pkProtoTop       multiparty.PublicKeyGenProtocol
	pkCRPTop         multiparty.PublicKeyGenCRP
	pkShareLocalTop  multiparty.PublicKeyGenShare

	rlkProto     multiparty.RelinearizationKeyGenProtocol
	rlkCRP       multiparty.RelinearizationKeyGenCRP
	rlkEphSk     *rlwe.SecretKey
	rlkShare1Loc multiparty.RelinearizationKeyGenShare
	rlkShare1Agg multiparty.RelinearizationKeyGenShare // round-1 aggregate, needed for round 2
}

// New constructs a Client for the given session. It generates `sk_c` at
// top level and builds the session CRS — both inputs to the keygen
// handshake. The CRS stream is shared with VAgent (same sid, same domain
// separator), but no bytes are consumed until the first Gen* call.
func New(params protocol.Params, sid protocol.SessionID) (*Client, error) {
	crs, err := protocol.NewSessionCRS(sid)
	if err != nil {
		return nil, fmt.Errorf("vclient: build session CRS: %w", err)
	}
	skTop := rlwe.NewKeyGenerator(params.LLKN.Top()).GenSecretKeyNew()
	return &Client{
		params:  params,
		sid:     sid,
		crs:     crs,
		skTop:   skTop,
		encoder: ckks.NewEncoder(params.CKKS),
	}, nil
}

// skEval returns the eval-level projection of skTop, computing and caching
// it on first call. Returns an error only if skTop is missing or the LLKN
// projection itself fails — both are infrastructure-level failures.
func (c *Client) skEval() (*rlwe.SecretKey, error) {
	if c.skEvalCached != nil {
		return c.skEvalCached, nil
	}
	if c.skTop == nil {
		return nil, fmt.Errorf("vclient: skEval called before skTop is generated")
	}
	out, err := c.params.ProjectSKToEval(c.skTop)
	if err != nil {
		return nil, fmt.Errorf("vclient: project sk_top to sk_eval: %w", err)
	}
	c.skEvalCached = out
	return out, nil
}

// SessionID returns the session id this client was constructed against.
func (c *Client) SessionID() protocol.SessionID { return c.sid }

// Params returns the bundled protocol parameters.
func (c *Client) Params() protocol.Params { return c.params }
