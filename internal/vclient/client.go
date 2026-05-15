// Package vclient is the subject-side crypto half of the protocol. It
// holds the client's secret-key share `sk_c`, drives the keygen handshake
// against VAgent's matching share (generating/aggregating PK, RLK, and
// per-rotation Galois shares), encrypts the preprocessed image under the
// aggregated `pk`, and contributes the client's partial decryption with
// noise flooding during joint decryption. VClient never decrypts on its
// own — there is no `*rlwe.Decryptor` here. See docs/DESIGN.md
// §`internal/vclient` and §`Multiparty decryption with authentication`.
//
// CRS draw order: every protocol's CRP comes from the same session-scoped
// `*sampling.KeyedPRNG` so VClient and VAgent see the same uniform stream.
// The order is fixed (docs/DESIGN.md §`internal/protocol`): PK → RLK
// (single CRP for both rounds) → per-rotation Galois in ascending label
// order. Any deviation desynchronises the two sides silently.
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

	// skShare is sk_c, the local secret-key share. The joint secret is
	// sk = sk_c + sk_a (per docs/DESIGN.md §`Stage 2`).
	skShare *rlwe.SecretKey

	// pkAgg is set after AggregatePK. Until then, EncryptImage errors.
	pkAgg     *rlwe.PublicKey
	encryptor *rlwe.Encryptor
	encoder   *ckks.Encoder

	// Stashed per-protocol state. PK and RLK protocols are stateless across
	// calls, but the CRP and the client-side share need to survive between
	// Gen* and Aggregate* calls.
	pkProto      multiparty.PublicKeyGenProtocol
	pkCRP        multiparty.PublicKeyGenCRP
	pkShareLocal multiparty.PublicKeyGenShare

	rlkProto      multiparty.RelinearizationKeyGenProtocol
	rlkCRP        multiparty.RelinearizationKeyGenCRP
	rlkEphSk      *rlwe.SecretKey
	rlkShare1Loc  multiparty.RelinearizationKeyGenShare
	rlkShare1Agg  multiparty.RelinearizationKeyGenShare // round-1 aggregate, needed for round 2
}

// New constructs a Client for the given session. It generates `sk_c` and
// builds the session CRS — both inputs to the keygen handshake. The CRS
// stream is shared with VAgent (same sid, same domain separator), but no
// bytes are consumed until the first Gen* call.
func New(params protocol.Params, sid protocol.SessionID) (*Client, error) {
	crs, err := protocol.NewSessionCRS(sid)
	if err != nil {
		return nil, fmt.Errorf("vclient: build session CRS: %w", err)
	}
	skShare := rlwe.NewKeyGenerator(params.CKKS).GenSecretKeyNew()
	return &Client{
		params:  params,
		sid:     sid,
		crs:     crs,
		skShare: skShare,
		encoder: ckks.NewEncoder(params.CKKS),
	}, nil
}

// SessionID returns the session id this client was constructed against.
func (c *Client) SessionID() protocol.SessionID { return c.sid }

// Params returns the bundled protocol parameters.
func (c *Client) Params() protocol.Params { return c.params }
