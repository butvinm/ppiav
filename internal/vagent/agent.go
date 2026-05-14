// Package vagent is the verification-side crypto half of the protocol. It
// holds the agent's secret-key share `sk_a` and the per-session
// `authenticator.Key`, drives the keygen handshake against VClient's
// matching share (generating/aggregating PK, RLK, and per-rotation Galois
// shares), builds the authenticated ciphertext `ct_M`, and runs the final
// step of the joint decryption + Ver. See docs/DESIGN.md §`internal/vagent`
// and §`Multiparty decryption with authentication`.
//
// CRS draw order is identical to VClient's (docs/DESIGN.md
// §`internal/protocol`): PK → RLK (single CRP for both rounds) →
// per-rotation Galois in ascending label order. Any deviation
// desynchronises the two sides silently.
//
// Concurrency: the Authenticator (cached `pt_one_hot`) is created once in
// New and shared across every session — Lattigo v6.2.0 made encoders and
// other per-structure resources safe to call concurrently, so a single
// Authenticator instance covers concurrent sessions.
package vagent

import (
	"crypto/rand"
	"fmt"
	"sync"

	"github.com/butvinm/ppiav/internal/authenticator"
	"github.com/butvinm/ppiav/internal/protocol"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

// sessionState captures every per-session resource VAgent persists between
// protocol stages. The keygen-stage fields (`pkProto`, `rlkProto`, …) are
// stashed between Gen* and Aggregate* calls so the matching CRP and local
// share survive across the handshake legs.
type sessionState struct {
	crs *sampling.KeyedPRNG

	// skShare is sk_a — the agent's share of the joint secret sk = sk_c + sk_a.
	skShare *rlwe.SecretKey

	// authKey is the per-session MPD-Auth key minted in OpenSession; consumed
	// once by FinalizeDecryption and then evicted from the sessions map.
	authKey authenticator.Key

	// Populated by AggregatePK and onward.
	pkAgg     *rlwe.PublicKey
	encryptor *rlwe.Encryptor

	// Populated by AggregateGaloisShares — VAgent needs the eval to run
	// Auth's rotation+sum.
	rlkAgg *rlwe.RelinearizationKey
	gks    []*rlwe.GaloisKey
	eval   *ckks.Evaluator

	// PK protocol stash (between GenPKShare and AggregatePK).
	pkProto      multiparty.PublicKeyGenProtocol
	pkCRP        multiparty.PublicKeyGenCRP
	pkShareLocal multiparty.PublicKeyGenShare

	// RLK protocol stash (across all four Gen/Aggregate calls). The CRP is
	// drawn once in Round 1 and reused in Round 2 per Lattigo's protocol.
	rlkProto     multiparty.RelinearizationKeyGenProtocol
	rlkCRP       multiparty.RelinearizationKeyGenCRP
	rlkEphSk     *rlwe.SecretKey
	rlkShare1Loc multiparty.RelinearizationKeyGenShare
	rlkShare1Agg multiparty.RelinearizationKeyGenShare
	rlkShare2Loc multiparty.RelinearizationKeyGenShare

	// Galois protocol stash (between GenGaloisShares and AggregateGaloisShares).
	galProto  multiparty.GaloisKeyGenProtocol
	galCRPs   []multiparty.GaloisKeyGenCRP
	galShares []multiparty.GaloisKeyGenShare
	galLabels []int
}

// Agent holds VAgent's protocol-wide state. The Authenticator is built
// once (its cached `pt_one_hot` is session-independent) and shared across
// concurrent sessions per Lattigo v6.2.0's concurrency guarantees.
type Agent struct {
	params   protocol.Params
	auth     *authenticator.Authenticator
	sessions map[protocol.SessionID]*sessionState
	mu       sync.Mutex
}

// New constructs an Agent with the supplied protocol parameters. The
// Authenticator is constructed up-front so its cached `pt_one_hot` is
// allocated once for the lifetime of the Agent.
func New(params protocol.Params) (*Agent, error) {
	auth, err := authenticator.New(params.Authenticator, params.CKKS)
	if err != nil {
		return nil, fmt.Errorf("vagent: build Authenticator: %w", err)
	}
	return &Agent{
		params:   params,
		auth:     auth,
		sessions: map[protocol.SessionID]*sessionState{},
	}, nil
}

// Params returns the bundled protocol parameters.
func (a *Agent) Params() protocol.Params { return a.params }

// OpenSession registers `sid`, mints `sk_a` and the per-session
// `authenticator.Key`, and builds the session-scoped CRS. The CRS stream
// is shared with VClient — both sides build it identically from the sid.
// Returns an error if the sid is already registered.
func (a *Agent) OpenSession(sid protocol.SessionID) error {
	crs, err := protocol.NewSessionCRS(sid)
	if err != nil {
		return fmt.Errorf("vagent: build session CRS: %w", err)
	}
	authKey, err := authenticator.KeyGen(a.params.Authenticator, rand.Reader)
	if err != nil {
		return fmt.Errorf("vagent: mint authKey: %w", err)
	}
	skShare := rlwe.NewKeyGenerator(a.params.CKKS).GenSecretKeyNew()

	a.mu.Lock()
	defer a.mu.Unlock()
	if _, exists := a.sessions[sid]; exists {
		return fmt.Errorf("vagent: session %q already open", sid)
	}
	a.sessions[sid] = &sessionState{
		crs:     crs,
		skShare: skShare,
		authKey: authKey,
	}
	return nil
}

// session looks up a registered session under the mutex. Callers that
// also need the mutex held should call sessionLocked instead.
func (a *Agent) session(sid protocol.SessionID) (*sessionState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sessionLocked(sid)
}

func (a *Agent) sessionLocked(sid protocol.SessionID) (*sessionState, error) {
	sess, ok := a.sessions[sid]
	if !ok {
		return nil, fmt.Errorf("vagent: unknown session id %q", sid)
	}
	return sess, nil
}
