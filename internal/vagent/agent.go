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

	hierkeys "github.com/butvinm/lattigo-hierkeys"
	"github.com/butvinm/ppiav/internal/authchain"
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

	// skTop is sk_a at TOP level (`params.LLKN.Top()`). The joint top-level
	// secret is sk_top = sk_c_top + sk_a_top.
	skTop *rlwe.SecretKey

	// skEvalCached is the lazy projection of skTop to eval level. Computed
	// on first call to skEval(); the projection is linear so each party
	// derives it independently from their own skTop. Consumed by: RLK
	// gen rounds, KeySwitch (partial-decrypt), eval-level PK gen, and
	// auth-atom Galois gen.
	skEvalCached *rlwe.SecretKey

	// authKey is the per-session MPD-Auth key minted in OpenSession; consumed
	// once by FinalizeDecryption and then evicted from the sessions map.
	authKey authenticator.Key

	// Populated by AggregatePK and onward. `pkAgg` is the eval-level
	// aggregated pk used by Auth to encrypt v under pkAgg. `pkTopAgg` is
	// the top-level aggregated pk shipped to VService inside
	// InferEvalKeys (consumed by hierkeys.PubToRot to seed the
	// LevelExpansion).
	pkAgg     *rlwe.PublicKey
	pkTopAgg  *rlwe.PublicKey
	encryptor *rlwe.Encryptor

	// Populated by AggregateGaloisShares.
	// `rlkAgg` is the aggregated eval-level relinearization key.
	// `gksAuth` is the per-auth-atom raw `*rlwe.GaloisKey` slice (eval
	// level, negative galEls). Used directly by `authchain` (no
	// hierarchical derivation at VAgent). Stashed so ExportState can
	// hand the full set to the bench `mac` / `finalize` subprocesses.
	// `gksMasterInfer` is the inference-side master-key bundle
	// (top level, positive galEls, hierkeys.GaloisKeyToMasterKey'd).
	// Shipped to VService via InferEvalKeys.
	// `authchain` wraps a `*ckks.Evaluator` over rlkAgg + gksAuth and
	// performs the binary-decompose chain rotation Auth's step 4 issues.
	rlkAgg         *rlwe.RelinearizationKey
	gksAuth        []*rlwe.GaloisKey
	gksMasterInfer map[int]*hierkeys.MasterKey
	authchain      *authchain.Evaluator

	// PK protocol stash (between GenPKShare and AggregatePK). Two
	// protocols run per stage — one per level. Each carries its own
	// CRP and local share, finalised into eval-level + top-level pks.
	pkProtoEval      multiparty.PublicKeyGenProtocol
	pkCRPEval        multiparty.PublicKeyGenCRP
	pkShareLocalEval multiparty.PublicKeyGenShare
	pkProtoTop       multiparty.PublicKeyGenProtocol
	pkCRPTop         multiparty.PublicKeyGenCRP
	pkShareLocalTop  multiparty.PublicKeyGenShare

	// RLK protocol stash (across all four Gen/Aggregate calls). The CRP is
	// drawn once in Round 1 and reused in Round 2 per Lattigo's protocol.
	rlkProto     multiparty.RelinearizationKeyGenProtocol
	rlkCRP       multiparty.RelinearizationKeyGenCRP
	rlkEphSk     *rlwe.SecretKey
	rlkShare1Loc multiparty.RelinearizationKeyGenShare
	rlkShare1Agg multiparty.RelinearizationKeyGenShare
	rlkShare2Loc multiparty.RelinearizationKeyGenShare

	// Galois protocol stash (between GenAuthAndInferShares and
	// AggregateGaloisShares). Two iterations run — one per atom set.
	// Each iteration is keyed by its own CRP and local share slice in
	// ascending atom order.
	galProtoEval  multiparty.GaloisKeyGenProtocol
	galCRPsAuth   []multiparty.GaloisKeyGenCRP
	galSharesAuth []multiparty.GaloisKeyGenShare
	authLabels    []int
	galProtoTop   multiparty.GaloisKeyGenProtocol
	galCRPsInfer  []multiparty.GaloisKeyGenCRP
	galSharesInfer []multiparty.GaloisKeyGenShare
	inferLabels   []int

	// authResult is the Stage-3 → Stage-4a hand-off: capacity-1 buffered so
	// the image POST handler can deposit ct_M before the SSE receiver opens
	// without blocking (and without bookkeeping for the pre-arrival race).
	// Receivers must use `select { case <-authResult: ...; case <-ctx.Done(): }`
	// to remain cancellable on browser disconnect — `sync.Cond.Wait` would
	// not. See docs/DESIGN.md line 175 (open SSE before image POST).
	authResult chan *rlwe.Ciphertext

	// authenticatedCt caches the ct_M produced by BuildAuthenticatedCt so
	// the Stage-4a partial-decryption handler can pass it to
	// FinalizeDecryption without re-deriving it. The HTTP layer needs this
	// because the SSE channel is single-receive (the browser consumed it);
	// FinalizeDecryption's signature requires the ciphertext as input.
	// Populated by handleImage in http.go, consumed by handlePartialDecrypt.
	authenticatedCt *rlwe.Ciphertext
}

// Agent holds VAgent's protocol-wide state. The Authenticator is built
// once (its cached `pt_one_hot` is session-independent) and shared across
// concurrent sessions per Lattigo v6.2.0's concurrency guarantees. The
// shared `encoder` mirrors the Authenticator's pattern — it's used by
// FinalizeDecryption and is params-only (no key material), so a single
// instance is sufficient for the Agent's lifetime.
type Agent struct {
	params   protocol.Params
	auth     *authenticator.Authenticator
	encoder  *ckks.Encoder
	sessions map[protocol.SessionID]*sessionState
	mu       sync.Mutex
}

// New constructs an Agent with the supplied protocol parameters. The
// Authenticator and the shared encoder are constructed up-front so their
// per-call allocations move out of FinalizeDecryption's hot path.
func New(params protocol.Params) (*Agent, error) {
	auth, err := authenticator.New(params.Authenticator, params.CKKS)
	if err != nil {
		return nil, fmt.Errorf("vagent: build Authenticator: %w", err)
	}
	return &Agent{
		params:   params,
		auth:     auth,
		encoder:  ckks.NewEncoder(params.CKKS),
		sessions: map[protocol.SessionID]*sessionState{},
	}, nil
}

// Params returns the bundled protocol parameters.
func (a *Agent) Params() protocol.Params { return a.params }

// OpenSession registers `sid`, mints `sk_a` at TOP level, the per-session
// `authenticator.Key`, and builds the session-scoped CRS. The CRS stream
// is shared with VClient — both sides build it identically from the sid.
// Returns an error if the sid is already registered.
//
// sk_a lives at top level (`params.LLKN.Top()`) so the top-level PK gen
// and infer-atom Galois gen consume it directly; eval-level operations
// (RLK gen, KeySwitch, eval-level PK gen, auth-atom Galois gen) consume
// the lazy `skEval = params.ProjectSKToEval(skTop)` projection cached on
// the session.
func (a *Agent) OpenSession(sid protocol.SessionID) error {
	crs, err := protocol.NewSessionCRS(sid)
	if err != nil {
		return fmt.Errorf("vagent: build session CRS: %w", err)
	}
	authKey, err := authenticator.KeyGen(a.params.Authenticator, rand.Reader)
	if err != nil {
		return fmt.Errorf("vagent: mint authKey: %w", err)
	}
	skTop := rlwe.NewKeyGenerator(a.params.LLKN.Top()).GenSecretKeyNew()

	a.mu.Lock()
	defer a.mu.Unlock()
	if _, exists := a.sessions[sid]; exists {
		return fmt.Errorf("vagent: session %q already open", sid)
	}
	a.sessions[sid] = &sessionState{
		crs:        crs,
		skTop:      skTop,
		authKey:    authKey,
		authResult: make(chan *rlwe.Ciphertext, 1),
	}
	return nil
}

// sessionSkEval returns the eval-level projection of the session's
// skTop, computing and caching it on first call. Returns an error only
// if skTop is missing (impossible by protocol) or the LLKN projection
// itself fails (infrastructure error). The caller must hold a.mu.
func (a *Agent) sessionSkEvalLocked(sess *sessionState) (*rlwe.SecretKey, error) {
	if sess.skEvalCached != nil {
		return sess.skEvalCached, nil
	}
	if sess.skTop == nil {
		return nil, fmt.Errorf("vagent: sessionSkEval called before skTop is minted")
	}
	out, err := a.params.ProjectSKToEval(sess.skTop)
	if err != nil {
		return nil, fmt.Errorf("vagent: project sk_top to sk_eval: %w", err)
	}
	sess.skEvalCached = out
	return out, nil
}

// SessionAuthResult exposes the per-session authResult channel for the SSE
// handler in http.go. Returns (nil, false) if the sid is unknown.
// Package-internal: http.go and tests are the only callers.
func (a *Agent) SessionAuthResult(sid protocol.SessionID) (chan *rlwe.Ciphertext, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	sess, ok := a.sessions[sid]
	if !ok {
		return nil, false
	}
	return sess.authResult, true
}

// storeAuthenticatedCt caches ct_M so the partial-decryption handler can
// retrieve it. Returns false if the sid is unknown (the caller maps that
// to a 404 with no callback per docs/DESIGN.md §`Failure modes`).
func (a *Agent) storeAuthenticatedCt(sid protocol.SessionID, ct *rlwe.Ciphertext) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	sess, ok := a.sessions[sid]
	if !ok {
		return false
	}
	sess.authenticatedCt = ct
	return true
}

// SessionAuthenticatedCt returns the cached ct_M for `sid`. The second
// return is false if the sid is unknown. The ct value is nil until
// storeAuthenticatedCt has run; callers check `ct != nil` to detect the
// pre-image case. http.go uses this in the partial-decryption handler to
// assemble FinalizeDecryption's input.
func (a *Agent) SessionAuthenticatedCt(sid protocol.SessionID) (ct *rlwe.Ciphertext, ok bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	sess, exists := a.sessions[sid]
	if !exists {
		return nil, false
	}
	return sess.authenticatedCt, true
}

// session looks up a registered session under the mutex. Callers that
// also need the mutex held should call sessionLocked instead.
func (a *Agent) session(sid protocol.SessionID) (*sessionState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sessionLocked(sid)
}

// EvictSession removes `sid` from the sessions table. Used by the HTTP
// layer to clean up after an unrecoverable Stage-2d failure (e.g.,
// VService eval-keys forwarding error): the session's keygen stash is
// already drained by AggregateGaloisShares, so retry is impossible —
// evicting forces the client into a clean restart.
func (a *Agent) EvictSession(sid protocol.SessionID) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.sessions, sid)
}

func (a *Agent) sessionLocked(sid protocol.SessionID) (*sessionState, error) {
	sess, ok := a.sessions[sid]
	if !ok {
		return nil, fmt.Errorf("vagent: unknown session id %q", sid)
	}
	return sess, nil
}
