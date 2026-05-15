package vagent

import (
	"fmt"

	"github.com/butvinm/ppiav/internal/authenticator"
	"github.com/butvinm/ppiav/internal/protocol"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// ExportedState is the per-session VAgent state needed to rebuild an Agent
// in a separate process — the bench `mac` and `finalize` CLI subcommands
// consume it. The CRS is NOT serialized: NewWithState rebuilds it
// deterministically from SID via protocol.NewSessionCRS (mirroring
// OpenSession).
//
// Aggregated keys (PkAgg, Rlk, Gks) are conceptually held by VService and
// transported to the Agent's process via separate artifact files; this
// struct bundles them with the per-session secrets (SkShare, MacKey) for
// a single round-trip across the CLI boundary. mac/finalize both need a
// fully-wired evaluator and encryptor — PkAgg powers Auth's encrypt-v
// step, Rlk+Gks power Auth's rotate-and-sum.
type ExportedState struct {
	SID     protocol.SessionID
	SkShare *rlwe.SecretKey
	MacKey  authenticator.Key
	PkAgg   *rlwe.PublicKey
	Rlk     *rlwe.RelinearizationKey
	Gks     []*rlwe.GaloisKey
}

// ExportState snapshots the per-session state for `sid`. Returns an error
// if the session is unknown or its keygen hasn't completed (pkAgg / rlkAgg
// / eval not yet built). The live session remains in the Agent; the caller
// is responsible for any subsequent eviction.
func (a *Agent) ExportState(sid protocol.SessionID) (*ExportedState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	sess, err := a.sessionLocked(sid)
	if err != nil {
		return nil, err
	}
	if sess.skShare == nil {
		return nil, fmt.Errorf("vagent: ExportState session %q has nil skShare", sid)
	}
	if sess.pkAgg == nil {
		return nil, fmt.Errorf("vagent: ExportState session %q has nil pkAgg (run AggregatePK first)", sid)
	}
	if sess.rlkAgg == nil {
		return nil, fmt.Errorf("vagent: ExportState session %q has nil rlkAgg (run AggregateRLKRound2 first)", sid)
	}
	// Deep-copy MacKey.S so callers can't mutate the live session via the
	// slice header.
	sCopy := make([]int, len(sess.authKey.S))
	copy(sCopy, sess.authKey.S)
	// gks is built on the fly by mac/finalize callers from the
	// evaluation-key set; in tests it's surfaced by AggregateGaloisShares.
	// We deliberately do not stash a copy here — the test passes the gks
	// slice it received from AggregateGaloisShares directly.
	return &ExportedState{
		SID:     sid,
		SkShare: sess.skShare,
		MacKey:  authenticator.Key{S: sCopy, SeedF: sess.authKey.SeedF},
		PkAgg:   sess.pkAgg,
		Rlk:     sess.rlkAgg,
	}, nil
}

// NewWithState constructs a fresh Agent and seeds its sessions map with a
// single entry built from `state`. Used by the bench CLI to recreate Agent
// state across process boundaries. The CRS is rebuilt deterministically
// from state.SID — the same construction OpenSession uses. When PkAgg /
// Rlk / Gks are all non-nil the seeded session is ready for
// BuildAuthenticatedCt; when nil the session is mac/finalize-incapable
// (useful for tests that only need to verify state seeding).
func NewWithState(params protocol.Params, state *ExportedState) (*Agent, error) {
	if state == nil {
		return nil, fmt.Errorf("vagent: NewWithState state is nil")
	}
	if state.SkShare == nil {
		return nil, fmt.Errorf("vagent: NewWithState SkShare is nil")
	}
	auth, err := authenticator.New(params.Authenticator, params.CKKS)
	if err != nil {
		return nil, fmt.Errorf("vagent: NewWithState build Authenticator: %w", err)
	}
	crs, err := protocol.NewSessionCRS(state.SID)
	if err != nil {
		return nil, fmt.Errorf("vagent: NewWithState build CRS: %w", err)
	}
	sCopy := make([]int, len(state.MacKey.S))
	copy(sCopy, state.MacKey.S)
	a := &Agent{
		params:   params,
		auth:     auth,
		encoder:  ckks.NewEncoder(params.CKKS),
		sessions: map[protocol.SessionID]*sessionState{},
	}
	sess := &sessionState{
		crs:        crs,
		skShare:    state.SkShare,
		authKey:    authenticator.Key{S: sCopy, SeedF: state.MacKey.SeedF},
		authResult: make(chan *rlwe.Ciphertext, 1),
	}
	if state.PkAgg != nil {
		sess.pkAgg = state.PkAgg
		sess.encryptor = rlwe.NewEncryptor(params.CKKS, state.PkAgg)
	}
	if state.Rlk != nil {
		sess.rlkAgg = state.Rlk
		evk := rlwe.NewMemEvaluationKeySet(state.Rlk, state.Gks...)
		sess.eval = ckks.NewEvaluator(params.CKKS, evk)
	}
	a.sessions[state.SID] = sess
	return a, nil
}
