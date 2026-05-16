package vagent

import (
	"fmt"

	hierkeys "github.com/butvinm/lattigo-hierkeys"
	"github.com/butvinm/ppiav/internal/authchain"
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
// Aggregated keys (PkAgg, PkTop, Rlk, GksAuth, GksMasterInfer) are
// conceptually held by VService and transported to the Agent's process
// via separate artifact files; this struct bundles them with the
// per-session secrets (SkTop, MacKey) for a single round-trip across the
// CLI boundary. mac/finalize both need a fully-wired chain evaluator and
// encryptor — PkAgg powers Auth's encrypt-v step, Rlk + GksAuth power
// Auth's chain-rotate-and-sum. PkTop + GksMasterInfer are stashed so a
// re-export round-trips the full keygen state.
type ExportedState struct {
	SID            protocol.SessionID
	SkTop          *rlwe.SecretKey
	MacKey         authenticator.Key
	PkAgg          *rlwe.PublicKey
	PkTop          *rlwe.PublicKey
	Rlk            *rlwe.RelinearizationKey
	GksAuth        []*rlwe.GaloisKey
	GksMasterInfer map[int]*hierkeys.MasterKey
}

// ExportState snapshots the per-session state for `sid`. Returns an error
// if the session is unknown or its keygen hasn't completed (pkAgg / rlkAgg
// not yet built). The live session remains in the Agent; the caller is
// responsible for any subsequent eviction.
func (a *Agent) ExportState(sid protocol.SessionID) (*ExportedState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	sess, err := a.sessionLocked(sid)
	if err != nil {
		return nil, err
	}
	if sess.skTop == nil {
		return nil, fmt.Errorf("vagent: ExportState session %q has nil skTop", sid)
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
	// Share the gksAuth slice and gksMasterInfer map by reference:
	// per-element entries are large and the bench caller serialises them
	// to disk immediately. Tests and the HTTP path do not mutate the
	// per-element entries; the shared slice/map headers are safe.
	return &ExportedState{
		SID:            sid,
		SkTop:          sess.skTop,
		MacKey:         authenticator.Key{S: sCopy, SeedF: sess.authKey.SeedF},
		PkAgg:          sess.pkAgg,
		PkTop:          sess.pkTopAgg,
		Rlk:            sess.rlkAgg,
		GksAuth:        sess.gksAuth,
		GksMasterInfer: sess.gksMasterInfer,
	}, nil
}

// NewWithState constructs a fresh Agent and seeds its sessions map with a
// single entry built from `state`. Used by the bench CLI to recreate Agent
// state across process boundaries. The CRS is rebuilt deterministically
// from state.SID — the same construction OpenSession uses. When PkAgg /
// Rlk / GksAuth are all non-nil the seeded session is ready for
// BuildAuthenticatedCt; when nil the session is mac/finalize-incapable
// (useful for tests that only need to verify state seeding).
func NewWithState(params protocol.Params, state *ExportedState) (*Agent, error) {
	if state == nil {
		return nil, fmt.Errorf("vagent: NewWithState state is nil")
	}
	if state.SkTop == nil {
		return nil, fmt.Errorf("vagent: NewWithState SkTop is nil")
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
		skTop:      state.SkTop,
		authKey:    authenticator.Key{S: sCopy, SeedF: state.MacKey.SeedF},
		authResult: make(chan *rlwe.Ciphertext, 1),
	}
	if state.PkAgg != nil {
		sess.pkAgg = state.PkAgg
		sess.encryptor = rlwe.NewEncryptor(params.CKKS, state.PkAgg)
	}
	if state.PkTop != nil {
		sess.pkTopAgg = state.PkTop
	}
	if state.Rlk != nil && state.GksAuth != nil {
		// Validate the loaded gks_auth.bin covers the canonical AuthAtoms
		// set at the expected (negative) Galois elements — a mismatched
		// artifact (wrong λ, different manifest) silently produces wrong
		// outputs at BuildAuthenticatedCt time.
		atoms := params.AuthAtoms()
		if err := validateGksAuthCoverage(params, atoms, state.GksAuth); err != nil {
			return nil, fmt.Errorf("vagent: NewWithState validate GksAuth: %w", err)
		}
		sess.rlkAgg = state.Rlk
		sess.gksAuth = state.GksAuth
		sess.gksMasterInfer = state.GksMasterInfer
		chainEval, err := authchain.New(params.CKKS, state.Rlk, state.GksAuth, atoms)
		if err != nil {
			return nil, fmt.Errorf("vagent: NewWithState build authchain: %w", err)
		}
		sess.authchain = chainEval
	}
	a.sessions[state.SID] = sess
	return a, nil
}

// validateGksAuthCoverage checks the loaded gks_auth slice covers the
// canonical auth-atom set at the expected eval-level Galois elements
// (negative atom per the signed-label convention on `protocol.Params`).
// A mismatch indicates a stale or cross-wired gks_auth.bin.
func validateGksAuthCoverage(params protocol.Params, atoms []int, gks []*rlwe.GaloisKey) error {
	if len(gks) != len(atoms) {
		return fmt.Errorf("GksAuth length %d != AuthAtoms length %d", len(gks), len(atoms))
	}
	if len(atoms) == 0 {
		return nil
	}
	present := make(map[uint64]struct{}, len(gks))
	for _, gk := range gks {
		if gk == nil {
			return fmt.Errorf("GksAuth contains nil entry")
		}
		present[gk.GaloisElement] = struct{}{}
	}
	for _, atom := range atoms {
		want := params.CKKS.GaloisElement(-atom)
		if _, ok := present[want]; !ok {
			return fmt.Errorf("GksAuth missing GaloisElement %d (atom %d)", want, atom)
		}
	}
	return nil
}
