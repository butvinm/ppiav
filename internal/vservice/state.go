package vservice

import (
	"fmt"

	hierkeys "github.com/butvinm/lattigo-hierkeys"
	"github.com/butvinm/ppiav/internal/protocol"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"

	orioneval "github.com/butvinm/orion/v2/evaluator"
)

// ExportedState is the per-session VService state needed to rebuild a
// Service in a separate process — the bench `infer` CLI subcommand consumes
// it. The Orion model itself is NOT serialized: NewWithState reloads it
// from disk (or skips loading entirely when orionDir == "").
//
// The snapshot carries the small inbound payload (`Rlk`, `PKTop`,
// `GksMaster`) PLUS the materialised `GksInfer` slice when available —
// `ExportState` populates it directly from the live session so the CLI
// `keygen` subcommand can persist the derived rotation set to disk
// (per-sample re-derivation is multi-minute at LogN=16). `NewWithState`
// honours `GksInfer` when supplied (no re-derivation) and falls back to
// running the hierkeys derivation against `PKTop + GksMaster` when nil —
// the HTTP path doesn't carry it on the wire.
type ExportedState struct {
	SID       protocol.SessionID
	Rlk       *rlwe.RelinearizationKey
	PKTop     *rlwe.PublicKey
	GksMaster map[int]*hierkeys.MasterKey
	GksInfer  []*rlwe.GaloisKey
}

// ExportState snapshots the per-session state for `sid`. Returns an error
// if the session is unknown or its evaluator has not been built yet
// (StoreEvalKeys not called). The live session remains in the Service; the
// caller is responsible for any subsequent eviction.
//
// `Rlk`, `PKTop`, and `GksMaster` are stashed by StoreEvalKeys and shared
// by reference. `GksInfer` is populated from the live session so the CLI
// keygen subcommand can persist the derived rotation set to disk
// (per-sample re-derivation is multi-minute at LogN=16). NewWithState
// honours a non-nil `GksInfer` when supplied; otherwise it re-runs the
// hierarchical derivation against `PKTop + GksMaster`.
func (s *Service) ExportState(sid protocol.SessionID) (*ExportedState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[sid]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownSession, sid)
	}
	// Manifest-only Service (NewWithOrionManifest) intentionally builds
	// no evaluator — StoreEvalKeys stashes rlk/gks/pkTop/gksMaster on
	// the session and returns without constructing one. ExportState
	// still needs to round-trip those artifacts to disk for the bench
	// keygen subcommand.
	if !s.orionMode && sess.eval == nil && sess.orionEval == nil {
		return nil, fmt.Errorf("%w (sid %q)", ErrNoEvaluator, sid)
	}
	if s.orionMode && s.orionModel != nil && sess.orionEval == nil {
		return nil, fmt.Errorf("%w (sid %q)", ErrNoEvaluator, sid)
	}
	return &ExportedState{
		SID:       sid,
		Rlk:       sess.rlk,
		PKTop:     sess.pkTop,
		GksMaster: sess.gksMaster,
		GksInfer:  sess.gksInfer,
	}, nil
}

// NewWithState constructs a fresh Service seeded from `state`. When
// `orionDir` is non-empty the compiled Orion model is loaded the same way
// NewWithOrion loads it, and `params.CKKS`, `params.InputLevel` are
// overridden by the model's ClientParams (caller-side params for those
// fields are ignored — mirroring NewWithOrion). When `orionDir` is empty
// the Service runs in synthetic-x² mode and `params` is used as-is.
//
// The session map is seeded directly: `state.SID → {evaluator}`. The
// per-target Galois keys are re-derived from `state.PKTop +
// state.GksMaster` via the same hierarchical expansion
// `StoreEvalKeys` runs. The random sid mint in OpenSession is bypassed
// so the bench `infer` subcommand can drive Infer against the
// keygen-emitted SID without re-running the multi-party handshake.
func NewWithState(params protocol.Params, orionDir string, state *ExportedState) (*Service, error) {
	if state == nil {
		return nil, fmt.Errorf("vservice: NewWithState state is nil")
	}
	if state.Rlk == nil {
		return nil, fmt.Errorf("vservice: NewWithState Rlk is nil")
	}

	var (
		model        *orioneval.Model
		mergedParams = params
	)
	if orionDir != "" {
		merged, m, err := mergeOrionParams(params, orionDir)
		if err != nil {
			return nil, fmt.Errorf("vservice: NewWithState: %w", err)
		}
		mergedParams = merged
		model = m
	} else if params.CKKS.LogN() <= 0 {
		return nil, fmt.Errorf("vservice: NewWithState params.CKKS is zero-valued (LogN <= 0)")
	}

	// Honour a pre-derived gks_infer when supplied — the bench `infer`
	// CLI subcommand passes it in straight from disk (gks_infer.bin) so a
	// per-sample re-derivation isn't paid on every Infer invocation. The
	// HTTP path leaves it nil and re-derives from PKTop + GksMaster.
	//
	// When supplied, validate the loaded set actually covers
	// ExtraRotationIndices — a mismatched gks_infer.bin (wrong manifest,
	// different λ, swapped artifact dir) would silently produce wrong
	// outputs at Infer time. Empty ExtraRotationIndices means synthetic-x²
	// mode, in which case gks_infer should be empty.
	var (
		gks        []*rlwe.GaloisKey
		deriveSecs float64
	)
	if state.GksInfer != nil {
		if err := validateGksInferCoverage(mergedParams, state.GksInfer); err != nil {
			return nil, fmt.Errorf("vservice: NewWithState validate GksInfer: %w", err)
		}
		gks = state.GksInfer
	} else {
		var err error
		gks, deriveSecs, err = deriveGksInfer(mergedParams, state.PKTop, state.GksMaster)
		if err != nil {
			return nil, fmt.Errorf("vservice: NewWithState derive gks_infer: %w", err)
		}
	}

	s := &Service{
		params:     mergedParams,
		orionModel: model,
		orionMode:  model != nil,
		sessions:   map[protocol.SessionID]*sessionState{},
	}

	evk := rlwe.NewMemEvaluationKeySet(state.Rlk, gks...)
	// Stash everything on the session so a subsequent ExportState
	// round-trips the same compact payload back out (PKTop +
	// GksMaster, not the multi-GB derived slice).
	sess := &sessionState{
		rlk:                   state.Rlk,
		gksInfer:              gks,
		pkTop:                 state.PKTop,
		gksMaster:             state.GksMaster,
		deriveGksInferSeconds: deriveSecs,
	}
	if model != nil {
		oe, err := orioneval.NewEvaluatorFromKeySet(mergedParams.CKKS, evk, nil)
		if err != nil {
			return nil, fmt.Errorf("vservice: NewWithState build Orion evaluator: %w", err)
		}
		sess.orionEval = oe
	} else {
		sess.eval = ckks.NewEvaluator(mergedParams.CKKS, evk)
	}
	s.sessions[state.SID] = sess
	return s, nil
}

// validateGksInferCoverage checks that the supplied gks_infer slice covers
// the per-target rotation set the inference circuit needs. Each label in
// `params.ExtraRotationIndices` (signed-label convention per
// `protocol.Params` docs) must have a corresponding key at
// `params.CKKS.GaloisElement(-label)`. A mismatched gks_infer.bin (wrong
// manifest, different λ, swapped artifact dir) silently produces wrong
// outputs at Infer time without this guard.
func validateGksInferCoverage(params protocol.Params, gks []*rlwe.GaloisKey) error {
	targets := params.ExtraRotationIndices
	if len(targets) == 0 {
		if len(gks) != 0 {
			return fmt.Errorf("ExtraRotationIndices empty but GksInfer has %d entries", len(gks))
		}
		return nil
	}
	if len(gks) != len(targets) {
		return fmt.Errorf("GksInfer length %d != ExtraRotationIndices length %d", len(gks), len(targets))
	}
	present := make(map[uint64]struct{}, len(gks))
	for _, gk := range gks {
		if gk == nil {
			return fmt.Errorf("GksInfer contains nil entry")
		}
		present[gk.GaloisElement] = struct{}{}
	}
	for _, label := range targets {
		want := params.CKKS.GaloisElement(-label)
		if _, ok := present[want]; !ok {
			return fmt.Errorf("GksInfer missing GaloisElement %d (label %d)", want, label)
		}
	}
	return nil
}
