package vservice

import (
	"fmt"

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
// Rlk + Glk are the aggregated evaluation keys produced by the multi-party
// keygen handshake. NewWithState rebuilds the evaluator from them, bypassing
// the StoreEvalKeys path that requires a prior OpenSession.
type ExportedState struct {
	SID protocol.SessionID
	Rlk *rlwe.RelinearizationKey
	Glk []*rlwe.GaloisKey
}

// ExportState snapshots the per-session state for `sid`. Returns an error
// if the session is unknown or its evaluator has not been built yet
// (StoreEvalKeys not called). The live session remains in the Service; the
// caller is responsible for any subsequent eviction.
//
// Rlk and Glk are populated from the values passed to StoreEvalKeys; the
// slice is shared by reference (GaloisKeys are large; tests and the HTTP
// path do not mutate per-element entries).
func (s *Service) ExportState(sid protocol.SessionID) (*ExportedState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[sid]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownSession, sid)
	}
	if sess.eval == nil && sess.orionEval == nil {
		return nil, fmt.Errorf("%w (sid %q)", ErrNoEvaluator, sid)
	}
	return &ExportedState{SID: sid, Rlk: sess.rlk, Glk: sess.glk}, nil
}

// NewWithState constructs a fresh Service seeded from `state`. When
// `orionDir` is non-empty the compiled Orion model is loaded the same way
// NewWithOrion loads it, and `params.CKKS`, `params.InputLevel` are
// overridden by the model's ClientParams (caller-side params for those
// fields are ignored — mirroring NewWithOrion). When `orionDir` is empty
// the Service runs in Phase-1 mode (synthetic x²) and `params` is used
// as-is.
//
// The session map is seeded directly: `state.SID → {evaluator}` with the
// evaluator built from `state.Rlk + state.Glk`. The random sid mint in
// OpenSession is bypassed so the bench `infer` subcommand can drive Infer
// against the keygen-emitted SID without re-running the handshake.
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
		m, ckksParams, inputLevel, rotations, err := loadOrionModel(orionDir)
		if err != nil {
			return nil, err
		}
		model = m
		mergedParams.CKKS = ckksParams
		mergedParams.InputLevel = inputLevel
		if len(params.ExtraRotationIndices) > 0 || len(rotations) > 0 {
			combined := make([]int, 0, len(params.ExtraRotationIndices)+len(rotations))
			combined = append(combined, params.ExtraRotationIndices...)
			combined = append(combined, rotations...)
			mergedParams.ExtraRotationIndices = combined
		}
	} else if params.CKKS.LogN() <= 0 {
		return nil, fmt.Errorf("vservice: NewWithState params.CKKS is zero-valued (LogN <= 0)")
	}

	s := &Service{
		params:     mergedParams,
		orionModel: model,
		sessions:   map[protocol.SessionID]*sessionState{},
	}

	evk := rlwe.NewMemEvaluationKeySet(state.Rlk, state.Glk...)
	sess := &sessionState{}
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
