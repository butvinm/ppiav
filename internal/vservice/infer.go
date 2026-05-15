package vservice

import (
	"errors"
	"fmt"

	"github.com/butvinm/ppiav/internal/protocol"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"

	orioneval "github.com/butvinm/orion/v2/evaluator"
)

// Sentinel errors surfaced by Infer / evaluatorFor / orionEvaluatorFor.
// The HTTP layer maps both to 404 (caller error: unknown sid, or
// Stage-2d not yet completed). Use `errors.Is` rather than substring
// matches — the Phase-1 ("no evaluator") and Phase-2 ("no Orion
// evaluator") messages differ.
var (
	ErrUnknownSession = errors.New("vservice: unknown session id")
	ErrNoEvaluator    = errors.New("vservice: session has no evaluator; call StoreEvalKeys first")
)

// Infer runs the session's inference circuit. Phase 1 (Service built via
// `New`) evaluates the synthetic `x²` over a single ciphertext, consuming
// exactly one level — see docs/DESIGN.md §`Level budget — Phase 1`.
// Phase 2 (Service built via `NewWithOrion`) walks the compiled Orion
// graph via `orioneval.Evaluator.Forward` and returns the model's single
// output ciphertext; C3AE has one logit output, so we hard-assert the
// `[]*rlwe.Ciphertext` slice has length 1.
//
// Concurrency note: in Phase 1 the underlying `*ckks.Evaluator` is
// concurrency-safe (Lattigo v6.2.0), so we look up the session pointer
// under s.mu and release before the homomorphic work. The Orion
// `*evaluator.Evaluator` is NOT goroutine-safe; in this in-process,
// single-flight orchestration (one Runner per session) that's fine — we
// still release s.mu before the call so an unrelated session can
// proceed in parallel.
func (s *Service) Infer(sid protocol.SessionID, inputCt *rlwe.Ciphertext) (*rlwe.Ciphertext, error) {
	if s.orionModel != nil {
		oe, err := s.orionEvaluatorFor(sid)
		if err != nil {
			return nil, err
		}
		outs, err := oe.Forward(s.orionModel, []*rlwe.Ciphertext{inputCt})
		if err != nil {
			return nil, fmt.Errorf("vservice: Orion Forward: %w", err)
		}
		if len(outs) != 1 {
			return nil, fmt.Errorf("vservice: Orion Forward returned %d ciphertexts, expected 1 (C3AE single-output)", len(outs))
		}
		return outs[0], nil
	}

	eval, err := s.evaluatorFor(sid)
	if err != nil {
		return nil, err
	}
	out, err := eval.MulRelinNew(inputCt, inputCt)
	if err != nil {
		return nil, fmt.Errorf("vservice: x² mul-relin: %w", err)
	}
	if err := eval.Rescale(out, out); err != nil {
		return nil, fmt.Errorf("vservice: x² rescale: %w", err)
	}
	return out, nil
}

func (s *Service) evaluatorFor(sid protocol.SessionID) (*ckks.Evaluator, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[sid]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownSession, sid)
	}
	if sess.eval == nil {
		return nil, fmt.Errorf("%w (sid %q)", ErrNoEvaluator, sid)
	}
	return sess.eval, nil
}

func (s *Service) orionEvaluatorFor(sid protocol.SessionID) (*orioneval.Evaluator, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[sid]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownSession, sid)
	}
	if sess.orionEval == nil {
		return nil, fmt.Errorf("%w (Orion, sid %q)", ErrNoEvaluator, sid)
	}
	return sess.orionEval, nil
}
