package vservice

import (
	"fmt"

	"github.com/butvinm/ppiav/internal/protocol"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// Infer runs the Phase-1 synthetic inference circuit: `x²` followed by
// rescaling. Consumes exactly one level — see docs/DESIGN.md §`Level
// budget — Phase 1`. Phase 2 swaps this for the Orion-compiled C3AE
// circuit.
//
// Concurrency: Lattigo v6.2.0 makes per-structure methods (including
// Evaluator) safe to call concurrently, so we look up the evaluator
// pointer under s.mu and release the mutex before doing the (expensive)
// homomorphic work.
func (s *Service) Infer(sid protocol.SessionID, inputCt *rlwe.Ciphertext) (*rlwe.Ciphertext, error) {
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
		return nil, fmt.Errorf("vservice: unknown session id %q", sid)
	}
	if sess.eval == nil {
		return nil, fmt.Errorf("vservice: session %q has no evaluator; call StoreEvalKeys first", sid)
	}
	return sess.eval, nil
}
