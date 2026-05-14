// Package vservice is the FHE inference engine. It issues session IDs,
// holds per-session evaluator state, receives the aggregated rlk and
// Galois keys from VAgent, and runs the inference circuit. See
// docs/DESIGN.md §`internal/vservice`.
package vservice

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/butvinm/ppiav/internal/protocol"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// sidEntropyBytes is the byte length drawn for each session id. 16 bytes
// = 128 bits of entropy, hex-encoded to 32 chars on the wire (per
// docs/DESIGN.md §`internal/vservice`).
const sidEntropyBytes = 16

type sessionState struct {
	eval *ckks.Evaluator
}

// Service is the FHE inference engine. The evaluator for each session is
// built lazily by StoreEvalKeys; OpenSession only reserves the slot.
type Service struct {
	params   protocol.Params
	sessions map[protocol.SessionID]*sessionState
	mu       sync.Mutex
}

// New constructs a Service with the given protocol parameters. The
// session map starts empty.
func New(params protocol.Params) *Service {
	return &Service{
		params:   params,
		sessions: map[protocol.SessionID]*sessionState{},
	}
}

// Params returns the bundled protocol parameters.
func (s *Service) Params() protocol.Params { return s.params }

// OpenSession draws ≥128 bits of entropy from crypto/rand, hex-encodes
// them as the session id, reserves a slot in the session table, and
// returns the id. The session's *ckks.Evaluator is built later by
// StoreEvalKeys — the slot exists but holds nil until then.
func (s *Service) OpenSession() (protocol.SessionID, error) {
	var buf [sidEntropyBytes]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("vservice: draw session entropy: %w", err)
	}
	sid := protocol.SessionID(hex.EncodeToString(buf[:]))

	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sid] = &sessionState{}
	return sid, nil
}

// StoreEvalKeys builds the session's *ckks.Evaluator from the aggregated
// relinearization key and the per-rotation Galois keys. Phase 4 will
// swap `gks` for a lattigo-hierkeys master key.
//
// The signature uses `[]*rlwe.GaloisKey` (not `*rlwe.GaloisKeySet`)
// because Lattigo v6.2.0 does not expose a `GaloisKeySet` type — the
// same payload is what `rlwe.NewMemEvaluationKeySet` consumes (see
// internal/protocol/wire.go `InferEvalKeys` for precedent).
func (s *Service) StoreEvalKeys(
	sid protocol.SessionID,
	rlk *rlwe.RelinearizationKey,
	gks []*rlwe.GaloisKey,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[sid]
	if !ok {
		return fmt.Errorf("vservice: unknown session id %q", sid)
	}
	evk := rlwe.NewMemEvaluationKeySet(rlk, gks...)
	sess.eval = ckks.NewEvaluator(s.params.CKKS, evk)
	return nil
}
