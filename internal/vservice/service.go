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

	orioneval "github.com/butvinm/orion/v2/evaluator"
)

// sidEntropyBytes is the byte length drawn for each session id. 16 bytes
// = 128 bits of entropy, hex-encoded to 32 chars on the wire (per
// docs/DESIGN.md §`internal/vservice`).
const sidEntropyBytes = 16

// sessionState carries per-session evaluator handles. Exactly one of
// `eval` (Phase-1 x² path) or `orionEval` (Phase-2 Orion path) is non-nil
// after `StoreEvalKeys`; which one is decided by whether the parent
// `Service` was built with `New` or `NewWithOrion`.
//
// `*ckks.Evaluator` is concurrency-safe (Lattigo v6.2.0). The Orion
// `*evaluator.Evaluator` is NOT goroutine-safe (Orion doc.go); each
// session therefore owns its own instance.
type sessionState struct {
	eval      *ckks.Evaluator
	orionEval *orioneval.Evaluator
}

// Service is the FHE inference engine. The evaluator for each session is
// built lazily by StoreEvalKeys; OpenSession only reserves the slot.
//
// When `orionModel` is non-nil the Service runs in Phase-2 mode: each
// session builds an `orioneval.Evaluator` from its aggregated rlk+gks and
// `Infer` calls `Forward` on the shared (goroutine-safe) Model. Otherwise
// the Service runs the Phase-1 synthetic `x²` circuit against the
// session's `*ckks.Evaluator`.
type Service struct {
	params     protocol.Params
	orionModel *orioneval.Model
	sessions   map[protocol.SessionID]*sessionState
	mu         sync.Mutex
}

// New constructs a Phase-1 Service that runs the synthetic `x²` circuit.
// The session map starts empty. Panics on a zero-valued `params.CKKS`
// (LogN == 0) — misconfiguration should fail close to the bug rather
// than at the first session.
func New(params protocol.Params) *Service {
	if params.CKKS.LogN() <= 0 {
		panic("vservice: params.CKKS is zero-valued (LogN <= 0); pass a configured protocol.Params")
	}
	return &Service{
		params:   params,
		sessions: map[protocol.SessionID]*sessionState{},
	}
}

// NewWithOrion constructs a Phase-2 Service that runs the compiled Orion
// circuit at `<orionDir>/model.orion`. The model is loaded once at
// construction; the returned Service overrides `params.CKKS` and
// `params.InputLevel` with the model's `ClientParams()` so callers
// downstream (VAgent, VClient) MUST consume `Service.Params()` rather
// than reusing the params they passed in.
//
// `params.Authenticator` and `params.FloodSigma` are kept verbatim — the
// authenticator config is independent of the inference circuit. The
// rotation indices declared by the manifest are unioned into
// `params.ExtraRotationIndices` so the collaborative GaloisKeyGen
// handshake covers both the authenticator's `[1, Lambda)` set and any
// rotations the circuit needs.
func NewWithOrion(params protocol.Params, orionDir string) (*Service, error) {
	model, ckksParams, inputLevel, rotations, err := loadOrionModel(orionDir)
	if err != nil {
		return nil, err
	}

	merged := params
	merged.CKKS = ckksParams
	merged.InputLevel = inputLevel
	// Defensive copy: appending to merged.ExtraRotationIndices must not
	// mutate the caller's slice (params is passed by value but the
	// underlying array is shared).
	if len(params.ExtraRotationIndices) > 0 || len(rotations) > 0 {
		combined := make([]int, 0, len(params.ExtraRotationIndices)+len(rotations))
		combined = append(combined, params.ExtraRotationIndices...)
		combined = append(combined, rotations...)
		merged.ExtraRotationIndices = combined
	}

	return &Service{
		params:     merged,
		orionModel: model,
		sessions:   map[protocol.SessionID]*sessionState{},
	}, nil
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
	if s.orionModel != nil {
		// Phase-2 path: per-session Orion Evaluator. The model is shared.
		// C3AE does not bootstrap, so btpKeys is nil.
		oe, err := orioneval.NewEvaluatorFromKeySet(s.params.CKKS, evk, nil)
		if err != nil {
			return fmt.Errorf("vservice: build Orion evaluator: %w", err)
		}
		sess.orionEval = oe
		return nil
	}
	sess.eval = ckks.NewEvaluator(s.params.CKKS, evk)
	return nil
}
