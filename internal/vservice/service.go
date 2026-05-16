// Package vservice is the FHE inference engine. It issues session IDs,
// holds per-session evaluator state, receives the aggregated rlk and
// Galois keys from VAgent, and runs the inference circuit. See
// docs/DESIGN.md §`internal/vservice`.
package vservice

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"runtime"
	"sync"
	"time"

	hierkeys "github.com/butvinm/lattigo-hierkeys"
	"github.com/butvinm/lattigo-hierkeys/llkn"
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
// `eval` (synthetic-x² path) or `orionEval` (Orion path) is non-nil
// after `StoreEvalKeys`; which one is decided by whether the parent
// `Service` was built with `New` or `NewWithOrion`.
//
// `*ckks.Evaluator` is concurrency-safe (Lattigo v6.2.0). The Orion
// `*evaluator.Evaluator` is NOT goroutine-safe (Orion doc.go); each
// session therefore owns its own instance.
//
// `rlk` and `glk` are stashed by StoreEvalKeys so ExportState can hand
// them back to the bench `infer` subprocess. The HTTP path doesn't read
// them — only the evaluator built from the merged key set is consulted
// at Infer time.
//
// `deriveGksInferSeconds` records the wall-clock time spent inside
// `StoreEvalKeys` running `LevelExpansion.Derive + FinalizeKey` across
// every target rotation. The orchestrator/CLI surfaces this through the
// bench harness under the step name `keygen.galois.service_store` — at
// `LogN=16` it is the dominant per-session cost (~tens of seconds
// concurrent / multi-minute sequential per ~/Dev/lattigo-hierkeys/
// README.md:147-161).
type sessionState struct {
	eval                  *ckks.Evaluator
	orionEval             *orioneval.Evaluator
	rlk                   *rlwe.RelinearizationKey
	glk                   []*rlwe.GaloisKey
	pkTop                 *rlwe.PublicKey
	gksMasterInfer        map[int]*hierkeys.MasterKey
	deriveGksInferSeconds float64
}

// Service is the FHE inference engine. The evaluator for each session is
// built lazily by StoreEvalKeys; OpenSession only reserves the slot.
//
// When `orionModel` is non-nil the Service runs in Orion mode: each
// session builds an `orioneval.Evaluator` from its aggregated rlk+gks and
// `Infer` calls `Forward` on the shared (goroutine-safe) Model. Otherwise
// the Service runs the synthetic `x²` circuit against the session's
// `*ckks.Evaluator`.
type Service struct {
	params     protocol.Params
	orionModel *orioneval.Model
	sessions   map[protocol.SessionID]*sessionState
	mu         sync.Mutex
}

// New constructs a Service that runs the synthetic `x²` circuit.
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

// NewWithOrion constructs a Service that runs the compiled Orion
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
// relinearization key (eval level), the top-level public key, and the
// master Galois-key bundle. The hierarchical derivation runs locally:
// `hierkeys.PubToRot(pkTop)` seeds a shift-0 level-0 MasterKey, then a
// `llkn.Evaluator.NewLevelExpansion` derives the full per-target Galois
// key set for `params.ExtraRotationIndices` (Orion mode) — or the empty
// set for synthetic mode.
//
// Concurrency: derivation runs on `GOMAXPROCS` workers. At LogN=16 this
// is the dominant per-session cost; sequential derivation is multi-minute
// while concurrent is tens of seconds (`~/Dev/lattigo-hierkeys/README.md`
// §15.4). The total wall-clock is recorded into
// `sess.deriveGksInferSeconds` for the bench harness.
//
// `gksMasterInfer` is keyed by the positive **top-level atom** under the
// hierkeys convention; the per-target `Derive(r)` calls receive
// `r = -extraIndex` to land the derived key on `GaloisElement(+k_orion)`,
// honoring the signed-label convention documented on `protocol.Params`
// (and `internal/vservice/orion.go`).
//
// `gksMasterInfer` may be nil (synthetic-x² mode, no rotations needed);
// in that case derivation is skipped and the evaluator is built with an
// empty Galois-key slice — same shape as Phase 1–3 with no rotations.
func (s *Service) StoreEvalKeys(
	sid protocol.SessionID,
	rlk *rlwe.RelinearizationKey,
	pkTop *rlwe.PublicKey,
	gksMasterInfer map[int]*hierkeys.MasterKey,
) error {
	s.mu.Lock()
	sess, ok := s.sessions[sid]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("%w: %q", ErrUnknownSession, sid)
	}
	// Snapshot params under the lock; derivation runs without it so an
	// unrelated session can proceed in parallel.
	params := s.params
	orionModel := s.orionModel
	s.mu.Unlock()

	gks, derive, err := deriveGksInfer(params, pkTop, gksMasterInfer)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	// Re-check the session — it could have been evicted between the
	// derivation pass and the re-acquire (no eviction path exists today
	// but the contract is safer to re-validate than to skip).
	sess, ok = s.sessions[sid]
	if !ok {
		return fmt.Errorf("%w: %q", ErrUnknownSession, sid)
	}
	evk := rlwe.NewMemEvaluationKeySet(rlk, gks...)
	sess.rlk = rlk
	sess.glk = gks
	sess.pkTop = pkTop
	sess.gksMasterInfer = gksMasterInfer
	sess.deriveGksInferSeconds = derive
	if orionModel != nil {
		// Orion path: per-session Orion Evaluator. The model is shared.
		// C3AE does not bootstrap, so btpKeys is nil.
		oe, err := orioneval.NewEvaluatorFromKeySet(params.CKKS, evk, nil)
		if err != nil {
			return fmt.Errorf("vservice: build Orion evaluator: %w", err)
		}
		sess.orionEval = oe
		return nil
	}
	sess.eval = ckks.NewEvaluator(params.CKKS, evk)
	return nil
}

// deriveGksInfer materialises the per-target Galois keys for
// `params.ExtraRotationIndices` via `hierkeys.PubToRot` + `LevelExpansion`,
// returning the resulting slice (in the same order as
// `params.ExtraRotationIndices`) and the wall-clock derivation time in
// seconds. Concurrency: up to `GOMAXPROCS` workers running
// `LevelExpansion.Derive + llkn.Evaluator.FinalizeKey` in parallel.
//
// If `params.ExtraRotationIndices` is empty (synthetic-x² mode) the
// function short-circuits to `(nil, 0, nil)`. If `gksMasterInfer` is nil
// but `ExtraRotationIndices` is non-empty, we error — the caller must
// supply a master bundle whenever the circuit needs rotations.
func deriveGksInfer(
	params protocol.Params,
	pkTop *rlwe.PublicKey,
	gksMasterInfer map[int]*hierkeys.MasterKey,
) ([]*rlwe.GaloisKey, float64, error) {
	targets := params.ExtraRotationIndices
	if len(targets) == 0 {
		return nil, 0, nil
	}
	if pkTop == nil {
		return nil, 0, fmt.Errorf("vservice: pkTop is nil but %d extra rotations need derivation", len(targets))
	}
	if len(gksMasterInfer) == 0 {
		return nil, 0, fmt.Errorf("vservice: gksMasterInfer is empty but %d extra rotations need derivation", len(targets))
	}

	// Map every ExtraRotationIndices entry (`-k_orion`) to the hierkeys
	// derivation target (`-extraIndex = +k_orion`). The derived Galois
	// key carries `GaloisElement(+target)` — exactly what Orion's
	// `RotateNew(ct, +k_orion)` consumes.
	deriveTargets := make([]int, len(targets))
	for i, e := range targets {
		deriveTargets[i] = -e
	}

	llknEval := llkn.NewEvaluator(params.LLKN)
	topParams := params.LLKN.Top()
	evalParams := params.LLKN.Eval()
	shift0, err := hierkeys.PubToRot(evalParams, topParams, pkTop)
	if err != nil {
		return nil, 0, fmt.Errorf("vservice: hierkeys.PubToRot: %w", err)
	}
	exp := llknEval.NewLevelExpansion(0, shift0, gksMasterInfer, deriveTargets)

	gks := make([]*rlwe.GaloisKey, len(deriveTargets))
	derrs := make([]error, len(deriveTargets))

	workers := runtime.GOMAXPROCS(0)
	if workers < 1 {
		workers = 1
	}
	if workers > len(deriveTargets) {
		workers = len(deriveTargets)
	}
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup

	start := time.Now()
	for i, r := range deriveTargets {
		wg.Add(1)
		sem <- struct{}{}
		go func(i, r int) {
			defer wg.Done()
			defer func() { <-sem }()
			mk, err := exp.Derive(r)
			if err != nil {
				derrs[i] = fmt.Errorf("derive target %d: %w", r, err)
				return
			}
			gk, err := llknEval.FinalizeKey(mk)
			if err != nil {
				derrs[i] = fmt.Errorf("finalize target %d: %w", r, err)
				return
			}
			gks[i] = gk
		}(i, r)
	}
	wg.Wait()
	elapsed := time.Since(start).Seconds()

	for i, err := range derrs {
		if err != nil {
			return nil, elapsed, fmt.Errorf("vservice: derive gks_infer (target %d): %w", deriveTargets[i], err)
		}
	}
	return gks, elapsed, nil
}

// DeriveGksInferSeconds returns the wall-clock derivation time recorded by
// the most recent `StoreEvalKeys` call for `sid`. Surfaced for the bench
// harness — the orchestrator/CLI reads it to emit the
// `keygen.galois.service_store` timing under the existing bench step
// registry. Returns `0, false` if the sid is unknown or StoreEvalKeys was
// never called (e.g. synthetic-x² mode short-circuit).
func (s *Service) DeriveGksInferSeconds(sid protocol.SessionID) (float64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[sid]
	if !ok {
		return 0, false
	}
	return sess.deriveGksInferSeconds, true
}
