// Package orchestrator is the in-process glue that wires VClient, VAgent,
// VService, and RService into the §`Protocol` call sequence. The CLI in
// `cmd/ppiav-cli` wraps each Runner method in `bench.Measure`; tests in
// this package drive the same methods directly. There is no business
// logic here — Runner only enforces the stage ordering documented in
// docs/DESIGN.md §`Protocol`.
package orchestrator

import (
	"fmt"

	"github.com/butvinm/ppiav/internal/protocol"
	"github.com/butvinm/ppiav/internal/rservice"
	"github.com/butvinm/ppiav/internal/vagent"
	"github.com/butvinm/ppiav/internal/vclient"
	"github.com/butvinm/ppiav/internal/vservice"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

// Inferrer is the minimal surface Runner needs from the inference engine.
// `vservice.Service` satisfies it; tests inject mocks via NewRunnerWithInferrer.
type Inferrer interface {
	OpenSession() (protocol.SessionID, error)
	StoreEvalKeys(sid protocol.SessionID, rlk *rlwe.RelinearizationKey, gks []*rlwe.GaloisKey) error
	Infer(sid protocol.SessionID, in *rlwe.Ciphertext) (*rlwe.Ciphertext, error)
	Params() protocol.Params
}

// stage tracks the Runner's position in the protocol so calls land in the
// right order. Each method below advances the cursor by one.
type stage int

const (
	stageInit stage = iota
	stageOpened
	stageSetup
	stageInferred
	stageVerified
)

func (s stage) String() string {
	switch s {
	case stageInit:
		return "init"
	case stageOpened:
		return "opened"
	case stageSetup:
		return "setup"
	case stageInferred:
		return "inferred"
	case stageVerified:
		return "verified"
	default:
		return "invalid"
	}
}

// Runner owns the four collaborators and the per-session state. A Runner
// drives a single session at a time — instantiate a fresh Runner per
// session.
type Runner struct {
	params protocol.Params

	vsvc   Inferrer
	vagent *vagent.Agent
	rsvc   *rservice.Service

	// Per-session state. vclient is built per session in Open because
	// vclient.New takes the sid.
	vclient *vclient.Client

	sid    protocol.SessionID
	cursor stage
}

// NewRunner wires the four real collaborators against the supplied params.
// Use NewRunnerWithInferrer when the inference op must be swapped (tests).
func NewRunner(params protocol.Params) (*Runner, error) {
	return NewRunnerWithInferrer(params, vservice.New(params))
}

// NewRunnerWithOrion is the Orion-mode constructor: it loads the compiled
// Orion circuit at `<orionDir>/model.orion`, derives the canonical
// `protocol.Params` from the model's `ClientParams()` (CKKS knobs +
// input level + circuit rotation indices), and wires VClient/VAgent
// against those params so all three agree on the same CKKS profile.
//
// The `baseParams` argument supplies the non-CKKS knobs that the Orion
// manifest doesn't carry — `Authenticator` and `FloodSigma`. Pass
// `protocol.Defaults()` (or a customised version) here. The CKKS,
// `InputLevel`, and `ExtraRotationIndices` fields on `baseParams` are
// ignored; the Orion model is the source of truth.
func NewRunnerWithOrion(baseParams protocol.Params, orionDir string) (*Runner, error) {
	svc, err := vservice.NewWithOrion(baseParams, orionDir)
	if err != nil {
		return nil, fmt.Errorf("orchestrator: build VService with Orion: %w", err)
	}
	// vservice.NewWithOrion overrides CKKS / InputLevel / rotation
	// indices on the params it stashes; pull that bundle back so VAgent
	// and VClient share the same source of truth.
	return NewRunnerWithInferrer(svc.Params(), svc)
}

// NewRunnerWithInferrer is the test-friendly constructor: the caller
// supplies the Inferrer (e.g. a real vservice.Service decorated with a
// negation post-process). VAgent and RService are still the production
// types — there is no mocking surface for them.
func NewRunnerWithInferrer(params protocol.Params, inferrer Inferrer) (*Runner, error) {
	if inferrer == nil {
		return nil, fmt.Errorf("orchestrator: inferrer must not be nil")
	}
	agent, err := vagent.New(params)
	if err != nil {
		return nil, fmt.Errorf("orchestrator: build VAgent: %w", err)
	}
	return &Runner{
		params: params,
		vsvc:   inferrer,
		vagent: agent,
		rsvc:   rservice.New(),
		cursor: stageInit,
	}, nil
}

// RService exposes the underlying resource service so tests (and the CLI's
// access-check path) can call CheckAccess(sid). The Runner itself never
// reads from RService — it only writes verdicts to it.
func (r *Runner) RService() *rservice.Service { return r.rsvc }

// SessionID returns the sid issued by Open. Zero until Open is called.
func (r *Runner) SessionID() protocol.SessionID { return r.sid }

// Open runs Stage 1: VService issues a sid, VAgent registers it, and a
// fresh VClient is built against the sid.
func (r *Runner) Open() (protocol.SessionID, error) {
	if r.cursor != stageInit {
		return "", fmt.Errorf("orchestrator: Open called from stage %s, expected init", r.cursor)
	}
	sid, err := r.vsvc.OpenSession()
	if err != nil {
		return "", fmt.Errorf("orchestrator: VService.OpenSession: %w", err)
	}
	if err := r.vagent.OpenSession(sid); err != nil {
		return "", fmt.Errorf("orchestrator: VAgent.OpenSession: %w", err)
	}
	c, err := vclient.New(r.params, sid)
	if err != nil {
		return "", fmt.Errorf("orchestrator: build VClient: %w", err)
	}
	r.vclient = c
	r.sid = sid
	r.cursor = stageOpened
	return sid, nil
}

// Setup runs Stages 2a–d: params handshake (no-op in-process, both sides
// share the same `protocol.Params` via constructor), PK handshake, two
// RLK rounds, Galois handshake, and finally `vservice.StoreEvalKeys` with
// the aggregated rlk + Galois keys.
//
// CRS draw order is enforced by the order of Gen*/Aggregate* calls: PK →
// RLK (single CRP reused across rounds) → per-rotation Galois in
// ascending label order. Any reordering desynchronises the two sides
// silently, so the call sequence is load-bearing.
func (r *Runner) Setup() error {
	if r.cursor != stageOpened {
		return fmt.Errorf("orchestrator: Setup called from stage %s, expected opened", r.cursor)
	}

	// Stage 2b — PK handshake.
	clientPKShare, err := r.vclient.GenPKShare()
	if err != nil {
		return fmt.Errorf("orchestrator: VClient.GenPKShare: %w", err)
	}
	agentPKShare, err := r.vagent.GenPKShare(r.sid)
	if err != nil {
		return fmt.Errorf("orchestrator: VAgent.GenPKShare: %w", err)
	}
	if err := r.vclient.AggregatePK(agentPKShare); err != nil {
		return fmt.Errorf("orchestrator: VClient.AggregatePK: %w", err)
	}
	if err := r.vagent.AggregatePK(r.sid, clientPKShare); err != nil {
		return fmt.Errorf("orchestrator: VAgent.AggregatePK: %w", err)
	}

	// Stage 2c — RLK round 1.
	clientRLK1, err := r.vclient.GenRLKShareRound1()
	if err != nil {
		return fmt.Errorf("orchestrator: VClient.GenRLKShareRound1: %w", err)
	}
	agentRLK1, err := r.vagent.GenRLKShareRound1(r.sid)
	if err != nil {
		return fmt.Errorf("orchestrator: VAgent.GenRLKShareRound1: %w", err)
	}
	if err := r.vclient.AggregateRLKRound1(agentRLK1); err != nil {
		return fmt.Errorf("orchestrator: VClient.AggregateRLKRound1: %w", err)
	}
	if err := r.vagent.AggregateRLKRound1(r.sid, clientRLK1); err != nil {
		return fmt.Errorf("orchestrator: VAgent.AggregateRLKRound1: %w", err)
	}

	// Stage 2c — RLK round 2.
	clientRLK2, err := r.vclient.GenRLKShareRound2()
	if err != nil {
		return fmt.Errorf("orchestrator: VClient.GenRLKShareRound2: %w", err)
	}
	agentRLK2, err := r.vagent.GenRLKShareRound2(r.sid)
	if err != nil {
		return fmt.Errorf("orchestrator: VAgent.GenRLKShareRound2: %w", err)
	}
	_ = agentRLK2 // VClient does not retain rlk per DESIGN.md §`internal/vclient`.
	if err := r.vagent.AggregateRLKRound2(r.sid, clientRLK2); err != nil {
		return fmt.Errorf("orchestrator: VAgent.AggregateRLKRound2: %w", err)
	}

	// Stage 2d — dual atom-set Galois handshake (Phase 4). VClient emits
	// auth-atom shares (eval level) + infer-atom shares (top level);
	// VAgent finalises them into raw eval-level *rlwe.GaloisKeys + a
	// `map[int]*hierkeys.MasterKey` for the inference side. Task 6 wires
	// the new VAgent signature; for now the vagent call site stays
	// broken on purpose (Task 6 owns it).
	clientAuthShares, clientInferShares, clientAuthLabels, clientInferLabels, err := r.vclient.GenAuthAndInferShares()
	if err != nil {
		return fmt.Errorf("orchestrator: VClient.GenAuthAndInferShares: %w", err)
	}
	_ = clientAuthShares
	_ = clientInferShares
	_ = clientAuthLabels
	_ = clientInferLabels
	if _, _, err := r.vagent.GenGaloisShares(r.sid); err != nil {
		return fmt.Errorf("orchestrator: VAgent.GenGaloisShares: %w", err)
	}
	rlk, gks, err := r.vagent.AggregateGaloisShares(r.sid, clientAuthShares, clientAuthLabels)
	if err != nil {
		return fmt.Errorf("orchestrator: VAgent.AggregateGaloisShares: %w", err)
	}

	if err := r.vsvc.StoreEvalKeys(r.sid, rlk, gks); err != nil {
		return fmt.Errorf("orchestrator: VService.StoreEvalKeys: %w", err)
	}

	r.cursor = stageSetup
	return nil
}

// Infer runs Stage 3: VClient encrypts the preprocessed image, VService
// runs the inference circuit (synthetic mode: `x²`), and the result ciphertext
// is returned for downstream verification.
func (r *Runner) Infer(image []float64) (*rlwe.Ciphertext, error) {
	if r.cursor != stageSetup {
		return nil, fmt.Errorf("orchestrator: Infer called from stage %s, expected setup", r.cursor)
	}
	inputCt, err := r.vclient.EncryptImage(image)
	if err != nil {
		return nil, fmt.Errorf("orchestrator: VClient.EncryptImage: %w", err)
	}
	resultCt, err := r.vsvc.Infer(r.sid, inputCt)
	if err != nil {
		return nil, fmt.Errorf("orchestrator: VService.Infer: %w", err)
	}
	r.cursor = stageInferred
	return resultCt, nil
}

// Verify runs Stage 4: VAgent builds the authenticated ciphertext,
// VClient computes its smudged KeySwitchShare, VAgent combines it with
// its own share and finalises Ver, and the verdict is delivered to
// RService.
func (r *Runner) Verify(resultCt *rlwe.Ciphertext) (protocol.Verdict, error) {
	if r.cursor != stageInferred {
		return protocol.VerdictUnknown, fmt.Errorf("orchestrator: Verify called from stage %s, expected inferred", r.cursor)
	}

	authCt, err := r.vagent.BuildAuthenticatedCt(r.sid, resultCt)
	if err != nil {
		return protocol.VerdictUnknown, fmt.Errorf("orchestrator: VAgent.BuildAuthenticatedCt: %w", err)
	}

	clientShare, err := r.vclient.PartialDecrypt(authCt)
	if err != nil {
		return protocol.VerdictUnknown, fmt.Errorf("orchestrator: VClient.PartialDecrypt: %w", err)
	}

	verdict, err := r.vagent.FinalizeDecryption(r.sid, authCt, clientShare)
	if err != nil {
		return protocol.VerdictUnknown, fmt.Errorf("orchestrator: VAgent.FinalizeDecryption: %w", err)
	}

	if err := r.rsvc.AcceptVerdict(r.sid, verdict); err != nil {
		return protocol.VerdictUnknown, fmt.Errorf("orchestrator: RService.AcceptVerdict: %w", err)
	}

	r.cursor = stageVerified
	return verdict, nil
}
