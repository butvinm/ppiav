package vagent

import (
	"fmt"

	hierkeys "github.com/butvinm/lattigo-hierkeys"
	"github.com/butvinm/ppiav/internal/authchain"
	"github.com/butvinm/ppiav/internal/protocol"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
)

// GenPKShare runs the agent side of Stage 2b. It instantiates TWO
// multiparty PK protocols — one at eval level, one at top level — draws
// their CRPs from the session CRS in fixed order (eval first, then top),
// and produces sk_a's shares against each. The CRPs and the local
// shares are stashed for AggregatePK.
//
// Why dual: the eval-level PK powers VAgent's per-session encryptor (Auth
// step 5 encrypts `v` under pkAgg). The top-level PK seeds VService's
// `hierkeys.PubToRot` LevelExpansion — VAgent ships it forward inside
// `InferEvalKeys`.
//
// CRS order: these are the FIRST TWO draws from sess.crs (pk_eval, then
// pk_top); RLK and per-atom Galois CRPs follow. See docs/DESIGN.md
// §`internal/protocol`.
func (a *Agent) GenPKShare(sid protocol.SessionID) (protocol.VAgentPKShare, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	sess, err := a.sessionLocked(sid)
	if err != nil {
		return protocol.VAgentPKShare{}, err
	}
	skEval, err := a.sessionSkEvalLocked(sess)
	if err != nil {
		return protocol.VAgentPKShare{}, err
	}

	// Eval-level PK share.
	sess.pkProtoEval = multiparty.NewPublicKeyGenProtocol(a.params.CKKS)
	sess.pkCRPEval = sess.pkProtoEval.SampleCRP(sess.crs)
	sess.pkShareLocalEval = sess.pkProtoEval.AllocateShare()
	sess.pkProtoEval.GenShare(skEval, sess.pkCRPEval, &sess.pkShareLocalEval)

	// Top-level PK share.
	topParams := a.params.LLKN.Top()
	sess.pkProtoTop = multiparty.NewPublicKeyGenProtocol(topParams)
	sess.pkCRPTop = sess.pkProtoTop.SampleCRP(sess.crs)
	sess.pkShareLocalTop = sess.pkProtoTop.AllocateShare()
	sess.pkProtoTop.GenShare(sess.skTop, sess.pkCRPTop, &sess.pkShareLocalTop)

	return protocol.VAgentPKShare{
		ShareEval: sess.pkShareLocalEval,
		ShareTop:  sess.pkShareLocalTop,
	}, nil
}

// AggregatePK combines the dual agent shares stashed by GenPKShare with
// VClient's matching shares, finalises both the eval-level and top-level
// aggregated public keys, and builds the per-session encryptor (against
// pkEval — Auth's step 5). pkTopAgg is retained on the session for the
// downstream wire path to VService.
func (a *Agent) AggregatePK(sid protocol.SessionID, clientShare protocol.VClientPKShare) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	sess, err := a.sessionLocked(sid)
	if err != nil {
		return err
	}
	if sess.pkCRPEval.Value.Q.Coeffs == nil {
		return fmt.Errorf("vagent: AggregatePK called before GenPKShare for sid %q", sid)
	}

	// Aggregate eval-level shares → pkEval.
	aggEval := sess.pkProtoEval.AllocateShare()
	sess.pkProtoEval.AggregateShares(sess.pkShareLocalEval, clientShare.ShareEval, &aggEval)
	pkEval := rlwe.NewPublicKey(a.params.CKKS)
	sess.pkProtoEval.GenPublicKey(aggEval, sess.pkCRPEval, pkEval)
	sess.pkAgg = pkEval
	sess.encryptor = rlwe.NewEncryptor(a.params.CKKS, pkEval)

	// Aggregate top-level shares → pkTop.
	aggTop := sess.pkProtoTop.AllocateShare()
	sess.pkProtoTop.AggregateShares(sess.pkShareLocalTop, clientShare.ShareTop, &aggTop)
	pkTop := rlwe.NewPublicKey(a.params.LLKN.Top())
	sess.pkProtoTop.GenPublicKey(aggTop, sess.pkCRPTop, pkTop)
	sess.pkTopAgg = pkTop
	return nil
}

// GenRLKShareRound1 runs the agent side of Stage 2c, round 1. It draws
// the next CRP from the session CRS (single CRP reused for both rounds,
// per Lattigo's protocol shape) and produces sk_eval's round-1 share. The
// CRP, the ephemeral sk_a, and the local share are stashed.
//
// The RLK protocol is EVAL-LEVEL — `skEval` (projected from `skTop`) is
// the right secret-key arg; passing `skTop` would mismatch the protocol's
// parameters.
func (a *Agent) GenRLKShareRound1(sid protocol.SessionID) (multiparty.RelinearizationKeyGenShare, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	sess, err := a.sessionLocked(sid)
	if err != nil {
		return multiparty.RelinearizationKeyGenShare{}, err
	}
	skEval, err := a.sessionSkEvalLocked(sess)
	if err != nil {
		return multiparty.RelinearizationKeyGenShare{}, err
	}
	sess.rlkProto = multiparty.NewRelinearizationKeyGenProtocol(a.params.CKKS)
	sess.rlkCRP = sess.rlkProto.SampleCRP(sess.crs)
	ephSk, share1, _ := sess.rlkProto.AllocateShare()
	sess.rlkEphSk = ephSk
	sess.rlkShare1Loc = share1
	sess.rlkProto.GenShareRoundOne(skEval, sess.rlkCRP, sess.rlkEphSk, &sess.rlkShare1Loc)
	return sess.rlkShare1Loc, nil
}

// AggregateRLKRound1 aggregates VClient's round-1 share with the agent's
// stashed share. The result is cached so round 2 has both inputs it needs.
// The RLK CRP drawn in Round 1 is reused in Round 2 (no fresh draw).
func (a *Agent) AggregateRLKRound1(sid protocol.SessionID, clientShare multiparty.RelinearizationKeyGenShare) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	sess, err := a.sessionLocked(sid)
	if err != nil {
		return err
	}
	if sess.rlkEphSk == nil {
		return fmt.Errorf("vagent: AggregateRLKRound1 called before GenRLKShareRound1 for sid %q", sid)
	}
	_, agg, _ := sess.rlkProto.AllocateShare()
	sess.rlkProto.AggregateShares(sess.rlkShare1Loc, clientShare, &agg)
	sess.rlkShare1Agg = agg
	return nil
}

// GenRLKShareRound2 runs the agent side of Stage 2c, round 2. It uses the
// cached round-1 aggregate and the stashed ephemeral sk. The round-2
// share does not cross the wire to VClient (VClient discards rlk
// finalisation per docs/DESIGN.md §`internal/vclient`); the method exists
// for in-process symmetry so AggregateRLKRound2 has both inputs.
func (a *Agent) GenRLKShareRound2(sid protocol.SessionID) (multiparty.RelinearizationKeyGenShare, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	sess, err := a.sessionLocked(sid)
	if err != nil {
		return multiparty.RelinearizationKeyGenShare{}, err
	}
	if sess.rlkEphSk == nil {
		return multiparty.RelinearizationKeyGenShare{}, fmt.Errorf("vagent: GenRLKShareRound2 called before round 1 for sid %q", sid)
	}
	skEval, err := a.sessionSkEvalLocked(sess)
	if err != nil {
		return multiparty.RelinearizationKeyGenShare{}, err
	}
	_, _, share2 := sess.rlkProto.AllocateShare()
	sess.rlkProto.GenShareRoundTwo(sess.rlkEphSk, skEval, sess.rlkShare1Agg, &share2)
	sess.rlkShare2Loc = share2
	return share2, nil
}

// AggregateRLKRound2 combines VClient's round-2 share with the agent's
// stashed round-2 share and finalises rlkAgg. After this the rlk is ready
// to be folded into the session evaluator (built by AggregateGaloisShares).
func (a *Agent) AggregateRLKRound2(sid protocol.SessionID, clientShare multiparty.RelinearizationKeyGenShare) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	sess, err := a.sessionLocked(sid)
	if err != nil {
		return err
	}
	if sess.rlkShare1Agg.Value == nil {
		return fmt.Errorf("vagent: AggregateRLKRound2 called before round 1 aggregate for sid %q", sid)
	}
	_, _, agg := sess.rlkProto.AllocateShare()
	sess.rlkProto.AggregateShares(sess.rlkShare2Loc, clientShare, &agg)
	rlk := rlwe.NewRelinearizationKey(a.params.CKKS)
	sess.rlkProto.GenRelinearizationKey(sess.rlkShare1Agg, agg, rlk)
	sess.rlkAgg = rlk
	return nil
}

// GenAuthAndInferShares produces the two parallel share lists that VAgent
// pairs against VClient's matching `VClientGaloisShares` payload:
//
//   - Auth atoms (eval level, NEGATIVE Galois elements). One share per
//     atom in `a.params.AuthAtoms()` (e.g. `{1,2,4,8,16,32,64}` for λ=128).
//     Secret-key arg is `skEval`. Each call uses
//     `a.params.CKKS.GaloisElement(-atom)`. Aggregated into raw
//     `*rlwe.GaloisKey`s used directly by `authchain` (no hierkeys
//     conversion).
//   - Infer atoms (top level, POSITIVE Galois elements). One share per
//     atom in `a.params.InferAtoms()`. Secret-key arg is `skTop`. Each call
//     uses `a.params.LLKN.Top().GaloisElement(+atom)`. Aggregated and
//     converted via `hierkeys.GaloisKeyToMasterKey` into the master-key
//     bundle shipped to VService.
//
// CRS draw order: auth-atom CRPs first (eval level, ascending), then
// infer-atom CRPs (top level, ascending). VClient draws in lockstep.
//
// The returned label slices are parallel to the share slices. The
// stashed `sess.authLabels` / `sess.inferLabels` are what
// AggregateGaloisShares uses to cross-check VClient's parallel labels.
func (a *Agent) GenAuthAndInferShares(sid protocol.SessionID) (
	authShares []multiparty.GaloisKeyGenShare,
	inferShares []multiparty.GaloisKeyGenShare,
	authLabels []int,
	inferLabels []int,
	err error,
) {
	a.mu.Lock()
	defer a.mu.Unlock()
	sess, err := a.sessionLocked(sid)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	skEval, err := a.sessionSkEvalLocked(sess)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	authLabels = a.params.AuthAtoms()
	authShares = make([]multiparty.GaloisKeyGenShare, len(authLabels))
	authCRPs := make([]multiparty.GaloisKeyGenCRP, len(authLabels))
	if len(authLabels) > 0 {
		gkgEval := multiparty.NewGaloisKeyGenProtocol(a.params.CKKS)
		for i, atom := range authLabels {
			crp := gkgEval.SampleCRP(sess.crs)
			share := gkgEval.AllocateShare()
			galEl := a.params.CKKS.GaloisElement(-atom)
			if err := gkgEval.GenShare(skEval, galEl, crp, &share); err != nil {
				return nil, nil, nil, nil, fmt.Errorf("vagent: GenShare for auth atom %d: %w", atom, err)
			}
			authShares[i] = share
			authCRPs[i] = crp
		}
		sess.galProtoEval = gkgEval
	}
	sess.galCRPsAuth = authCRPs
	sess.galSharesAuth = authShares
	sess.authLabels = authLabels

	inferLabels = a.params.InferAtoms()
	inferShares = make([]multiparty.GaloisKeyGenShare, len(inferLabels))
	inferCRPs := make([]multiparty.GaloisKeyGenCRP, len(inferLabels))
	if len(inferLabels) > 0 {
		topParams := a.params.LLKN.Top()
		gkgTop := multiparty.NewGaloisKeyGenProtocol(topParams)
		for i, atom := range inferLabels {
			crp := gkgTop.SampleCRP(sess.crs)
			share := gkgTop.AllocateShare()
			galEl := topParams.GaloisElement(+atom)
			if err := gkgTop.GenShare(sess.skTop, galEl, crp, &share); err != nil {
				return nil, nil, nil, nil, fmt.Errorf("vagent: GenShare for infer atom %d: %w", atom, err)
			}
			inferShares[i] = share
			inferCRPs[i] = crp
		}
		sess.galProtoTop = gkgTop
	}
	sess.galCRPsInfer = inferCRPs
	sess.galSharesInfer = inferShares
	sess.inferLabels = inferLabels

	return authShares, inferShares, authLabels, inferLabels, nil
}

// AggregateGaloisShares finalises VAgent's Stage-2d handshake. For each
// auth atom it combines the local + client share into a raw
// `*rlwe.GaloisKey` (eval level, negative galEl) and collects them into
// `gksAuth` — directly consumed by `authchain.New` to build the chain
// evaluator. For each infer atom it combines + finalises a top-level
// `*rlwe.GaloisKey` and converts it via `hierkeys.GaloisKeyToMasterKey`
// into a `*hierkeys.MasterKey`, keyed by atom int in `gksMasterInfer`.
//
// Returns `(rlk, pkTop, gksMasterInfer, err)`. `gksAuth` is NOT returned —
// it stays inside the VAgent session (consumed only by `BuildAuthenticatedCt`).
// The orchestrator and HTTP layer carry only the inference-side payload
// onward inside `InferEvalKeys{RLK, PKTop, GKSMasterInfer}`.
//
// Atom labels are NOT carried on the wire — both sides derive them from
// `params.AuthAtoms()` / `params.InferAtoms()` (the canonical sets
// determined by `Authenticator.Lambda` and the LLKN base). The shape
// guard checks share counts against the agent-stashed labels; a desync
// would surface as a count mismatch.
func (a *Agent) AggregateGaloisShares(
	sid protocol.SessionID,
	clientShares protocol.VClientGaloisShares,
) (
	*rlwe.RelinearizationKey,
	*rlwe.PublicKey,
	map[int]*hierkeys.MasterKey,
	error,
) {
	a.mu.Lock()
	defer a.mu.Unlock()
	sess, err := a.sessionLocked(sid)
	if err != nil {
		return nil, nil, nil, err
	}
	if sess.rlkAgg == nil {
		return nil, nil, nil, fmt.Errorf("vagent: AggregateGaloisShares called before AggregateRLKRound2 for sid %q", sid)
	}
	if sess.pkTopAgg == nil {
		return nil, nil, nil, fmt.Errorf("vagent: AggregateGaloisShares called before AggregatePK for sid %q", sid)
	}

	// Validate share-count shape against stashed agent material. Atom
	// labels are not on the wire (derived from params on both sides), so
	// only counts can drift — a count mismatch means the peer drew a
	// different number of CRPs and we cannot safely aggregate.
	if len(clientShares.AuthAtomShares) != len(sess.galSharesAuth) {
		return nil, nil, nil, fmt.Errorf("vagent: client auth share count %d != agent count %d",
			len(clientShares.AuthAtomShares), len(sess.galSharesAuth))
	}
	if len(clientShares.InferAtomShares) != len(sess.galSharesInfer) {
		return nil, nil, nil, fmt.Errorf("vagent: client infer share count %d != agent count %d",
			len(clientShares.InferAtomShares), len(sess.galSharesInfer))
	}

	// Auth atoms — raw eval-level `*rlwe.GaloisKey`s.
	gksAuth := make([]*rlwe.GaloisKey, len(sess.authLabels))
	if len(sess.authLabels) > 0 {
		gkgEval := sess.galProtoEval
		for i, atom := range sess.authLabels {
			agg := gkgEval.AllocateShare()
			if err := gkgEval.AggregateShares(sess.galSharesAuth[i], clientShares.AuthAtomShares[i], &agg); err != nil {
				return nil, nil, nil, fmt.Errorf("vagent: aggregate auth atom %d: %w", atom, err)
			}
			gk := rlwe.NewGaloisKey(a.params.CKKS)
			if err := gkgEval.GenGaloisKey(agg, sess.galCRPsAuth[i], gk); err != nil {
				return nil, nil, nil, fmt.Errorf("vagent: finalise auth atom %d: %w", atom, err)
			}
			gksAuth[i] = gk
		}
	}

	// Infer atoms — top-level `*rlwe.GaloisKey` → `hierkeys.MasterKey`.
	topParams := a.params.LLKN.Top()
	gksMasterInfer := make(map[int]*hierkeys.MasterKey, len(sess.inferLabels))
	if len(sess.inferLabels) > 0 {
		gkgTop := sess.galProtoTop
		for i, atom := range sess.inferLabels {
			agg := gkgTop.AllocateShare()
			if err := gkgTop.AggregateShares(sess.galSharesInfer[i], clientShares.InferAtomShares[i], &agg); err != nil {
				return nil, nil, nil, fmt.Errorf("vagent: aggregate infer atom %d: %w", atom, err)
			}
			gk := rlwe.NewGaloisKey(topParams)
			if err := gkgTop.GenGaloisKey(agg, sess.galCRPsInfer[i], gk); err != nil {
				return nil, nil, nil, fmt.Errorf("vagent: finalise infer atom %d: %w", atom, err)
			}
			mk, err := hierkeys.GaloisKeyToMasterKey(topParams, gk)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("vagent: convert infer atom %d to MasterKey: %w", atom, err)
			}
			gksMasterInfer[atom] = mk
		}
	}

	// Build the chain rotator. `gksAuth` already at eval level and at
	// negative galEls — `authchain.New` wires them into a
	// `rlwe.NewMemEvaluationKeySet` and exposes the chain-rotate surface
	// Auth's step 4 consumes.
	chainEval, err := authchain.New(a.params.CKKS, sess.rlkAgg, gksAuth, sess.authLabels)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("vagent: build authchain evaluator: %w", err)
	}
	sess.gksAuth = gksAuth
	sess.gksMasterInfer = gksMasterInfer
	sess.authchain = chainEval

	return sess.rlkAgg, sess.pkTopAgg, gksMasterInfer, nil
}
