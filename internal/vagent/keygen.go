package vagent

import (
	"fmt"
	"runtime"
	"sync"
	"time"

	hierkeys "github.com/butvinm/lattigo-hierkeys"
	"github.com/butvinm/lattigo-hierkeys/llkn"
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

// GenMasterShares produces the single master-atom share list that VAgent
// pairs against VClient's matching `VClientGaloisShares` payload:
//
//   - One share per atom in `a.params.MasterAtoms()` (top level, POSITIVE
//     Galois elements). Secret-key arg is `skTop`. Each call uses
//     `a.params.LLKN.Top().GaloisElement(+atom)`. Aggregated and converted
//     via `hierkeys.GaloisKeyToMasterKey` into the master-key bundle that
//     powers BOTH the auth-atom derivation (negative direction, local to
//     VAgent) and the inference rotation set (signed labels, local to
//     VService).
//
// CRS draw order: master-atom CRPs at top level, ascending. VClient draws
// in lockstep.
//
// The returned label slice is parallel to the share slice. The stashed
// `sess.masterLabels` is what AggregateGaloisShares uses to cross-check
// VClient's parallel count.
func (a *Agent) GenMasterShares(sid protocol.SessionID) (
	shares []multiparty.GaloisKeyGenShare,
	labels []int,
	err error,
) {
	a.mu.Lock()
	defer a.mu.Unlock()
	sess, err := a.sessionLocked(sid)
	if err != nil {
		return nil, nil, err
	}

	labels = a.params.MasterAtoms()
	shares = make([]multiparty.GaloisKeyGenShare, len(labels))
	crps := make([]multiparty.GaloisKeyGenCRP, len(labels))
	if len(labels) > 0 {
		topParams := a.params.LLKN.Top()
		gkgTop := multiparty.NewGaloisKeyGenProtocol(topParams)
		for i, atom := range labels {
			crp := gkgTop.SampleCRP(sess.crs)
			share := gkgTop.AllocateShare()
			galEl := topParams.GaloisElement(+atom)
			if err := gkgTop.GenShare(sess.skTop, galEl, crp, &share); err != nil {
				return nil, nil, fmt.Errorf("vagent: GenShare for master atom %d: %w", atom, err)
			}
			shares[i] = share
			crps[i] = crp
		}
		sess.galProtoTop = gkgTop
	}
	sess.galCRPsMaster = crps
	sess.galSharesMaster = shares
	sess.masterLabels = labels

	return shares, labels, nil
}

// AggregateGaloisShares finalises VAgent's Stage-2d handshake. For each
// master atom it combines the local + client share into a top-level
// `*rlwe.GaloisKey` and converts it via `hierkeys.GaloisKeyToMasterKey`
// into a `*hierkeys.MasterKey`, keyed by ascending positive atom in
// `gksMaster`. The same bundle is then used to derive the negative
// auth-atom keys locally (via `hierkeys.LevelExpansion`) so VAgent can
// build its authenticator chain evaluator.
//
// Returns `(rlk, pkTop, gksMaster, err)`. The orchestrator and HTTP layer
// carry the full inference payload onward inside
// `InferEvalKeys{RLK, PKTop, GKSMaster}`.
//
// Atom labels are NOT carried on the wire — both sides derive them from
// `params.MasterAtoms()`. The shape guard checks share counts against
// the agent-stashed labels; a desync surfaces as a count mismatch.
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
	sess, err := a.sessionLocked(sid)
	if err != nil {
		a.mu.Unlock()
		return nil, nil, nil, err
	}
	if sess.rlkAgg == nil {
		a.mu.Unlock()
		return nil, nil, nil, fmt.Errorf("vagent: AggregateGaloisShares called before AggregateRLKRound2 for sid %q", sid)
	}
	if sess.pkTopAgg == nil {
		a.mu.Unlock()
		return nil, nil, nil, fmt.Errorf("vagent: AggregateGaloisShares called before AggregatePK for sid %q", sid)
	}

	// Validate share-count shape against stashed agent material. Atom
	// labels are not on the wire (derived from params on both sides), so
	// only counts can drift — a count mismatch means the peer drew a
	// different number of CRPs and we cannot safely aggregate.
	if len(clientShares.MasterShares) != len(sess.galSharesMaster) {
		a.mu.Unlock()
		return nil, nil, nil, fmt.Errorf("vagent: client master share count %d != agent count %d",
			len(clientShares.MasterShares), len(sess.galSharesMaster))
	}

	// Master atoms — top-level `*rlwe.GaloisKey` → `hierkeys.MasterKey`.
	topParams := a.params.LLKN.Top()
	gksMaster := make(map[int]*hierkeys.MasterKey, len(sess.masterLabels))
	if len(sess.masterLabels) > 0 {
		gkgTop := sess.galProtoTop
		for i, atom := range sess.masterLabels {
			agg := gkgTop.AllocateShare()
			if err := gkgTop.AggregateShares(sess.galSharesMaster[i], clientShares.MasterShares[i], &agg); err != nil {
				a.mu.Unlock()
				return nil, nil, nil, fmt.Errorf("vagent: aggregate master atom %d: %w", atom, err)
			}
			gk := rlwe.NewGaloisKey(topParams)
			if err := gkgTop.GenGaloisKey(agg, sess.galCRPsMaster[i], gk); err != nil {
				a.mu.Unlock()
				return nil, nil, nil, fmt.Errorf("vagent: finalise master atom %d: %w", atom, err)
			}
			mk, err := hierkeys.GaloisKeyToMasterKey(topParams, gk)
			if err != nil {
				a.mu.Unlock()
				return nil, nil, nil, fmt.Errorf("vagent: convert master atom %d to MasterKey: %w", atom, err)
			}
			gksMaster[atom] = mk
		}
	}

	rlk := sess.rlkAgg
	pkTop := sess.pkTopAgg
	params := a.params
	a.mu.Unlock()

	// Derive the auth-atom Galois keys locally from gksMaster. Mirrors
	// vservice.deriveGksInfer: PubToRot seeds a level-0 shift-0 MasterKey
	// from pkTop, LevelExpansion factors each target rotation through the
	// master atom set, FinalizeKey collapses to the eval-level key.
	authAtoms := params.AuthAtoms()
	gksAuth, deriveSecs, err := deriveAuthGks(params, pkTop, gksMaster, authAtoms)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("vagent: derive auth Galois keys: %w", err)
	}

	// Build the chain rotator over the locally-derived gksAuth.
	chainEval, err := authchain.New(params.CKKS, rlk, gksAuth, authAtoms)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("vagent: build authchain evaluator: %w", err)
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	// Re-check the session — it could have been evicted while we ran the
	// derivation pass without the mutex.
	sess, err = a.sessionLocked(sid)
	if err != nil {
		return nil, nil, nil, err
	}
	sess.gksAuth = gksAuth
	sess.gksMaster = gksMaster
	sess.authchain = chainEval
	sess.deriveGksAuthSeconds = deriveSecs

	return rlk, pkTop, gksMaster, nil
}

// deriveAuthGks materialises the per-auth-atom negative-direction Galois
// keys from the wire-transported master bundle. Mirrors
// vservice.deriveGksInfer: `hierkeys.PubToRot(pkTop)` seeds a level-0
// shift-0 MasterKey, then a `llkn.Evaluator.NewLevelExpansion` derives
// each `-atom` target concurrently across `GOMAXPROCS` workers. The
// derivation is local to VAgent's process — it does not cross the wire.
//
// Returns the gksAuth slice (parallel to authAtoms in input order, NOT
// the worker-completion order — see the index-keyed assignment below)
// and the wall-clock derivation time in seconds.
func deriveAuthGks(
	params protocol.Params,
	pkTop *rlwe.PublicKey,
	gksMaster map[int]*hierkeys.MasterKey,
	authAtoms []int,
) ([]*rlwe.GaloisKey, float64, error) {
	if len(authAtoms) == 0 {
		return nil, 0, nil
	}
	if pkTop == nil {
		return nil, 0, fmt.Errorf("pkTop is nil but %d auth atoms need derivation", len(authAtoms))
	}
	if len(gksMaster) == 0 {
		return nil, 0, fmt.Errorf("gksMaster is empty but %d auth atoms need derivation", len(authAtoms))
	}
	// LevelExpansion.Derive accepts negative ints; lattigo-hierkeys
	// decomposes via the group structure, not by absolute value.
	authTargets := make([]int, len(authAtoms))
	for i, a := range authAtoms {
		authTargets[i] = -a
	}

	llknEval := llkn.NewEvaluator(params.LLKN)
	topParams := params.LLKN.Top()
	evalParams := params.LLKN.Eval()
	shift0, err := hierkeys.PubToRot(evalParams, topParams, pkTop)
	if err != nil {
		return nil, 0, fmt.Errorf("hierkeys.PubToRot: %w", err)
	}
	exp := llknEval.NewLevelExpansion(0, shift0, gksMaster, authTargets)

	gks := make([]*rlwe.GaloisKey, len(authTargets))
	derrs := make([]error, len(authTargets))

	workers := runtime.GOMAXPROCS(0)
	if workers < 1 {
		workers = 1
	}
	if workers > len(authTargets) {
		workers = len(authTargets)
	}
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup

	start := time.Now()
	for i, r := range authTargets {
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
			return nil, elapsed, fmt.Errorf("derive auth atom %d: %w", authAtoms[i], err)
		}
	}
	return gks, elapsed, nil
}
