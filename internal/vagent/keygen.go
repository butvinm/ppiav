package vagent

import (
	"fmt"

	"github.com/butvinm/ppiav/internal/protocol"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// GenPKShare runs the agent side of Stage 2b. It instantiates the
// multiparty PK protocol, draws the first CRP from the session CRS, and
// produces sk_a's share. The CRP and the local share are stashed for
// AggregatePK.
//
// CRS order: this is the FIRST draw from sess.crs — RLK and Galois CRPs
// follow in order. See docs/DESIGN.md §`internal/protocol`.
func (a *Agent) GenPKShare(sid protocol.SessionID) (multiparty.PublicKeyGenShare, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	sess, err := a.sessionLocked(sid)
	if err != nil {
		return multiparty.PublicKeyGenShare{}, err
	}
	sess.pkProto = multiparty.NewPublicKeyGenProtocol(a.params.CKKS)
	sess.pkCRP = sess.pkProto.SampleCRP(sess.crs)
	sess.pkShareLocal = sess.pkProto.AllocateShare()
	sess.pkProto.GenShare(sess.skShare, sess.pkCRP, &sess.pkShareLocal)
	return sess.pkShareLocal, nil
}

// AggregatePK combines the agent share stashed by GenPKShare with
// VClient's matching share, finalises the aggregated public key, and
// builds the per-session encryptor (needed by Auth to encrypt v under
// pkAgg).
func (a *Agent) AggregatePK(sid protocol.SessionID, clientShare multiparty.PublicKeyGenShare) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	sess, err := a.sessionLocked(sid)
	if err != nil {
		return err
	}
	if sess.pkCRP.Value.Q.Coeffs == nil {
		return fmt.Errorf("vagent: AggregatePK called before GenPKShare for sid %q", sid)
	}
	agg := sess.pkProto.AllocateShare()
	sess.pkProto.AggregateShares(sess.pkShareLocal, clientShare, &agg)

	pk := rlwe.NewPublicKey(a.params.CKKS)
	sess.pkProto.GenPublicKey(agg, sess.pkCRP, pk)
	sess.pkAgg = pk
	sess.encryptor = rlwe.NewEncryptor(a.params.CKKS, pk)
	return nil
}

// GenRLKShareRound1 runs the agent side of Stage 2c, round 1. It draws
// the SECOND CRP from the session CRS (single CRP reused for both rounds,
// per Lattigo's protocol shape) and produces sk_a's round-1 share. The
// CRP, the ephemeral sk_a, and the local share are stashed.
func (a *Agent) GenRLKShareRound1(sid protocol.SessionID) (multiparty.RelinearizationKeyGenShare, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	sess, err := a.sessionLocked(sid)
	if err != nil {
		return multiparty.RelinearizationKeyGenShare{}, err
	}
	sess.rlkProto = multiparty.NewRelinearizationKeyGenProtocol(a.params.CKKS)
	sess.rlkCRP = sess.rlkProto.SampleCRP(sess.crs)
	ephSk, share1, _ := sess.rlkProto.AllocateShare()
	sess.rlkEphSk = ephSk
	sess.rlkShare1Loc = share1
	sess.rlkProto.GenShareRoundOne(sess.skShare, sess.rlkCRP, sess.rlkEphSk, &sess.rlkShare1Loc)
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
	_, _, share2 := sess.rlkProto.AllocateShare()
	sess.rlkProto.GenShareRoundTwo(sess.rlkEphSk, sess.skShare, sess.rlkShare1Agg, &share2)
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

// GenGaloisShares produces one share per rotation label in
// `a.params.RotationIndices()` (canonical `[1, lambda)` unioned with any
// inference-circuit extras from the Orion manifest) in ascending order.
// The CRPs are drawn from sess.crs in label order — the THIRD-and-onward
// draws.
//
// Galois-element mapping mirrors VClient: per docs/DESIGN.md
// §`Implementation notes`, Auth uses `eval.RotateNew(ct, -j)` to place
// slot 0 at slot j. The required Galois element per label j is therefore
// `params.GaloisElement(-j)`.
//
// The returned `labels` slice is parallel to `shares`. AggregateGaloisShares
// validates that VClient's parallel labels match.
func (a *Agent) GenGaloisShares(sid protocol.SessionID) ([]multiparty.GaloisKeyGenShare, []int, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	sess, err := a.sessionLocked(sid)
	if err != nil {
		return nil, nil, err
	}
	labels := a.params.RotationIndices()
	if len(labels) == 0 {
		sess.galLabels = nil
		sess.galShares = nil
		sess.galCRPs = nil
		return nil, nil, nil
	}
	gkg := multiparty.NewGaloisKeyGenProtocol(a.params.CKKS)
	shares := make([]multiparty.GaloisKeyGenShare, len(labels))
	crps := make([]multiparty.GaloisKeyGenCRP, len(labels))
	for i, j := range labels {
		crp := gkg.SampleCRP(sess.crs)
		share := gkg.AllocateShare()
		galEl := a.params.CKKS.GaloisElement(-j)
		if err := gkg.GenShare(sess.skShare, galEl, crp, &share); err != nil {
			return nil, nil, fmt.Errorf("vagent: GenShare for rotation label %d: %w", j, err)
		}
		shares[i] = share
		crps[i] = crp
	}
	sess.galProto = gkg
	sess.galLabels = labels
	sess.galShares = shares
	sess.galCRPs = crps
	return shares, labels, nil
}

// AggregateGaloisShares combines VClient's per-rotation shares with the
// agent's stashed shares, derives one `*rlwe.GaloisKey` per label, and
// builds the session evaluator from rlkAgg + the new Galois keys. Returns
// the finalised rlk and Galois key slice so the caller can hand them to
// `vservice.StoreEvalKeys`.
//
// `clientLabels` must be element-wise identical to the stashed agent
// labels — they describe the canonical rotation set both sides agreed on
// via the CRS draw order, and a mismatch indicates a desynchronised
// handshake (hard error rather than silently aggregating the wrong CRP).
func (a *Agent) AggregateGaloisShares(
	sid protocol.SessionID,
	clientShares []multiparty.GaloisKeyGenShare,
	clientLabels []int,
) (*rlwe.RelinearizationKey, []*rlwe.GaloisKey, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	sess, err := a.sessionLocked(sid)
	if err != nil {
		return nil, nil, err
	}
	if sess.rlkAgg == nil {
		return nil, nil, fmt.Errorf("vagent: AggregateGaloisShares called before AggregateRLKRound2 for sid %q", sid)
	}
	if len(clientShares) != len(sess.galShares) {
		return nil, nil, fmt.Errorf("vagent: client galois share count %d != agent count %d", len(clientShares), len(sess.galShares))
	}
	if len(clientLabels) != len(sess.galLabels) {
		return nil, nil, fmt.Errorf("vagent: client galois label count %d != agent count %d", len(clientLabels), len(sess.galLabels))
	}
	for i, j := range sess.galLabels {
		if clientLabels[i] != j {
			return nil, nil, fmt.Errorf("vagent: galois label mismatch at index %d: client=%d agent=%d", i, clientLabels[i], j)
		}
	}

	gkg := sess.galProto
	gks := make([]*rlwe.GaloisKey, len(sess.galLabels))
	for i, j := range sess.galLabels {
		agg := gkg.AllocateShare()
		if err := gkg.AggregateShares(sess.galShares[i], clientShares[i], &agg); err != nil {
			return nil, nil, fmt.Errorf("vagent: aggregate galois share for label %d: %w", j, err)
		}
		gk := rlwe.NewGaloisKey(a.params.CKKS)
		if err := gkg.GenGaloisKey(agg, sess.galCRPs[i], gk); err != nil {
			return nil, nil, fmt.Errorf("vagent: finalise galois key for label %d: %w", j, err)
		}
		gks[i] = gk
	}

	evk := rlwe.NewMemEvaluationKeySet(sess.rlkAgg, gks...)
	sess.eval = ckks.NewEvaluator(a.params.CKKS, evk)
	return sess.rlkAgg, gks, nil
}
