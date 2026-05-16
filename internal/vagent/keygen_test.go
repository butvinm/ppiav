package vagent

import (
	"testing"

	hierkeys "github.com/butvinm/lattigo-hierkeys"
	"github.com/butvinm/ppiav/internal/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

// vclientStub is the test-side counterparty: it drives VClient's half of
// each multiparty protocol against the real Agent so we can assert the
// Agent's aggregated keys decrypt under the joint sk = sk_c + sk_a. The
// stub holds sk_c at top level (matching the production VClient), a
// lazily-projected sk_c_eval, and a CRS seeded identically to the
// Agent's session CRS.
type vclientStub struct {
	params  protocol.Params
	skCTop  *rlwe.SecretKey
	skCEval *rlwe.SecretKey
	crs     *sampling.KeyedPRNG
}

func newVClientStub(t *testing.T, params protocol.Params, sid protocol.SessionID) *vclientStub {
	t.Helper()
	crs, err := protocol.NewSessionCRS(sid)
	require.NoError(t, err)
	skCTop := rlwe.NewKeyGenerator(params.LLKN.Top()).GenSecretKeyNew()
	skCEval, err := params.ProjectSKToEval(skCTop)
	require.NoError(t, err)
	return &vclientStub{params: params, skCTop: skCTop, skCEval: skCEval, crs: crs}
}

// jointSk returns sk_c_eval + sk_a_eval — the eval-level secret under
// which the aggregated eval-level pk (and any ciphertext produced by it)
// decrypts.
func jointSk(t *testing.T, params protocol.Params, skCEval, skAEval *rlwe.SecretKey) *rlwe.SecretKey {
	t.Helper()
	joint := rlwe.NewSecretKey(params.CKKS)
	params.CKKS.RingQP().Add(skCEval.Value, joint.Value, joint.Value)
	params.CKKS.RingQP().Add(skAEval.Value, joint.Value, joint.Value)
	return joint
}

// runFullKeygen drives the full Stage-2 handshake against `a` using
// `stub` as VClient's side. Returns the joint eval-level sk, the
// finalised rlk, and the per-auth-atom Galois keys (parallel to
// `params.AuthAtoms()`, derived locally by the Agent from gksMaster) so
// callers can wire them into an evaluator and decrypt arbitrary outputs.
//
// CRS draw order followed exactly: pk_eval, pk_top, rlk (single CRP),
// then master atoms (top level, ascending). The stub draws in lockstep.
func runFullKeygen(t *testing.T, a *Agent, sid protocol.SessionID, stub *vclientStub) (
	*rlwe.SecretKey,
	*rlwe.RelinearizationKey,
	[]*rlwe.GaloisKey,
) {
	t.Helper()
	params := a.Params()

	// Stage 2b — dual PK.
	agentPKShare, err := a.GenPKShare(sid)
	require.NoError(t, err)

	pkProtoEval := multiparty.NewPublicKeyGenProtocol(params.CKKS)
	clientCRPEval := pkProtoEval.SampleCRP(stub.crs)
	clientPKShareEval := pkProtoEval.AllocateShare()
	pkProtoEval.GenShare(stub.skCEval, clientCRPEval, &clientPKShareEval)

	pkProtoTop := multiparty.NewPublicKeyGenProtocol(params.LLKN.Top())
	clientCRPTop := pkProtoTop.SampleCRP(stub.crs)
	clientPKShareTop := pkProtoTop.AllocateShare()
	pkProtoTop.GenShare(stub.skCTop, clientCRPTop, &clientPKShareTop)

	require.NoError(t, a.AggregatePK(sid, protocol.VClientPKShare{
		ShareEval: clientPKShareEval,
		ShareTop:  clientPKShareTop,
	}))
	_ = agentPKShare

	// Stage 2c — RLK round 1.
	agentRLK1, err := a.GenRLKShareRound1(sid)
	require.NoError(t, err)
	rlkProto := multiparty.NewRelinearizationKeyGenProtocol(params.CKKS)
	clientRLKCRP := rlkProto.SampleCRP(stub.crs)
	clientEphSk, clientRLK1, clientRLK2 := rlkProto.AllocateShare()
	rlkProto.GenShareRoundOne(stub.skCEval, clientRLKCRP, clientEphSk, &clientRLK1)
	require.NoError(t, a.AggregateRLKRound1(sid, clientRLK1))

	// Mirror the round-1 aggregate on the stub side (must match Agent's).
	_, clientRLK1Agg, _ := rlkProto.AllocateShare()
	rlkProto.AggregateShares(clientRLK1, agentRLK1, &clientRLK1Agg)

	// Stage 2c — RLK round 2.
	agentRLK2, err := a.GenRLKShareRound2(sid)
	require.NoError(t, err)
	rlkProto.GenShareRoundTwo(clientEphSk, stub.skCEval, clientRLK1Agg, &clientRLK2)
	require.NoError(t, a.AggregateRLKRound2(sid, clientRLK2))
	_ = agentRLK2

	// Stage 2d — single master-atom-set Galois handshake.
	_, agentMasterLabels, err := a.GenMasterShares(sid)
	require.NoError(t, err)
	require.Equal(t, params.MasterAtoms(), agentMasterLabels)

	clientMasterShares := generateClientGaloisShares(t, stub, params, agentMasterLabels)
	clientShares := protocol.VClientGaloisShares{
		MasterShares: clientMasterShares,
	}

	rlk, _, _, err := a.AggregateGaloisShares(sid, clientShares)
	require.NoError(t, err)

	sess := agentState(t, a, sid)
	require.NotNil(t, sess.authchain)
	require.Equal(t, len(params.AuthAtoms()), len(sess.gksAuth))

	return jointSk(t, params, stub.skCEval, sess.skEvalCached), rlk, sess.gksAuth
}

// generateClientGaloisShares draws the stub-side master CRPs and shares
// in canonical order. The stub's CRS must be at the master-atom draw
// position when this is called (PK + RLK already consumed).
func generateClientGaloisShares(
	t *testing.T,
	stub *vclientStub,
	params protocol.Params,
	masterLabels []int,
) []multiparty.GaloisKeyGenShare {
	t.Helper()
	shares := make([]multiparty.GaloisKeyGenShare, len(masterLabels))
	if len(masterLabels) == 0 {
		return shares
	}
	topParams := params.LLKN.Top()
	gkgTop := multiparty.NewGaloisKeyGenProtocol(topParams)
	for i, atom := range masterLabels {
		crp := gkgTop.SampleCRP(stub.crs)
		share := gkgTop.AllocateShare()
		galEl := topParams.GaloisElement(+atom)
		require.NoError(t, gkgTop.GenShare(stub.skCTop, galEl, crp, &share))
		shares[i] = share
	}
	return shares
}

// agentState pokes inside the Agent's mutex for tests that need the
// session's skTop/skEvalCached/authchain. Not part of the public surface.
func agentState(t *testing.T, a *Agent, sid protocol.SessionID) *sessionState {
	t.Helper()
	sess, err := a.session(sid)
	require.NoError(t, err)
	// Ensure skEvalCached is populated by triggering the lazy projection
	// (tests that read `sess.skEvalCached` directly need it ready).
	a.mu.Lock()
	_, err = a.sessionSkEvalLocked(sess)
	a.mu.Unlock()
	require.NoError(t, err)
	return sess
}

// runHandshakeUpToGalois drives PK + RLK against the Agent but lets the
// caller produce the client-side Galois shares — useful for tests that
// need to peek between Agent stages.
func runHandshakeUpToGalois(t *testing.T, a *Agent, sid protocol.SessionID, stub *vclientStub) {
	t.Helper()
	params := a.Params()

	_, err := a.GenPKShare(sid)
	require.NoError(t, err)

	pkProtoEval := multiparty.NewPublicKeyGenProtocol(params.CKKS)
	clientCRPEval := pkProtoEval.SampleCRP(stub.crs)
	clientPKShareEval := pkProtoEval.AllocateShare()
	pkProtoEval.GenShare(stub.skCEval, clientCRPEval, &clientPKShareEval)

	pkProtoTop := multiparty.NewPublicKeyGenProtocol(params.LLKN.Top())
	clientCRPTop := pkProtoTop.SampleCRP(stub.crs)
	clientPKShareTop := pkProtoTop.AllocateShare()
	pkProtoTop.GenShare(stub.skCTop, clientCRPTop, &clientPKShareTop)
	require.NoError(t, a.AggregatePK(sid, protocol.VClientPKShare{
		ShareEval: clientPKShareEval,
		ShareTop:  clientPKShareTop,
	}))

	agentRLK1, err := a.GenRLKShareRound1(sid)
	require.NoError(t, err)
	rlkProto := multiparty.NewRelinearizationKeyGenProtocol(params.CKKS)
	clientRLKCRP := rlkProto.SampleCRP(stub.crs)
	clientEphSk, clientRLK1, clientRLK2 := rlkProto.AllocateShare()
	rlkProto.GenShareRoundOne(stub.skCEval, clientRLKCRP, clientEphSk, &clientRLK1)
	require.NoError(t, a.AggregateRLKRound1(sid, clientRLK1))

	_, clientRLK1Agg, _ := rlkProto.AllocateShare()
	rlkProto.AggregateShares(clientRLK1, agentRLK1, &clientRLK1Agg)

	_, err = a.GenRLKShareRound2(sid)
	require.NoError(t, err)
	rlkProto.GenShareRoundTwo(clientEphSk, stub.skCEval, clientRLK1Agg, &clientRLK2)
	require.NoError(t, a.AggregateRLKRound2(sid, clientRLK2))
}

func TestAggregatedPKEncryptsUnderJointSk(t *testing.T) {
	params := smallParams(t)
	a, err := New(params)
	require.NoError(t, err)
	sid := protocol.SessionID("pk-sid")
	require.NoError(t, a.OpenSession(sid))
	stub := newVClientStub(t, params, sid)

	_, err = a.GenPKShare(sid)
	require.NoError(t, err)
	pkProtoEval := multiparty.NewPublicKeyGenProtocol(params.CKKS)
	clientCRPEval := pkProtoEval.SampleCRP(stub.crs)
	clientShareEval := pkProtoEval.AllocateShare()
	pkProtoEval.GenShare(stub.skCEval, clientCRPEval, &clientShareEval)

	pkProtoTop := multiparty.NewPublicKeyGenProtocol(params.LLKN.Top())
	clientCRPTop := pkProtoTop.SampleCRP(stub.crs)
	clientShareTop := pkProtoTop.AllocateShare()
	pkProtoTop.GenShare(stub.skCTop, clientCRPTop, &clientShareTop)

	require.NoError(t, a.AggregatePK(sid, protocol.VClientPKShare{
		ShareEval: clientShareEval,
		ShareTop:  clientShareTop,
	}))

	sess := agentState(t, a, sid)
	require.NotNil(t, sess.pkAgg)
	require.NotNil(t, sess.pkTopAgg)
	require.NotNil(t, sess.encryptor)

	encoder := ckks.NewEncoder(params.CKKS)
	encryptor := rlwe.NewEncryptor(params.CKKS, sess.pkAgg)
	pt := ckks.NewPlaintext(params.CKKS, params.CKKS.MaxLevel())
	want := make([]float64, params.CKKS.MaxSlots())
	want[0] = 0.42
	require.NoError(t, encoder.Encode(want, pt))
	ct, err := encryptor.EncryptNew(pt)
	require.NoError(t, err)

	joint := jointSk(t, params, stub.skCEval, sess.skEvalCached)
	dec := rlwe.NewDecryptor(params.CKKS, joint)
	got := make([]float64, params.CKKS.MaxSlots())
	require.NoError(t, encoder.Decode(dec.DecryptNew(ct), got))
	assert.InDelta(t, 0.42, got[0], 1e-3, "aggregate eval-level pk must decrypt under sk_c_eval+sk_a_eval")
}

func TestAggregatedRLKEnablesRelinMul(t *testing.T) {
	params := smallParams(t)
	a, err := New(params)
	require.NoError(t, err)
	sid := protocol.SessionID("rlk-sid")
	require.NoError(t, a.OpenSession(sid))
	stub := newVClientStub(t, params, sid)

	joint, rlk, _ := runFullKeygen(t, a, sid, stub)
	sess := agentState(t, a, sid)

	encoder := ckks.NewEncoder(params.CKKS)
	encryptor := rlwe.NewEncryptor(params.CKKS, sess.pkAgg)

	want := make([]float64, params.CKKS.MaxSlots())
	want[0] = 0.3
	pt := ckks.NewPlaintext(params.CKKS, params.CKKS.MaxLevel())
	require.NoError(t, encoder.Encode(want, pt))
	ct, err := encryptor.EncryptNew(pt)
	require.NoError(t, err)

	eval := ckks.NewEvaluator(params.CKKS, rlwe.NewMemEvaluationKeySet(rlk))
	squared, err := eval.MulRelinNew(ct, ct)
	require.NoError(t, err)
	require.NoError(t, eval.Rescale(squared, squared))

	dec := rlwe.NewDecryptor(params.CKKS, joint)
	got := make([]float64, params.CKKS.MaxSlots())
	require.NoError(t, encoder.Decode(dec.DecryptNew(squared), got))
	assert.InDelta(t, 0.09, got[0], 1e-3, "rlk-enabled mul of 0.3 should decrypt as 0.09")
}

func TestAggregatedAuthAtomKeysEnableRotation(t *testing.T) {
	params := smallParams(t)
	a, err := New(params)
	require.NoError(t, err)
	sid := protocol.SessionID("gal-sid")
	require.NoError(t, a.OpenSession(sid))
	stub := newVClientStub(t, params, sid)

	joint, rlk, gks := runFullKeygen(t, a, sid, stub)
	sess := agentState(t, a, sid)

	encoder := ckks.NewEncoder(params.CKKS)
	encryptor := rlwe.NewEncryptor(params.CKKS, sess.pkAgg)

	want := make([]float64, params.CKKS.MaxSlots())
	for i := 0; i < params.Authenticator.Lambda; i++ {
		want[i] = 0.1 * float64(i+1)
	}
	pt := ckks.NewPlaintext(params.CKKS, params.CKKS.MaxLevel())
	require.NoError(t, encoder.Encode(want, pt))
	ct, err := encryptor.EncryptNew(pt)
	require.NoError(t, err)

	eval := ckks.NewEvaluator(params.CKKS, rlwe.NewMemEvaluationKeySet(rlk, gks...))

	// Auth atom 1 = GaloisElement(-1). The aggregated key for atom 1
	// directly enables `RotateNew(ct, -1)`.
	rotated, err := eval.RotateNew(ct, -1)
	require.NoError(t, err)

	dec := rlwe.NewDecryptor(params.CKKS, joint)
	got := make([]float64, params.CKKS.MaxSlots())
	require.NoError(t, encoder.Decode(dec.DecryptNew(rotated), got))
	assert.InDelta(t, want[0], got[1], 1e-3, "Rot(ct, -1) places slot 0 at slot 1")
	assert.InDelta(t, want[1], got[2], 1e-3, "Rot(ct, -1) places slot 1 at slot 2")
}

// TestAggregateGaloisShareCountMismatchErrors covers the share-count
// validation path on the agent's AggregateGaloisShares. Atom labels are
// not on the wire (both sides derive them from `params.MasterAtoms()`),
// so the remaining real desync surface is a share-count mismatch on the
// single master set.
func TestAggregateGaloisShareCountMismatchErrors(t *testing.T) {
	params := smallParams(t)
	a, err := New(params)
	require.NoError(t, err)
	sid := protocol.SessionID("gal-mismatch-sid")
	require.NoError(t, a.OpenSession(sid))
	stub := newVClientStub(t, params, sid)

	runHandshakeUpToGalois(t, a, sid, stub)
	_, agentMasterLabels, err := a.GenMasterShares(sid)
	require.NoError(t, err)
	clientMaster := generateClientGaloisShares(t, stub, params, agentMasterLabels)

	// Trim master shares to short-count and expect a count-mismatch error.
	if len(clientMaster) >= 1 {
		short := clientMaster[:len(clientMaster)-1]
		_, _, _, err = a.AggregateGaloisShares(sid,
			protocol.VClientGaloisShares{MasterShares: short})
		require.Error(t, err, "short master share count must error")
	}
}

// TestAggregatedMasterAtomsConvertToMasterKey checks AggregateGaloisShares
// yields a non-empty gksMaster map keyed by ascending positive atoms,
// with each value a valid hierkeys.MasterKey. Also rebuilds the
// authchain evaluator from the locally-derived gksAuth as a regression
// against the design-A derivation path.
func TestAggregatedMasterAtomsConvertToMasterKey(t *testing.T) {
	params := smallParams(t)
	a, err := New(params)
	require.NoError(t, err)
	sid := protocol.SessionID("mk-sid")
	require.NoError(t, a.OpenSession(sid))
	stub := newVClientStub(t, params, sid)

	runHandshakeUpToGalois(t, a, sid, stub)
	_, agentMasterLabels, err := a.GenMasterShares(sid)
	require.NoError(t, err)
	clientMaster := generateClientGaloisShares(t, stub, params, agentMasterLabels)

	_, pkTop, gksMaster, err := a.AggregateGaloisShares(sid,
		protocol.VClientGaloisShares{MasterShares: clientMaster})
	require.NoError(t, err)
	require.NotNil(t, pkTop, "pkTop must be returned")
	require.Len(t, gksMaster, len(agentMasterLabels))
	for _, atom := range agentMasterLabels {
		mk, ok := gksMaster[atom]
		require.True(t, ok, "atom %d missing from gksMaster", atom)
		require.IsType(t, &hierkeys.MasterKey{}, mk)
	}

	// Design-A regression: AggregateGaloisShares must populate gksAuth
	// (locally derived from gksMaster) and wire it into the session's
	// authchain. Confirm the count matches AuthAtoms() and the
	// authchain is non-nil.
	sess := agentState(t, a, sid)
	require.NotNil(t, sess.authchain, "authchain must be wired after AggregateGaloisShares")
	require.Len(t, sess.gksAuth, len(params.AuthAtoms()), "gksAuth must cover every auth atom")
}

func TestKeygenMethodsRejectUnknownSid(t *testing.T) {
	params := smallParams(t)
	a, err := New(params)
	require.NoError(t, err)
	sid := protocol.SessionID("never-opened")

	_, err = a.GenPKShare(sid)
	require.Error(t, err)
	require.Error(t, a.AggregatePK(sid, protocol.VClientPKShare{}))
	_, err = a.GenRLKShareRound1(sid)
	require.Error(t, err)
	require.Error(t, a.AggregateRLKRound1(sid, multiparty.RelinearizationKeyGenShare{}))
	_, err = a.GenRLKShareRound2(sid)
	require.Error(t, err)
	require.Error(t, a.AggregateRLKRound2(sid, multiparty.RelinearizationKeyGenShare{}))
	_, _, err = a.GenMasterShares(sid)
	require.Error(t, err)
}
