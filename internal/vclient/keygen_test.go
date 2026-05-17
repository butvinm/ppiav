package vclient

import (
	"testing"

	hierkeys "github.com/butvinm/lattigo-hierkeys"
	"github.com/butvinm/lattigo-hierkeys/llkn"
	"github.com/butvinm/ppiav/internal/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// vagentStub is a minimal in-test peer that performs VAgent's half of the
// multiparty handshake so the client-side methods have something to talk
// to. It is NOT a substitute for `internal/vagent` — it exists only to
// give VClient's tests a matching counterparty (Task 6 builds the real
// thing). The stub mints its own sk_a at TOP level from a fresh
// KeyGenerator, projects it to eval level for eval-level protocol calls,
// drives each Lattigo multiparty protocol with the same CRS seed VClient
// uses, and exposes both keys plus the joint sk (sk_c_eval + sk_a_eval)
// the tests need to decrypt eval-level ciphertexts.
type vagentStub struct {
	params  protocol.Params
	skATop  *rlwe.SecretKey
	skAEval *rlwe.SecretKey
	crs     interface {
		Read([]byte) (int, error)
	}
}

func newVAgentStub(t *testing.T, params protocol.Params, sid protocol.SessionID) *vagentStub {
	t.Helper()
	crs, err := protocol.NewSessionCRS(sid)
	require.NoError(t, err)
	skATop := rlwe.NewKeyGenerator(params.LLKN.Top()).GenSecretKeyNew()
	skAEval, err := params.ProjectSKToEval(skATop)
	require.NoError(t, err)
	return &vagentStub{params: params, skATop: skATop, skAEval: skAEval, crs: crs}
}

// jointSk returns sk_c_eval + sk_a_eval — the eval-level secret under
// which the aggregated eval-level pk (and any ciphertext produced by it)
// decrypts. Lattigo's multiparty PK generation has this exact correctness
// contract — see
// `~/Dev/.../lattigo/multiparty/multiparty_test.go::testPublicKeyGenProtocol`.
func jointSk(t *testing.T, params protocol.Params, skCEval, skAEval *rlwe.SecretKey) *rlwe.SecretKey {
	t.Helper()
	joint := rlwe.NewSecretKey(params.CKKS)
	params.CKKS.RingQP().Add(skCEval.Value, joint.Value, joint.Value)
	params.CKKS.RingQP().Add(skAEval.Value, joint.Value, joint.Value)
	return joint
}

// runFullKeygen drives every Gen*/Aggregate* step in the canonical CRS
// order. Returns the eval-level joint sk plus the finalised rlk and
// per-auth-atom Galois keys (eval-level keys derived from the joint
// master-atom bundle via hierkeys.LevelExpansion, ready for
// `rlwe.NewMemEvaluationKeySet`). Used by both keygen_test.go and the
// downstream image_test.go / partial_decrypt_test.go round-trips.
//
// CRS order followed exactly: pk_eval, pk_top, rlk (single CRP), then
// master atoms (top level, ascending). The stub draws in lockstep.
func runFullKeygen(t *testing.T, c *Client, stub *vagentStub) (
	*rlwe.SecretKey,
	*rlwe.RelinearizationKey,
	[]*rlwe.GaloisKey,
) {
	t.Helper()
	params := c.Params()

	// Stage 2b — dual PK. VClient's shares (eval+top) are held inside the
	// Client struct and consumed by AggregatePK; the returned struct is
	// what would normally go over the wire to VAgent.
	clientPK, err := c.GenPKShare()
	require.NoError(t, err)
	_ = clientPK // shape-validated below via AggregatePK round-trip

	// Stub's matching shares, drawn from the same CRS in the same order.
	pkProtoEval := multiparty.NewPublicKeyGenProtocol(params.CKKS)
	agentCRPEval := pkProtoEval.SampleCRP(stub.crs)
	agentPKShareEval := pkProtoEval.AllocateShare()
	pkProtoEval.GenShare(stub.skAEval, agentCRPEval, &agentPKShareEval)

	pkProtoTop := multiparty.NewPublicKeyGenProtocol(params.LLKN.Top())
	agentCRPTop := pkProtoTop.SampleCRP(stub.crs)
	agentPKShareTop := pkProtoTop.AllocateShare()
	pkProtoTop.GenShare(stub.skATop, agentCRPTop, &agentPKShareTop)

	// Aggregate the top-level pk so we can seed PubToRot for the
	// auth-atom derivation below. The Client already aggregates the
	// eval-level pk via AggregatePK; we mirror the top-level branch on
	// the stub side because vclient does not retain pkTop.
	aggPKTopShare := pkProtoTop.AllocateShare()
	pkProtoTop.AggregateShares(clientPK.ShareTop, agentPKShareTop, &aggPKTopShare)
	pkTop := rlwe.NewPublicKey(params.LLKN.Top())
	pkProtoTop.GenPublicKey(aggPKTopShare, agentCRPTop, pkTop)

	require.NoError(t, c.AggregatePK(protocol.VAgentPKShare{
		ShareEval: agentPKShareEval,
		ShareTop:  agentPKShareTop,
	}))

	// Stage 2c — RLK round 1.
	clientRLK1, err := c.GenRLKShareRound1()
	require.NoError(t, err)
	rlkProto := multiparty.NewRelinearizationKeyGenProtocol(params.CKKS)
	agentRLKCRP := rlkProto.SampleCRP(stub.crs)
	agentEphSk, agentRLK1, agentRLK2 := rlkProto.AllocateShare()
	rlkProto.GenShareRoundOne(stub.skAEval, agentRLKCRP, agentEphSk, &agentRLK1)
	require.NoError(t, c.AggregateRLKRound1(agentRLK1))

	// Round-1 aggregate as seen on the agent side (must match VClient's).
	_, agentRLK1Agg, _ := rlkProto.AllocateShare()
	rlkProto.AggregateShares(agentRLK1, clientRLK1, &agentRLK1Agg)

	// Stage 2c — RLK round 2.
	clientRLK2, err := c.GenRLKShareRound2()
	require.NoError(t, err)
	rlkProto.GenShareRoundTwo(agentEphSk, stub.skAEval, agentRLK1Agg, &agentRLK2)
	_, _, rlkRound2Agg := rlkProto.AllocateShare()
	rlkProto.AggregateShares(clientRLK2, agentRLK2, &rlkRound2Agg)
	rlk := rlwe.NewRelinearizationKey(params.CKKS)
	rlkProto.GenRelinearizationKey(agentRLK1Agg, rlkRound2Agg, rlk)

	// Stage 2d — single master-atom-set Galois shares.
	masterShares, masterLabels, err := c.GenMasterShares()
	require.NoError(t, err)
	require.Equal(t, params.MasterAtoms(), masterLabels, "client master labels must match MasterAtoms()")
	require.Equal(t, len(masterLabels), len(masterShares))

	// Master-atom finalisation (top level, positive galEl). Convert each
	// finalised top-level GaloisKey into a hierkeys.MasterKey so we can
	// run LevelExpansion to derive the auth-atom keys (eval level,
	// negative galEls) — same derivation VAgent does in production.
	gkgTop := multiparty.NewGaloisKeyGenProtocol(params.LLKN.Top())
	masterKeys := make(map[int]*hierkeys.MasterKey, len(masterLabels))
	for i, a := range masterLabels {
		crp := gkgTop.SampleCRP(stub.crs)
		agentShare := gkgTop.AllocateShare()
		galEl := params.LLKN.Top().GaloisElement(+a)
		require.NoError(t, gkgTop.GenShare(stub.skATop, galEl, crp, &agentShare))

		agg := gkgTop.AllocateShare()
		require.NoError(t, gkgTop.AggregateShares(masterShares[i], agentShare, &agg))

		gk := rlwe.NewGaloisKey(params.LLKN.Top())
		require.NoError(t, gkgTop.GenGaloisKey(agg, crp, gk))
		require.Equal(t, galEl, gk.GaloisElement, "master atom %d → element mismatch", a)
		mk, err := hierkeys.GaloisKeyToMasterKey(params.LLKN.Top(), gk)
		require.NoError(t, err)
		masterKeys[a] = mk
	}

	// Derive auth-atom keys via the same LevelExpansion path VAgent uses.
	authAtoms := params.AuthAtoms()
	authTargets := make([]int, len(authAtoms))
	for i, atom := range authAtoms {
		authTargets[i] = -atom
	}
	llknEval := llkn.NewEvaluator(params.LLKN)
	shift0, err := hierkeys.PubToRot(params.LLKN.Eval(), params.LLKN.Top(), pkTop)
	require.NoError(t, err)
	exp := llknEval.NewLevelExpansion(0, shift0, masterKeys, authTargets)
	gks := make([]*rlwe.GaloisKey, len(authTargets))
	for i, r := range authTargets {
		mk, err := exp.Derive(r)
		require.NoError(t, err)
		gk, err := llknEval.FinalizeKey(mk)
		require.NoError(t, err)
		gks[i] = gk
	}

	// Project sk_c_top → sk_c_eval so the joint key is well-defined at
	// eval level. The Client already cached this internally; rederive
	// here to keep the helper self-contained for callers that don't want
	// to reach into c.skEvalCached.
	skCEval, err := params.ProjectSKToEval(c.skTop)
	require.NoError(t, err)
	return jointSk(t, params, skCEval, stub.skAEval), rlk, gks
}

func TestAggregatedPKEncryptsUnderJointSk(t *testing.T) {
	params := smallParams(t)
	c, err := New(params, protocol.SessionID("pk-sid"))
	require.NoError(t, err)
	stub := newVAgentStub(t, params, protocol.SessionID("pk-sid"))

	// Run dual PK handshake only — RLK and Galois are tested separately
	// to keep failure attribution clean. The returned struct carries
	// both client shares; AggregatePK consumes the matching agent shares
	// from the stub.
	_, err = c.GenPKShare()
	require.NoError(t, err)

	pkProtoEval := multiparty.NewPublicKeyGenProtocol(params.CKKS)
	agentCRPEval := pkProtoEval.SampleCRP(stub.crs)
	agentShareEval := pkProtoEval.AllocateShare()
	pkProtoEval.GenShare(stub.skAEval, agentCRPEval, &agentShareEval)

	pkProtoTop := multiparty.NewPublicKeyGenProtocol(params.LLKN.Top())
	agentCRPTop := pkProtoTop.SampleCRP(stub.crs)
	agentShareTop := pkProtoTop.AllocateShare()
	pkProtoTop.GenShare(stub.skATop, agentCRPTop, &agentShareTop)

	require.NoError(t, c.AggregatePK(protocol.VAgentPKShare{
		ShareEval: agentShareEval,
		ShareTop:  agentShareTop,
	}))
	require.NotNil(t, c.pkAgg)
	require.NotNil(t, c.encryptor)

	encoder := ckks.NewEncoder(params.CKKS)
	encryptor := rlwe.NewEncryptor(params.CKKS, c.pkAgg)
	pt := ckks.NewPlaintext(params.CKKS, params.CKKS.MaxLevel())
	want := make([]float64, params.CKKS.MaxSlots())
	want[0] = 0.42
	require.NoError(t, encoder.Encode(want, pt))
	ct, err := encryptor.EncryptNew(pt)
	require.NoError(t, err)

	skCEval, err := params.ProjectSKToEval(c.skTop)
	require.NoError(t, err)
	joint := jointSk(t, params, skCEval, stub.skAEval)
	dec := rlwe.NewDecryptor(params.CKKS, joint)
	got := make([]float64, params.CKKS.MaxSlots())
	require.NoError(t, encoder.Decode(dec.DecryptNew(ct), got))
	assert.InDelta(t, 0.42, got[0], 1e-3, "aggregate eval-level pk must decrypt under sk_c_eval+sk_a_eval")
}

func TestAggregatedRLKEnablesRelinMul(t *testing.T) {
	params := smallParams(t)
	c, err := New(params, protocol.SessionID("rlk-sid"))
	require.NoError(t, err)
	stub := newVAgentStub(t, params, protocol.SessionID("rlk-sid"))

	joint, rlk, _ := runFullKeygen(t, c, stub)
	encoder := ckks.NewEncoder(params.CKKS)
	encryptor := rlwe.NewEncryptor(params.CKKS, c.pkAgg)

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

func TestAuthAtomKeysEnableRotation(t *testing.T) {
	params := smallParams(t)
	c, err := New(params, protocol.SessionID("gal-sid"))
	require.NoError(t, err)
	stub := newVAgentStub(t, params, protocol.SessionID("gal-sid"))

	joint, rlk, gks := runFullKeygen(t, c, stub)

	encoder := ckks.NewEncoder(params.CKKS)
	encryptor := rlwe.NewEncryptor(params.CKKS, c.pkAgg)

	// Populate enough slots so a rotation by -1 is detectable. AuthAtoms
	// at λ=8 is {1,2,4} so atom=1 yields GaloisElement(-1), which Auth's
	// chain decomposition uses for any -j with bit 0 set (incl. -1).
	want := make([]float64, params.CKKS.MaxSlots())
	for i := 0; i < params.Authenticator.Lambda; i++ {
		want[i] = 0.1 * float64(i+1) // 0.1, 0.2, …
	}
	pt := ckks.NewPlaintext(params.CKKS, params.CKKS.MaxLevel())
	require.NoError(t, encoder.Encode(want, pt))
	ct, err := encryptor.EncryptNew(pt)
	require.NoError(t, err)

	eval := ckks.NewEvaluator(params.CKKS, rlwe.NewMemEvaluationKeySet(rlk, gks...))

	// `Rot(ct, -1)` resolves to GaloisElement(-1) which the gks slice
	// carries directly (auth atom 1). Slot 1 of the rotated ct holds
	// want[0] = 0.1, slot 2 holds want[1] = 0.2.
	rotated, err := eval.RotateNew(ct, -1)
	require.NoError(t, err)

	dec := rlwe.NewDecryptor(params.CKKS, joint)
	got := make([]float64, params.CKKS.MaxSlots())
	require.NoError(t, encoder.Decode(dec.DecryptNew(rotated), got))
	assert.InDelta(t, want[0], got[1], 1e-3, "Rot(ct, -1) via atom-1 key places slot 0 at slot 1")
	assert.InDelta(t, want[1], got[2], 1e-3, "Rot(ct, -1) via atom-1 key places slot 1 at slot 2")
}

// TestGenMasterSharesShape checks the share/label counts emitted by
// VClient match the canonical master atom set from `Params`. This is the
// load-bearing invariant that downstream VAgent aggregation relies on.
func TestGenMasterSharesShape(t *testing.T) {
	params := smallParams(t)
	c, err := New(params, protocol.SessionID("shape-sid"))
	require.NoError(t, err)

	shares, labels, err := c.GenMasterShares()
	require.NoError(t, err)

	expected := params.MasterAtoms()
	require.Equal(t, expected, labels)
	require.Equal(t, len(expected), len(shares))

	// Ascending labels — load-bearing for the wire ordering contract.
	for i := 1; i < len(labels); i++ {
		require.Greater(t, labels[i], labels[i-1], "master labels not ascending at %d", i)
	}
}

// TestMasterAtomShareConvertsToMasterKey verifies the top-level
// master-atom shares VClient emits aggregate cleanly with a stub's
// matching shares and the resulting `*rlwe.GaloisKey` converts to a
// `*hierkeys.MasterKey` via `hierkeys.GaloisKeyToMasterKey`. This is the
// contract VAgent's AggregateGaloisShares depends on.
func TestMasterAtomShareConvertsToMasterKey(t *testing.T) {
	params := smallParams(t)
	sid := protocol.SessionID("master-mk-sid")
	c, err := New(params, sid)
	require.NoError(t, err)
	stub := newVAgentStub(t, params, sid)

	// Walk the canonical draw order on the stub up to the point of
	// master-atom CRPs: pk_eval, pk_top, rlk. Doing this with throwaway
	// draws keeps the stub's CRS aligned with the Client's emissions.
	_ = multiparty.NewPublicKeyGenProtocol(params.CKKS).SampleCRP(stub.crs)
	_ = multiparty.NewPublicKeyGenProtocol(params.LLKN.Top()).SampleCRP(stub.crs)
	_ = multiparty.NewRelinearizationKeyGenProtocol(params.CKKS).SampleCRP(stub.crs)

	// VClient emits the share list (this consumes the master CRPs on
	// VClient's CRS).
	masterShares, masterLabels, err := c.GenMasterShares()
	require.NoError(t, err)
	require.NotEmpty(t, masterLabels)

	// Stub matches the master-atom shares.
	gkgTop := multiparty.NewGaloisKeyGenProtocol(params.LLKN.Top())
	for i, a := range masterLabels {
		crp := gkgTop.SampleCRP(stub.crs)
		agentShare := gkgTop.AllocateShare()
		galEl := params.LLKN.Top().GaloisElement(+a)
		require.NoError(t, gkgTop.GenShare(stub.skATop, galEl, crp, &agentShare))

		agg := gkgTop.AllocateShare()
		require.NoError(t, gkgTop.AggregateShares(masterShares[i], agentShare, &agg))

		gk := rlwe.NewGaloisKey(params.LLKN.Top())
		require.NoError(t, gkgTop.GenGaloisKey(agg, crp, gk))

		mk, err := hierkeys.GaloisKeyToMasterKey(params.LLKN.Top(), gk)
		require.NoError(t, err, "atom %d: GaloisKeyToMasterKey must accept the aggregated top-level key", a)
		require.NotNil(t, mk)
	}
}

func TestRLKRound2BeforeRound1Errors(t *testing.T) {
	params := smallParams(t)
	c, err := New(params, protocol.SessionID("error-sid"))
	require.NoError(t, err)
	_, err = c.GenRLKShareRound2()
	require.Error(t, err, "round 2 without round 1 must error cleanly")
}

func TestAggregatePKBeforeGenShareErrors(t *testing.T) {
	params := smallParams(t)
	c, err := New(params, protocol.SessionID("error-sid-2"))
	require.NoError(t, err)
	err = c.AggregatePK(protocol.VAgentPKShare{})
	require.Error(t, err)
}
