package vclient

import (
	"testing"

	hierkeys "github.com/butvinm/lattigo-hierkeys"
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
// per-auth-atom Galois keys (raw eval-level keys, ready for
// `rlwe.NewMemEvaluationKeySet`). Used by both keygen_test.go and the
// downstream image_test.go / partial_decrypt_test.go round-trips.
//
// CRS order followed exactly: pk_eval, pk_top, rlk (single CRP), then
// auth atoms (eval level, ascending), then infer atoms (top level,
// ascending). The stub draws in lockstep.
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

	// Stage 2d — dual atom-set Galois shares.
	authShares, inferShares, authLabels, inferLabels, err := c.GenAuthAndInferShares()
	require.NoError(t, err)
	require.Equal(t, params.AuthAtoms(), authLabels, "client auth labels must match AuthAtoms()")
	require.Equal(t, params.InferAtoms(), inferLabels, "client infer labels must match InferAtoms()")
	require.Equal(t, len(authLabels), len(authShares))
	require.Equal(t, len(inferLabels), len(inferShares))

	// Auth-atom finalisation (eval level, negative galEl, raw *rlwe.GaloisKey).
	gkgEval := multiparty.NewGaloisKeyGenProtocol(params.CKKS)
	gks := make([]*rlwe.GaloisKey, len(authLabels))
	for i, a := range authLabels {
		crp := gkgEval.SampleCRP(stub.crs)
		agentShare := gkgEval.AllocateShare()
		galEl := params.CKKS.GaloisElement(-a)
		require.NoError(t, gkgEval.GenShare(stub.skAEval, galEl, crp, &agentShare))

		agg := gkgEval.AllocateShare()
		require.NoError(t, gkgEval.AggregateShares(authShares[i], agentShare, &agg))

		gk := rlwe.NewGaloisKey(params.CKKS)
		require.NoError(t, gkgEval.GenGaloisKey(agg, crp, gk))
		require.Equal(t, galEl, gk.GaloisElement, "auth atom %d → element mismatch", a)
		gks[i] = gk
	}

	// Infer-atom finalisation (top level, positive galEl). We finalise
	// them and discard inside this helper — Task 6 wires the master-key
	// bundle into the wire payload; here we only need to prove the stub
	// can aggregate against VClient's emitted top-level shares without
	// CRP misalignment.
	gkgTop := multiparty.NewGaloisKeyGenProtocol(params.LLKN.Top())
	for i, a := range inferLabels {
		crp := gkgTop.SampleCRP(stub.crs)
		agentShare := gkgTop.AllocateShare()
		galEl := params.LLKN.Top().GaloisElement(+a)
		require.NoError(t, gkgTop.GenShare(stub.skATop, galEl, crp, &agentShare))

		agg := gkgTop.AllocateShare()
		require.NoError(t, gkgTop.AggregateShares(inferShares[i], agentShare, &agg))

		gk := rlwe.NewGaloisKey(params.LLKN.Top())
		require.NoError(t, gkgTop.GenGaloisKey(agg, crp, gk))
		require.Equal(t, galEl, gk.GaloisElement, "infer atom %d → element mismatch", a)
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
	require.NotNil(t, c.pkTopAgg)
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

// TestGenAuthAndInferSharesShape checks the share/label counts emitted by
// VClient match the canonical atom sets from `Params`. This is the
// load-bearing invariant that downstream VAgent aggregation relies on.
func TestGenAuthAndInferSharesShape(t *testing.T) {
	params := smallParams(t)
	c, err := New(params, protocol.SessionID("shape-sid"))
	require.NoError(t, err)

	authShares, inferShares, authLabels, inferLabels, err := c.GenAuthAndInferShares()
	require.NoError(t, err)

	expectedAuth := params.AuthAtoms()
	expectedInfer := params.InferAtoms()
	require.Equal(t, expectedAuth, authLabels)
	require.Equal(t, expectedInfer, inferLabels)
	require.Equal(t, len(expectedAuth), len(authShares))
	require.Equal(t, len(expectedInfer), len(inferShares))

	// Ascending labels — load-bearing for the wire ordering contract.
	for i := 1; i < len(authLabels); i++ {
		require.Greater(t, authLabels[i], authLabels[i-1], "auth labels not ascending at %d", i)
	}
	for i := 1; i < len(inferLabels); i++ {
		require.Greater(t, inferLabels[i], inferLabels[i-1], "infer labels not ascending at %d", i)
	}
}

// TestInferAtomShareConvertsToMasterKey verifies the top-level infer-atom
// shares VClient emits aggregate cleanly with a stub's matching shares
// and the resulting `*rlwe.GaloisKey` converts to a `*hierkeys.MasterKey`
// via `hierkeys.GaloisKeyToMasterKey`. This is the contract VAgent's
// AggregateGaloisShares depends on (Task 6).
func TestInferAtomShareConvertsToMasterKey(t *testing.T) {
	params := smallParams(t)
	sid := protocol.SessionID("infer-mk-sid")
	c, err := New(params, sid)
	require.NoError(t, err)
	stub := newVAgentStub(t, params, sid)

	// Walk the canonical draw order on the stub up to the point of
	// infer-atom CRPs: pk_eval, pk_top, rlk, auth-atom CRPs in order.
	// Doing this with throwaway draws keeps the stub's CRS aligned with
	// the Client's emissions.
	_ = multiparty.NewPublicKeyGenProtocol(params.CKKS).SampleCRP(stub.crs)
	_ = multiparty.NewPublicKeyGenProtocol(params.LLKN.Top()).SampleCRP(stub.crs)
	_ = multiparty.NewRelinearizationKeyGenProtocol(params.CKKS).SampleCRP(stub.crs)
	authLabels := params.AuthAtoms()
	gkgEvalDrain := multiparty.NewGaloisKeyGenProtocol(params.CKKS)
	for range authLabels {
		_ = gkgEvalDrain.SampleCRP(stub.crs)
	}

	// VClient emits the full share list (this consumes ALL CRPs on
	// VClient's CRS — pk_eval, pk_top, rlk, auth atoms, infer atoms).
	_, inferShares, _, inferLabels, err := c.GenAuthAndInferShares()
	require.NoError(t, err)
	require.NotEmpty(t, inferLabels)

	// Stub matches just the infer-atom shares.
	gkgTop := multiparty.NewGaloisKeyGenProtocol(params.LLKN.Top())
	for i, a := range inferLabels {
		crp := gkgTop.SampleCRP(stub.crs)
		agentShare := gkgTop.AllocateShare()
		galEl := params.LLKN.Top().GaloisElement(+a)
		require.NoError(t, gkgTop.GenShare(stub.skATop, galEl, crp, &agentShare))

		agg := gkgTop.AllocateShare()
		require.NoError(t, gkgTop.AggregateShares(inferShares[i], agentShare, &agg))

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
