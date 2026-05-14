package vagent

import (
	"testing"

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
// stub holds sk_c and a CRS seeded identically to the Agent's session CRS.
type vclientStub struct {
	params protocol.Params
	skC    *rlwe.SecretKey
	crs    *sampling.KeyedPRNG
}

func newVClientStub(t *testing.T, params protocol.Params, sid protocol.SessionID) *vclientStub {
	t.Helper()
	crs, err := protocol.NewSessionCRS(sid)
	require.NoError(t, err)
	skC := rlwe.NewKeyGenerator(params.CKKS).GenSecretKeyNew()
	return &vclientStub{params: params, skC: skC, crs: crs}
}

// jointSk returns sk_c + sk_a — the secret under which the aggregated pk
// (and any ciphertext produced by it) decrypts.
func jointSk(t *testing.T, params protocol.Params, skC, skA *rlwe.SecretKey) *rlwe.SecretKey {
	t.Helper()
	joint := rlwe.NewSecretKey(params.CKKS)
	params.CKKS.RingQP().Add(skC.Value, joint.Value, joint.Value)
	params.CKKS.RingQP().Add(skA.Value, joint.Value, joint.Value)
	return joint
}

// runFullKeygen drives the full Stage-2 handshake against `a` using
// `stub` as VClient's side. Returns the joint sk, the finalised rlk, and
// the per-rotation Galois keys (parallel to canonical labels) so callers
// can wire them into an evaluator and decrypt arbitrary outputs.
func runFullKeygen(t *testing.T, a *Agent, sid protocol.SessionID, stub *vclientStub) (
	*rlwe.SecretKey,
	*rlwe.RelinearizationKey,
	[]*rlwe.GaloisKey,
) {
	t.Helper()
	params := a.Params()

	// Stage 2b — PK.
	agentPKShare, err := a.GenPKShare(sid)
	require.NoError(t, err)
	pkProto := multiparty.NewPublicKeyGenProtocol(params.CKKS)
	clientCRP := pkProto.SampleCRP(stub.crs)
	clientPKShare := pkProto.AllocateShare()
	pkProto.GenShare(stub.skC, clientCRP, &clientPKShare)
	require.NoError(t, a.AggregatePK(sid, clientPKShare))
	_ = agentPKShare // returned share is also stashed inside the Agent

	// Stage 2c — RLK round 1.
	agentRLK1, err := a.GenRLKShareRound1(sid)
	require.NoError(t, err)
	rlkProto := multiparty.NewRelinearizationKeyGenProtocol(params.CKKS)
	clientRLKCRP := rlkProto.SampleCRP(stub.crs)
	clientEphSk, clientRLK1, clientRLK2 := rlkProto.AllocateShare()
	rlkProto.GenShareRoundOne(stub.skC, clientRLKCRP, clientEphSk, &clientRLK1)
	require.NoError(t, a.AggregateRLKRound1(sid, clientRLK1))

	// Mirror the round-1 aggregate on the stub side (must match Agent's).
	_, clientRLK1Agg, _ := rlkProto.AllocateShare()
	rlkProto.AggregateShares(clientRLK1, agentRLK1, &clientRLK1Agg)

	// Stage 2c — RLK round 2.
	agentRLK2, err := a.GenRLKShareRound2(sid)
	require.NoError(t, err)
	rlkProto.GenShareRoundTwo(clientEphSk, stub.skC, clientRLK1Agg, &clientRLK2)
	require.NoError(t, a.AggregateRLKRound2(sid, clientRLK2))
	_ = agentRLK2 // returned for symmetry; not consumed on the stub side

	// Stage 2d — Galois keys.
	agentGalShares, agentLabels, err := a.GenGaloisShares(sid)
	require.NoError(t, err)
	require.Equal(t, len(protocol.CanonicalRotationIndices(params.Authenticator.Lambda)), len(agentGalShares))

	// Drive VClient's side of GaloisKeyGen in lockstep (CRP draws come out
	// of `stub.crs` in the same canonical order the Agent consumed them).
	clientGalShares := generateClientGaloisShares(t, stub, params, agentLabels)

	rlk, gks, err := a.AggregateGaloisShares(sid, clientGalShares, agentLabels)
	require.NoError(t, err)
	require.Len(t, gks, len(agentLabels))

	return jointSk(t, params, stub.skC, agentState(t, a, sid).skShare), rlk, gks
}

// generateClientGaloisShares draws the stub-side CRPs and shares in
// canonical order. The stub's CRS must be at the third-and-onward draw
// (PK + RLK already consumed) when this is called.
func generateClientGaloisShares(t *testing.T, stub *vclientStub, params protocol.Params, labels []int) []multiparty.GaloisKeyGenShare {
	t.Helper()
	gkg := multiparty.NewGaloisKeyGenProtocol(params.CKKS)
	out := make([]multiparty.GaloisKeyGenShare, len(labels))
	for i, j := range labels {
		crp := gkg.SampleCRP(stub.crs)
		share := gkg.AllocateShare()
		galEl := params.CKKS.GaloisElement(-j)
		require.NoError(t, gkg.GenShare(stub.skC, galEl, crp, &share))
		out[i] = share
	}
	return out
}

// agentState pokes inside the Agent's mutex for tests that need the
// session's skShare. Not part of the public surface.
func agentState(t *testing.T, a *Agent, sid protocol.SessionID) *sessionState {
	t.Helper()
	sess, err := a.session(sid)
	require.NoError(t, err)
	return sess
}

// runHandshakeWithExternalGaloisDriver drives PK + RLK against the Agent
// but lets the caller produce the client-side Galois shares — useful for
// tests that need to peek between Agent stages.
func runHandshakeUpToGalois(t *testing.T, a *Agent, sid protocol.SessionID, stub *vclientStub) {
	t.Helper()
	params := a.Params()

	_, err := a.GenPKShare(sid)
	require.NoError(t, err)
	pkProto := multiparty.NewPublicKeyGenProtocol(params.CKKS)
	clientCRP := pkProto.SampleCRP(stub.crs)
	clientPKShare := pkProto.AllocateShare()
	pkProto.GenShare(stub.skC, clientCRP, &clientPKShare)
	require.NoError(t, a.AggregatePK(sid, clientPKShare))

	agentRLK1, err := a.GenRLKShareRound1(sid)
	require.NoError(t, err)
	rlkProto := multiparty.NewRelinearizationKeyGenProtocol(params.CKKS)
	clientRLKCRP := rlkProto.SampleCRP(stub.crs)
	clientEphSk, clientRLK1, clientRLK2 := rlkProto.AllocateShare()
	rlkProto.GenShareRoundOne(stub.skC, clientRLKCRP, clientEphSk, &clientRLK1)
	require.NoError(t, a.AggregateRLKRound1(sid, clientRLK1))

	_, clientRLK1Agg, _ := rlkProto.AllocateShare()
	rlkProto.AggregateShares(clientRLK1, agentRLK1, &clientRLK1Agg)

	_, err = a.GenRLKShareRound2(sid)
	require.NoError(t, err)
	rlkProto.GenShareRoundTwo(clientEphSk, stub.skC, clientRLK1Agg, &clientRLK2)
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
	pkProto := multiparty.NewPublicKeyGenProtocol(params.CKKS)
	clientCRP := pkProto.SampleCRP(stub.crs)
	clientShare := pkProto.AllocateShare()
	pkProto.GenShare(stub.skC, clientCRP, &clientShare)
	require.NoError(t, a.AggregatePK(sid, clientShare))

	sess := agentState(t, a, sid)
	require.NotNil(t, sess.pkAgg)
	require.NotNil(t, sess.encryptor)

	encoder := ckks.NewEncoder(params.CKKS)
	encryptor := rlwe.NewEncryptor(params.CKKS, sess.pkAgg)
	pt := ckks.NewPlaintext(params.CKKS, params.CKKS.MaxLevel())
	want := make([]float64, params.CKKS.MaxSlots())
	want[0] = 0.42
	require.NoError(t, encoder.Encode(want, pt))
	ct, err := encryptor.EncryptNew(pt)
	require.NoError(t, err)

	joint := jointSk(t, params, stub.skC, sess.skShare)
	dec := rlwe.NewDecryptor(params.CKKS, joint)
	got := make([]float64, params.CKKS.MaxSlots())
	require.NoError(t, encoder.Decode(dec.DecryptNew(ct), got))
	assert.InDelta(t, 0.42, got[0], 1e-3, "aggregate pk must decrypt under sk_c+sk_a")
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

func TestAggregatedGaloisKeysEnableRotation(t *testing.T) {
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

	rotated, err := eval.RotateNew(ct, -1)
	require.NoError(t, err)

	dec := rlwe.NewDecryptor(params.CKKS, joint)
	got := make([]float64, params.CKKS.MaxSlots())
	require.NoError(t, encoder.Decode(dec.DecryptNew(rotated), got))
	assert.InDelta(t, want[0], got[1], 1e-3, "Rot(ct, -1) places slot 0 at slot 1")
	assert.InDelta(t, want[1], got[2], 1e-3, "Rot(ct, -1) places slot 1 at slot 2")
}

func TestAggregateGaloisShareLabelMismatchErrors(t *testing.T) {
	params := smallParams(t)
	a, err := New(params)
	require.NoError(t, err)
	sid := protocol.SessionID("gal-mismatch-sid")
	require.NoError(t, a.OpenSession(sid))
	stub := newVClientStub(t, params, sid)

	runHandshakeUpToGalois(t, a, sid, stub)
	_, agentLabels, err := a.GenGaloisShares(sid)
	require.NoError(t, err)
	clientShares := generateClientGaloisShares(t, stub, params, agentLabels)

	// Tamper: flip the last two labels.
	badLabels := append([]int(nil), agentLabels...)
	badLabels[len(badLabels)-1], badLabels[len(badLabels)-2] = badLabels[len(badLabels)-2], badLabels[len(badLabels)-1]
	_, _, err = a.AggregateGaloisShares(sid, clientShares, badLabels)
	require.Error(t, err)
}

func TestKeygenMethodsRejectUnknownSid(t *testing.T) {
	params := smallParams(t)
	a, err := New(params)
	require.NoError(t, err)
	sid := protocol.SessionID("never-opened")

	_, err = a.GenPKShare(sid)
	require.Error(t, err)
	require.Error(t, a.AggregatePK(sid, multiparty.PublicKeyGenShare{}))
	_, err = a.GenRLKShareRound1(sid)
	require.Error(t, err)
	require.Error(t, a.AggregateRLKRound1(sid, multiparty.RelinearizationKeyGenShare{}))
	_, err = a.GenRLKShareRound2(sid)
	require.Error(t, err)
	require.Error(t, a.AggregateRLKRound2(sid, multiparty.RelinearizationKeyGenShare{}))
	_, _, err = a.GenGaloisShares(sid)
	require.Error(t, err)
}
