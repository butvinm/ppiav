package vclient

import (
	"testing"

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
// thing). The stub mints its own sk_a from a fresh KeyGenerator, drives
// each Lattigo multiparty protocol with the same CRS seed VClient uses,
// and exposes the joint sk (sk_c + sk_a) the tests need to decrypt.
type vagentStub struct {
	params protocol.Params
	skA    *rlwe.SecretKey
	crs    interface {
		Read([]byte) (int, error)
	}
}

func newVAgentStub(t *testing.T, params protocol.Params, sid protocol.SessionID) *vagentStub {
	t.Helper()
	crs, err := protocol.NewSessionCRS(sid)
	require.NoError(t, err)
	skA := rlwe.NewKeyGenerator(params.CKKS).GenSecretKeyNew()
	return &vagentStub{params: params, skA: skA, crs: crs}
}

// jointSk returns sk_c + sk_a — the secret under which the aggregated pk
// (and any ciphertext produced by it) decrypts. Lattigo's multiparty PK
// generation has this exact correctness contract — see
// `~/Dev/.../lattigo/multiparty/multiparty_test.go::testPublicKeyGenProtocol`.
func jointSk(t *testing.T, params protocol.Params, skC, skA *rlwe.SecretKey) *rlwe.SecretKey {
	t.Helper()
	joint := rlwe.NewSecretKey(params.CKKS)
	params.CKKS.RingQP().Add(skC.Value, joint.Value, joint.Value)
	params.CKKS.RingQP().Add(skA.Value, joint.Value, joint.Value)
	return joint
}

// runFullKeygen drives every Gen*/Aggregate* step in the canonical CRS
// order. Returns the joint sk plus the finalised rlk and per-rotation
// Galois keys, so individual tests can plug them straight into
// `rlwe.NewMemEvaluationKeySet`. Used by both keygen_test.go and the
// downstream image_test.go / partial_decrypt_test.go round-trips.
func runFullKeygen(t *testing.T, c *Client, stub *vagentStub) (
	*rlwe.SecretKey,
	*rlwe.RelinearizationKey,
	[]*rlwe.GaloisKey,
) {
	t.Helper()
	params := c.Params()

	// Stage 2b — PK. VClient's share is held inside the Client struct and
	// consumed by AggregatePK; the return value is what would normally go
	// over the wire to VAgent, which we ignore here.
	_, err := c.GenPKShare()
	require.NoError(t, err)
	pkProto := multiparty.NewPublicKeyGenProtocol(params.CKKS)
	agentCRP := pkProto.SampleCRP(stub.crs)
	agentPKShare := pkProto.AllocateShare()
	pkProto.GenShare(stub.skA, agentCRP, &agentPKShare)
	require.NoError(t, c.AggregatePK(agentPKShare))

	// Stage 2c — RLK round 1.
	clientRLK1, err := c.GenRLKShareRound1()
	require.NoError(t, err)
	rlkProto := multiparty.NewRelinearizationKeyGenProtocol(params.CKKS)
	agentRLKCRP := rlkProto.SampleCRP(stub.crs)
	agentEphSk, agentRLK1, agentRLK2 := rlkProto.AllocateShare()
	rlkProto.GenShareRoundOne(stub.skA, agentRLKCRP, agentEphSk, &agentRLK1)
	require.NoError(t, c.AggregateRLKRound1(agentRLK1))

	// Round-1 aggregate as seen on the agent side (must match VClient's).
	_, agentRLK1Agg, _ := rlkProto.AllocateShare()
	rlkProto.AggregateShares(agentRLK1, clientRLK1, &agentRLK1Agg)

	// Stage 2c — RLK round 2.
	clientRLK2, err := c.GenRLKShareRound2()
	require.NoError(t, err)
	rlkProto.GenShareRoundTwo(agentEphSk, stub.skA, agentRLK1Agg, &agentRLK2)
	_, _, rlkRound2Agg := rlkProto.AllocateShare()
	rlkProto.AggregateShares(clientRLK2, agentRLK2, &rlkRound2Agg)
	rlk := rlwe.NewRelinearizationKey(params.CKKS)
	rlkProto.GenRelinearizationKey(agentRLK1Agg, rlkRound2Agg, rlk)

	// Stage 2d — Galois keys.
	clientGalShares, labels, err := c.GenGaloisShares()
	require.NoError(t, err)
	require.Equal(t, len(protocol.CanonicalRotationIndices(params.Authenticator.Lambda)), len(clientGalShares))

	gkg := multiparty.NewGaloisKeyGenProtocol(params.CKKS)
	gks := make([]*rlwe.GaloisKey, len(labels))
	for i, j := range labels {
		crp := gkg.SampleCRP(stub.crs)
		agentShare := gkg.AllocateShare()
		galEl := params.CKKS.GaloisElement(-j)
		require.NoError(t, gkg.GenShare(stub.skA, galEl, crp, &agentShare))

		agg := gkg.AllocateShare()
		require.NoError(t, gkg.AggregateShares(clientGalShares[i], agentShare, &agg))

		gk := rlwe.NewGaloisKey(params.CKKS)
		require.NoError(t, gkg.GenGaloisKey(agg, crp, gk))
		// Sanity: the finalised key must carry the same Galois element
		// VClient used so the eval can find it by GaloisElement(-j) later.
		require.Equal(t, galEl, gk.GaloisElement, "label %d → element mismatch", j)
		gks[i] = gk
	}

	return jointSk(t, params, c.skShare, stub.skA), rlk, gks
}

func TestAggregatedPKEncryptsUnderJointSk(t *testing.T) {
	params := smallParams(t)
	c, err := New(params, protocol.SessionID("pk-sid"))
	require.NoError(t, err)
	stub := newVAgentStub(t, params, protocol.SessionID("pk-sid"))

	// Run PK handshake only — RLK and Galois are tested separately to keep
	// failure attribution clean. The returned share is also stashed inside
	// the Client (so AggregatePK can finish without it being passed back).
	_, err = c.GenPKShare()
	require.NoError(t, err)
	pkProto := multiparty.NewPublicKeyGenProtocol(params.CKKS)
	agentCRP := pkProto.SampleCRP(stub.crs)
	agentShare := pkProto.AllocateShare()
	pkProto.GenShare(stub.skA, agentCRP, &agentShare)
	require.NoError(t, c.AggregatePK(agentShare))
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

	joint := jointSk(t, params, c.skShare, stub.skA)
	dec := rlwe.NewDecryptor(params.CKKS, joint)
	got := make([]float64, params.CKKS.MaxSlots())
	require.NoError(t, encoder.Decode(dec.DecryptNew(ct), got))
	assert.InDelta(t, 0.42, got[0], 1e-3, "aggregate pk must decrypt under sk_c+sk_a")
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

func TestAggregatedGaloisKeysEnableRotation(t *testing.T) {
	params := smallParams(t)
	c, err := New(params, protocol.SessionID("gal-sid"))
	require.NoError(t, err)
	stub := newVAgentStub(t, params, protocol.SessionID("gal-sid"))

	joint, rlk, gks := runFullKeygen(t, c, stub)

	encoder := ckks.NewEncoder(params.CKKS)
	encryptor := rlwe.NewEncryptor(params.CKKS, c.pkAgg)

	// Populate slots [0..λ-1] with distinct values so a rotation by -j (left
	// by -j ≡ right by j) shifts slot 0 to slot j and is detectable.
	want := make([]float64, params.CKKS.MaxSlots())
	for i := 0; i < params.Authenticator.Lambda; i++ {
		want[i] = 0.1 * float64(i+1) // 0.1, 0.2, …
	}
	pt := ckks.NewPlaintext(params.CKKS, params.CKKS.MaxLevel())
	require.NoError(t, encoder.Encode(want, pt))
	ct, err := encryptor.EncryptNew(pt)
	require.NoError(t, err)

	eval := ckks.NewEvaluator(params.CKKS, rlwe.NewMemEvaluationKeySet(rlk, gks...))

	// Lattigo's RotateNew(ct, k) is LEFT-rotation: slot i ← slot (i+k) mod
	// N/2. For k=-1, slot 0 ← slot -1 ≡ slot N/2-1, slot 1 ← slot 0, etc.
	// So slot 1 of the rotated ct should hold want[0] = 0.1.
	rotated, err := eval.RotateNew(ct, -1)
	require.NoError(t, err)

	dec := rlwe.NewDecryptor(params.CKKS, joint)
	got := make([]float64, params.CKKS.MaxSlots())
	require.NoError(t, encoder.Decode(dec.DecryptNew(rotated), got))
	assert.InDelta(t, want[0], got[1], 1e-3, "Rot(ct, -1) places slot 0 at slot 1")
	assert.InDelta(t, want[1], got[2], 1e-3, "Rot(ct, -1) places slot 1 at slot 2")
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
	err = c.AggregatePK(multiparty.PublicKeyGenShare{})
	require.Error(t, err)
}
