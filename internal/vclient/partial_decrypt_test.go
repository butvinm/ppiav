package vclient

import (
	"testing"

	"github.com/butvinm/ppiav/internal/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// TestPartialDecryptJointRoundTrip drives the full §4a joint decryption:
//   1. Run keygen handshake (PK + RLK rounds + Galois) against the VAgent
//      stub so we have an aggregated pk we can encrypt under.
//   2. Encrypt m=0.42 under pk_agg.
//   3. VClient produces its KeySwitchShare (sk_c → 0 with σ=2^16).
//   4. Stub VAgent produces a matching KeySwitchShare (sk_a → 0 with σ=0
//      per docs/DESIGN.md §`Joint decryption + Ver` — VAgent does NOT
//      smudge; eFresh added by GenShare suffices).
//   5. Aggregate, KeySwitch the ciphertext, decrypt under the zero sk.
//   6. Decode and compare against m. Tolerance is loose (1e-2) because
//      σ_flood = 2^16 dominates the intrinsic decryption noise (see
//      docs/DESIGN.md §`Noise magnitude`).
func TestPartialDecryptJointRoundTrip(t *testing.T) {
	params := smallParams(t)
	c, err := New(params, protocol.SessionID("pd-sid"))
	require.NoError(t, err)
	stub := newVAgentStub(t, params, protocol.SessionID("pd-sid"))

	// Run the full handshake — we need pk_agg + the joint sk for the
	// final-decrypt step. We also exercise RLK/Galois even though this
	// test doesn't use them, to confirm the CRS draw order doesn't desync.
	_, _, _ = runFullKeygen(t, c, stub)

	// Encrypt m=0.42 at slot 0, under the aggregated pk.
	encoder := ckks.NewEncoder(params.CKKS)
	encryptor := rlwe.NewEncryptor(params.CKKS, c.pkAgg)
	values := make([]float64, params.CKKS.MaxSlots())
	values[0] = 0.42
	pt := ckks.NewPlaintext(params.CKKS, params.CKKS.MaxLevel())
	require.NoError(t, encoder.Encode(values, pt))
	ct, err := encryptor.EncryptNew(pt)
	require.NoError(t, err)

	// VClient's smudged share.
	clientShare, err := c.PartialDecrypt(ct)
	require.NoError(t, err)

	// VAgent's σ=0 share. Lattigo's NewKeySwitchProtocol requires a
	// non-default DistributionParameters value of type DiscreteGaussian;
	// it always adds eFresh on top regardless of the smudging σ.
	agentProto, err := multiparty.NewKeySwitchProtocol(params.CKKS, ring.DiscreteGaussian{Sigma: 0, Bound: 0})
	require.NoError(t, err)
	zeroSk := rlwe.NewSecretKey(params.CKKS)
	agentShare := agentProto.AllocateShare(ct.Level())
	agentProto.GenShare(stub.skA, zeroSk, ct, &agentShare)

	// Aggregate shares and apply key-switch on the agent side (any
	// `KeySwitchProtocol` instance works for aggregation/KeySwitch — they
	// only differ in noise source for GenShare).
	combined := agentProto.AllocateShare(ct.Level())
	require.NoError(t, agentProto.AggregateShares(clientShare, agentShare, &combined))

	ksOut := rlwe.NewCiphertext(params.CKKS, ct.Degree(), ct.Level())
	agentProto.KeySwitch(ct, combined, ksOut)

	// After KeySwitch from (sk_c, sk_a) to (0, 0), the ciphertext decrypts
	// under sk = 0. Use a Decryptor wired with the zero sk.
	dec := rlwe.NewDecryptor(params.CKKS, zeroSk)
	got := make([]float64, params.CKKS.MaxSlots())
	require.NoError(t, encoder.Decode(dec.DecryptNew(ksOut), got))
	// 1e-2 tolerance: σ_flood=2^16 dominates the intrinsic noise but is
	// still well within the encoder's Δ=2^40 quantisation budget.
	assert.InDelta(t, 0.42, got[0], 1e-2, "joint decryption must recover m within smudging tolerance")
}

func TestPartialDecryptNilCiphertextErrors(t *testing.T) {
	params := smallParams(t)
	c, err := New(params, protocol.SessionID("pd-nil-sid"))
	require.NoError(t, err)
	_, err = c.PartialDecrypt(nil)
	require.Error(t, err)
}
