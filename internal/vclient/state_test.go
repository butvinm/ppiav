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

// TestExportStateRoundTripEncrypt runs the full PK handshake on Client A,
// exports state, rebuilds Client B via NewWithState, encrypts the same
// image on both, and verifies both ciphertexts decrypt to the same
// plaintext under the joint sk. Uses LogN=15 because EncryptImage requires
// 12288 slots (smallParams' LogN=14 only has 8192).
//
// CKKS encryption uses fresh RLWE randomness on every call so the two
// ciphertexts are NOT bit-for-bit identical; plaintext equivalence under
// the joint sk is the strongest guarantee.
func TestExportStateRoundTripEncrypt(t *testing.T) {
	requireHeavy(t)
	params := imageParams(t)
	sid := protocol.SessionID("export-encrypt-sid")
	a, err := New(params, sid)
	require.NoError(t, err)
	stub := newVAgentStub(t, params, sid)
	joint, _, _ := runFullKeygen(t, a, stub)

	// Export and rebuild.
	state, err := a.ExportState()
	require.NoError(t, err)
	require.NotNil(t, state)
	assert.Equal(t, sid, state.SID)
	require.NotNil(t, state.SkShare)
	require.NotNil(t, state.PkAgg)

	b, err := NewWithState(params, state)
	require.NoError(t, err)
	require.NotNil(t, b)
	assert.Equal(t, sid, b.SessionID())
	require.NotNil(t, b.encryptor, "PkAgg present → encryptor must be wired")

	input := make([]float64, ImageLen)
	for i := range input {
		input[i] = float64(i%128) / 256.0
	}

	ctA, err := a.EncryptImage(input)
	require.NoError(t, err)
	ctB, err := b.EncryptImage(input)
	require.NoError(t, err)

	dec := rlwe.NewDecryptor(params.CKKS, joint)
	encoder := ckks.NewEncoder(params.CKKS)
	gotA := make([]float64, params.CKKS.MaxSlots())
	gotB := make([]float64, params.CKKS.MaxSlots())
	require.NoError(t, encoder.Decode(dec.DecryptNew(ctA), gotA))
	require.NoError(t, encoder.Decode(dec.DecryptNew(ctB), gotB))

	for i := 0; i < ImageLen; i++ {
		assert.InDelta(t, input[i], gotA[i], 1e-3, "Client A slot %d", i)
		assert.InDelta(t, input[i], gotB[i], 1e-3, "Client B slot %d", i)
	}
}

// TestExportStateRoundTripPartialDecrypt verifies the rebuilt Client can
// produce a KeySwitchShare that aggregates with VAgent's share to recover
// the plaintext. Uses smallParams (LogN=14) since PartialDecrypt is image-
// length-independent; this keeps the test cheap.
//
// PkAgg is left nil on import to confirm partial-decrypt does not require
// the aggregated public key — only sk_c.
func TestExportStateRoundTripPartialDecrypt(t *testing.T) {
	params := smallParams(t)
	sid := protocol.SessionID("export-pd-sid")
	a, err := New(params, sid)
	require.NoError(t, err)
	stub := newVAgentStub(t, params, sid)
	_, _, _ = runFullKeygen(t, a, stub)

	// Encrypt m=0.42 under pk_agg from Client A.
	encoder := ckks.NewEncoder(params.CKKS)
	encryptor := rlwe.NewEncryptor(params.CKKS, a.pkAgg)
	values := make([]float64, params.CKKS.MaxSlots())
	values[0] = 0.42
	pt := ckks.NewPlaintext(params.CKKS, params.CKKS.MaxLevel())
	require.NoError(t, encoder.Encode(values, pt))
	ct, err := encryptor.EncryptNew(pt)
	require.NoError(t, err)

	// Export with PkAgg deliberately nil — partial-decrypt must work without it.
	state, err := a.ExportState()
	require.NoError(t, err)
	state.PkAgg = nil

	b, err := NewWithState(params, state)
	require.NoError(t, err)
	require.Nil(t, b.encryptor, "PkAgg nil → encryptor must remain unwired")

	clientShare, err := b.PartialDecrypt(ct)
	require.NoError(t, err)

	// Aggregate against the stub's matching share + key-switch + decrypt.
	agentProto, err := multiparty.NewKeySwitchProtocol(params.CKKS, ring.DiscreteGaussian{Sigma: 0, Bound: 0})
	require.NoError(t, err)
	zeroSk := rlwe.NewSecretKey(params.CKKS)
	agentShare := agentProto.AllocateShare(ct.Level())
	agentProto.GenShare(stub.skA, zeroSk, ct, &agentShare)

	combined := agentProto.AllocateShare(ct.Level())
	require.NoError(t, agentProto.AggregateShares(clientShare, agentShare, &combined))

	ksOut := rlwe.NewCiphertext(params.CKKS, ct.Degree(), ct.Level())
	agentProto.KeySwitch(ct, combined, ksOut)

	dec := rlwe.NewDecryptor(params.CKKS, zeroSk)
	got := make([]float64, params.CKKS.MaxSlots())
	require.NoError(t, encoder.Decode(dec.DecryptNew(ksOut), got))
	assert.InDelta(t, 0.42, got[0], 1e-2, "rebuilt Client's partial-decrypt must recover m")
}

// NewWithState must reject nil state and nil SkShare so misuse fails
// loudly instead of producing a half-built Client that crashes later.
func TestNewWithStateRejectsInvalidInputs(t *testing.T) {
	params := smallParams(t)
	_, err := NewWithState(params, nil)
	require.Error(t, err)

	_, err = NewWithState(params, &ExportedState{SID: "x"})
	require.Error(t, err, "missing SkShare must fail")
}

// ExportState on a freshly-built Client (no keygen yet) succeeds and
// returns PkAgg=nil. The bench driver relies on this to export sk_c after
// keygen but before AggregatePK if needed; we pin the contract.
func TestExportStateAllowsNilPkAgg(t *testing.T) {
	params := smallParams(t)
	sid := protocol.SessionID("nil-pk-sid")
	c, err := New(params, sid)
	require.NoError(t, err)

	state, err := c.ExportState()
	require.NoError(t, err)
	require.NotNil(t, state.SkShare)
	assert.Nil(t, state.PkAgg, "PkAgg before AggregatePK must be nil")
}
