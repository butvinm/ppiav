package vagent

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

// runFinalizeWith drives the full §4a path against the Agent for a given
// slot-0 message m: full keygen → encrypt m → BuildAuthenticatedCt →
// VClient-side PartialDecrypt (faked from the stub's sk_c with σ=2^16
// flooding) → FinalizeDecryption. Returns the verdict + any error.
func runFinalizeWith(t *testing.T, m float64) (protocol.Verdict, error) {
	t.Helper()
	params := smallParams(t)
	a, err := New(params)
	require.NoError(t, err)
	sid := protocol.SessionID("fin-sid")
	require.NoError(t, a.OpenSession(sid))
	stub := newVClientStub(t, params, sid)
	_, _, _ = runFullKeygen(t, a, sid, stub)
	sess := agentState(t, a, sid)

	// Encrypt m at slot 0 under pkAgg (acts as the inference result).
	encoder := ckks.NewEncoder(params.CKKS)
	encryptor := rlwe.NewEncryptor(params.CKKS, sess.pkAgg)
	values := make([]float64, params.CKKS.MaxSlots())
	values[0] = m
	pt := ckks.NewPlaintext(params.CKKS, params.CKKS.MaxLevel())
	require.NoError(t, encoder.Encode(values, pt))
	resultCt, err := encryptor.EncryptNew(pt)
	require.NoError(t, err)

	ctM, err := a.BuildAuthenticatedCt(sid, resultCt)
	require.NoError(t, err)

	// VClient's smudged PartialDecrypt — built directly from the stub's
	// sk_c (we don't need internal/vclient here; the Lattigo call is the
	// same).
	clientProto, err := multiparty.NewKeySwitchProtocol(params.CKKS, ring.DiscreteGaussian{
		Sigma: params.FloodSigma,
		Bound: 6 * params.FloodSigma,
	})
	require.NoError(t, err)
	zeroSk := rlwe.NewSecretKey(params.CKKS)
	clientShare := clientProto.AllocateShare(ctM.Level())
	clientProto.GenShare(stub.skC, zeroSk, ctM, &clientShare)

	return a.FinalizeDecryption(sid, ctM, clientShare)
}

func TestFinalizeAcceptsPositiveLogit(t *testing.T) {
	verdict, err := runFinalizeWith(t, 0.7)
	require.NoError(t, err)
	assert.Equal(t, protocol.VerdictAccept, verdict)
}

func TestFinalizeRejectsNegativeLogit(t *testing.T) {
	verdict, err := runFinalizeWith(t, -0.3)
	require.NoError(t, err)
	assert.Equal(t, protocol.VerdictReject, verdict)
}

// m==0 is the strict boundary: FinalizeDecryption accepts only m > 0, so
// exact zero must Reject. Documents the strict-positive convention so a
// future refactor that switches to m >= 0 surfaces in CI.
func TestFinalizeRejectsZeroLogit(t *testing.T) {
	verdict, err := runFinalizeWith(t, 0.0)
	require.NoError(t, err)
	assert.Equal(t, protocol.VerdictReject, verdict)
}

func TestFinalizeRejectsTamperedShare(t *testing.T) {
	// Replay the happy-path setup, but produce VClient's KeySwitchShare
	// against a DIFFERENT sk (i.e., a wrong sk_c). Ver should fail and
	// FinalizeDecryption returns Reject.
	params := smallParams(t)
	a, err := New(params)
	require.NoError(t, err)
	sid := protocol.SessionID("tamper-sid")
	require.NoError(t, a.OpenSession(sid))
	stub := newVClientStub(t, params, sid)
	_, _, _ = runFullKeygen(t, a, sid, stub)
	sess := agentState(t, a, sid)

	encoder := ckks.NewEncoder(params.CKKS)
	encryptor := rlwe.NewEncryptor(params.CKKS, sess.pkAgg)
	values := make([]float64, params.CKKS.MaxSlots())
	values[0] = 0.7
	pt := ckks.NewPlaintext(params.CKKS, params.CKKS.MaxLevel())
	require.NoError(t, encoder.Encode(values, pt))
	resultCt, err := encryptor.EncryptNew(pt)
	require.NoError(t, err)
	ctM, err := a.BuildAuthenticatedCt(sid, resultCt)
	require.NoError(t, err)

	wrongSk := rlwe.NewKeyGenerator(params.CKKS).GenSecretKeyNew()
	clientProto, err := multiparty.NewKeySwitchProtocol(params.CKKS, ring.DiscreteGaussian{
		Sigma: params.FloodSigma,
		Bound: 6 * params.FloodSigma,
	})
	require.NoError(t, err)
	zeroSk := rlwe.NewSecretKey(params.CKKS)
	clientShare := clientProto.AllocateShare(ctM.Level())
	clientProto.GenShare(wrongSk, zeroSk, ctM, &clientShare)

	verdict, err := a.FinalizeDecryption(sid, ctM, clientShare)
	require.NoError(t, err)
	assert.Equal(t, protocol.VerdictReject, verdict, "Ver must reject a share produced under a wrong sk_c")
}

func TestFinalizeDropsSessionOnSuccess(t *testing.T) {
	params := smallParams(t)
	a, err := New(params)
	require.NoError(t, err)
	sid := protocol.SessionID("single-use-sid")
	require.NoError(t, a.OpenSession(sid))
	stub := newVClientStub(t, params, sid)
	_, _, _ = runFullKeygen(t, a, sid, stub)
	sess := agentState(t, a, sid)

	encoder := ckks.NewEncoder(params.CKKS)
	encryptor := rlwe.NewEncryptor(params.CKKS, sess.pkAgg)
	values := make([]float64, params.CKKS.MaxSlots())
	values[0] = 0.5
	pt := ckks.NewPlaintext(params.CKKS, params.CKKS.MaxLevel())
	require.NoError(t, encoder.Encode(values, pt))
	resultCt, err := encryptor.EncryptNew(pt)
	require.NoError(t, err)
	ctM, err := a.BuildAuthenticatedCt(sid, resultCt)
	require.NoError(t, err)

	clientProto, err := multiparty.NewKeySwitchProtocol(params.CKKS, ring.DiscreteGaussian{
		Sigma: params.FloodSigma,
		Bound: 6 * params.FloodSigma,
	})
	require.NoError(t, err)
	zeroSk := rlwe.NewSecretKey(params.CKKS)
	clientShare := clientProto.AllocateShare(ctM.Level())
	clientProto.GenShare(stub.skC, zeroSk, ctM, &clientShare)

	_, err = a.FinalizeDecryption(sid, ctM, clientShare)
	require.NoError(t, err)

	// Single-use authKey: the session must be evicted after FinalizeDecryption.
	_, err = a.session(sid)
	require.Error(t, err, "session must be dropped after FinalizeDecryption")
}

func TestFinalizeRejectsUnknownSid(t *testing.T) {
	params := smallParams(t)
	a, err := New(params)
	require.NoError(t, err)
	ct := &rlwe.Ciphertext{}
	_, err = a.FinalizeDecryption(protocol.SessionID("nope"), ct, multiparty.KeySwitchShare{})
	require.Error(t, err)
}

func TestFinalizeRejectsNilCt(t *testing.T) {
	params := smallParams(t)
	a, err := New(params)
	require.NoError(t, err)
	_, err = a.FinalizeDecryption(protocol.SessionID("nope"), nil, multiparty.KeySwitchShare{})
	require.Error(t, err)
}
