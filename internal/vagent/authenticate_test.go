package vagent

import (
	"math/big"
	"testing"

	"github.com/butvinm/ppiav/internal/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// TestBuildAuthenticatedCtLayout drives the full keygen handshake, then
// calls BuildAuthenticatedCt against a ciphertext that encrypts m=0.7 at
// slot 0 under the aggregated pk. It decrypts the resulting ct_M under
// the joint sk and asserts the §`Auth` layout:
//
//	i ∈ [0, λ) \ S → m
//	i ∈ S         → v[i] / Δ  (where v[i] is the deterministic PRG output)
func TestBuildAuthenticatedCtLayout(t *testing.T) {
	params := smallParams(t)
	a, err := New(params)
	require.NoError(t, err)
	sid := protocol.SessionID("auth-sid")
	require.NoError(t, a.OpenSession(sid))
	stub := newVClientStub(t, params, sid)

	joint, _, _ := runFullKeygen(t, a, sid, stub)
	sess := agentState(t, a, sid)

	// Encrypt m=0.7 at slot 0 under pkAgg.
	encoder := ckks.NewEncoder(params.CKKS)
	encryptor := rlwe.NewEncryptor(params.CKKS, sess.pkAgg)
	values := make([]float64, params.CKKS.MaxSlots())
	values[0] = 0.7
	pt := ckks.NewPlaintext(params.CKKS, params.CKKS.MaxLevel())
	require.NoError(t, encoder.Encode(values, pt))
	resultCt, err := encryptor.EncryptNew(pt)
	require.NoError(t, err)

	// Capture authKey BEFORE BuildAuthenticatedCt so we can replay the PRG
	// to derive expected v[i] / Δ. Build* itself doesn't drop the key.
	authKey := sess.authKey

	ctM, err := a.BuildAuthenticatedCt(sid, resultCt)
	require.NoError(t, err)
	require.NotNil(t, ctM)

	dec := rlwe.NewDecryptor(params.CKKS, joint)
	got := make([]float64, params.CKKS.MaxSlots())
	require.NoError(t, encoder.Decode(dec.DecryptNew(ctM), got))

	// Replicate the authenticator's PRG to compare against (re-uses the same
	// deterministic AES-CTR + rejection-sampling pipeline).
	q0Half := new(big.Int).Rsh(new(big.Int).SetUint64(params.CKKS.Q()[0]), 1)
	vRaw, err := buildExpectedVRaw(authKey.SeedF, params.Authenticator.Lambda, authKey.S, q0Half)
	require.NoError(t, err)

	delta := params.CKKS.DefaultScale().Float64()
	inS := buildSSet(authKey.S, params.Authenticator.Lambda)
	tol := params.Authenticator.Epsilon / delta // ε in decoded-space units

	for i := 0; i < params.Authenticator.Lambda; i++ {
		if inS[i] {
			assert.InDelta(t, vRaw[i]/delta, got[i], tol, "slot %d (in S) should equal v[%d]/Δ", i, i)
		} else {
			assert.InDelta(t, 0.7, got[i], tol, "slot %d (not in S) should equal m", i)
		}
	}
}

func TestBuildAuthenticatedCtRejectsUnknownSid(t *testing.T) {
	params := smallParams(t)
	a, err := New(params)
	require.NoError(t, err)
	_, err = a.BuildAuthenticatedCt(protocol.SessionID("nope"), &rlwe.Ciphertext{})
	require.Error(t, err)
}

func TestBuildAuthenticatedCtRequiresKeygen(t *testing.T) {
	params := smallParams(t)
	a, err := New(params)
	require.NoError(t, err)
	sid := protocol.SessionID("no-keygen")
	require.NoError(t, a.OpenSession(sid))
	// No keygen handshake → eval is nil → must error.
	_, err = a.BuildAuthenticatedCt(sid, &rlwe.Ciphertext{})
	require.Error(t, err)
}

func TestBuildAuthenticatedCtRejectsNilCt(t *testing.T) {
	params := smallParams(t)
	a, err := New(params)
	require.NoError(t, err)
	sid := protocol.SessionID("nil-ct")
	require.NoError(t, a.OpenSession(sid))
	stub := newVClientStub(t, params, sid)
	_, _, _ = runFullKeygen(t, a, sid, stub)

	_, err = a.BuildAuthenticatedCt(sid, nil)
	require.Error(t, err)
}
