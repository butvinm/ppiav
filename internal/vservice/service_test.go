package vservice

import (
	"encoding/hex"
	"testing"

	"github.com/butvinm/ppiav/internal/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpenSessionReturnsDistinctSids(t *testing.T) {
	params, err := protocol.Defaults()
	require.NoError(t, err)
	svc := New(params)

	const n = 8
	seen := map[protocol.SessionID]struct{}{}
	for i := 0; i < n; i++ {
		sid, err := svc.OpenSession()
		require.NoError(t, err)
		require.NotEmpty(t, string(sid))

		// sid is hex-encoded and carries ≥128 bits of entropy.
		raw, err := hex.DecodeString(string(sid))
		require.NoError(t, err, "sid %q must be hex-decodable", sid)
		require.GreaterOrEqual(t, len(raw), 16, "sid must carry ≥128 bits of entropy")

		_, dup := seen[sid]
		require.False(t, dup, "consecutive OpenSession calls must return distinct sids")
		seen[sid] = struct{}{}
	}
}

func TestStoreEvalKeysUnknownSid(t *testing.T) {
	params, err := protocol.Defaults()
	require.NoError(t, err)
	svc := New(params)

	err = svc.StoreEvalKeys(protocol.SessionID("does-not-exist"), nil, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown session")
}

func TestParamsReturnsOriginal(t *testing.T) {
	params, err := protocol.Defaults()
	require.NoError(t, err)
	svc := New(params)

	got := svc.Params()
	assert.Equal(t, params.CKKS.LogN(), got.CKKS.LogN())
	assert.Equal(t, params.FloodSigma, got.FloodSigma)
	assert.Equal(t, params.Authenticator.Lambda, got.Authenticator.Lambda)
	assert.Equal(t, params.Authenticator.Epsilon, got.Authenticator.Epsilon)
}
