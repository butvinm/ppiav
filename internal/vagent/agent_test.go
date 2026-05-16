package vagent

import (
	"math"
	"testing"

	"github.com/butvinm/ppiav/internal/authenticator"
	"github.com/butvinm/ppiav/internal/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// smallParams builds the unit-test profile: LogN=14 (8192 slots), λ=8 so
// |S|=4 and 7 rotation keys, FloodSigma=2^16. Mirrors vclient's
// smallParams so the two packages can be cross-checked at the same shape.
func smallParams(t *testing.T) protocol.Params {
	t.Helper()
	lit := ckks.ParametersLiteral{
		LogN:            14,
		LogQ:            []int{55, 40, 40},
		LogP:            []int{55, 55},
		LogDefaultScale: 40,
		RingType:        ring.Standard,
	}
	ckksParams, err := ckks.NewParametersFromLiteral(lit)
	require.NoError(t, err)
	llknParams, err := protocol.BuildLLKNParams(ckksParams)
	require.NoError(t, err)
	return protocol.Params{
		CKKS:     ckksParams,
		LLKN:     llknParams,
		LLKNBase: protocol.DefaultLLKNBase,
		Authenticator: authenticator.Config{
			Lambda:  8,
			Epsilon: math.Exp2(20),
		},
		FloodSigma: math.Exp2(16),
	}
}

func TestNewAgentBuildsAuthenticator(t *testing.T) {
	params := smallParams(t)
	a, err := New(params)
	require.NoError(t, err)
	require.NotNil(t, a)
	assert.NotNil(t, a.auth, "Authenticator must be wired in New")
	assert.NotNil(t, a.sessions, "sessions map must be allocated in New")
	assert.Equal(t, params.Authenticator.Lambda, a.Params().Authenticator.Lambda)
}

func TestNewAgentRejectsBadConfig(t *testing.T) {
	params := smallParams(t)
	// Lambda must be > 0 and even — odd is invalid (no |S| = Lambda/2).
	params.Authenticator = authenticator.Config{Lambda: 7, Epsilon: 1}
	_, err := New(params)
	require.Error(t, err, "Authenticator config validation must surface through New")
}

func TestOpenSessionIsIdempotentlyRejectedOnDuplicate(t *testing.T) {
	params := smallParams(t)
	a, err := New(params)
	require.NoError(t, err)
	require.NoError(t, a.OpenSession(protocol.SessionID("session-1")))

	// Re-opening the same sid must fail to avoid silently overwriting
	// active session state.
	require.Error(t, a.OpenSession(protocol.SessionID("session-1")))

	// A different sid still works.
	require.NoError(t, a.OpenSession(protocol.SessionID("session-2")))
}

func TestOpenSessionPopulatesState(t *testing.T) {
	params := smallParams(t)
	a, err := New(params)
	require.NoError(t, err)
	require.NoError(t, a.OpenSession(protocol.SessionID("populated")))

	sess, err := a.session(protocol.SessionID("populated"))
	require.NoError(t, err)
	require.NotNil(t, sess.crs, "CRS must be built")
	require.NotNil(t, sess.skTop, "sk_a (top level) must be minted")
	// authKey has |S| = Lambda/2 and is a *valid* MPD-Auth key.
	assert.Len(t, sess.authKey.S, params.Authenticator.Lambda/2)
	// pkAgg / authchain must remain nil until later stages.
	assert.Nil(t, sess.pkAgg)
	assert.Nil(t, sess.authchain)
}

func TestSessionLookupForUnknownSidErrors(t *testing.T) {
	params := smallParams(t)
	a, err := New(params)
	require.NoError(t, err)
	_, err = a.session(protocol.SessionID("never-opened"))
	require.Error(t, err)
}
