package vagent

import (
	"math/big"
	"testing"

	"github.com/butvinm/ppiav/internal/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// TestExportStateRoundTrip drives the full keygen handshake on Agent A,
// exports the per-session state, rebuilds Agent B via NewWithState, then
// calls BuildAuthenticatedCt on both and verifies that the decoded slot
// vectors (under the joint sk) match up to encryption-noise tolerance.
//
// Auth's RLWE encryption step uses fresh randomness on every call, so the
// two ct_M's are NOT bit-for-bit identical — but they decrypt to the same
// plaintext layout (§`Auth`: m at non-S slots, v[i]/Δ at S slots, with the
// SAME v[i] because MacKey.SeedF is preserved across export). That's the
// strongest equivalence available without re-seeding Lattigo's RNG.
func TestExportStateRoundTrip(t *testing.T) {
	params := smallParams(t)
	a, err := New(params)
	require.NoError(t, err)
	sid := protocol.SessionID("export-sid")
	require.NoError(t, a.OpenSession(sid))
	stub := newVClientStub(t, params, sid)

	// Drive PK + RLK + Galois on Agent A. The returned (joint, rlk,
	// gksAuth) are the inputs we'll pass through ExportedState to Agent B.
	joint, _, gks := runFullKeygen(t, a, sid, stub)

	// Capture authKey before export so we can replay the deterministic v[i].
	sessA := agentState(t, a, sid)
	authKey := sessA.authKey

	// Encrypt m=0.7 at slot 0 under pkAgg.
	encoder := ckks.NewEncoder(params.CKKS)
	encryptor := rlwe.NewEncryptor(params.CKKS, sessA.pkAgg)
	values := make([]float64, params.CKKS.MaxSlots())
	values[0] = 0.7
	pt := ckks.NewPlaintext(params.CKKS, params.CKKS.MaxLevel())
	require.NoError(t, encoder.Encode(values, pt))
	resultCtA, err := encryptor.EncryptNew(pt)
	require.NoError(t, err)
	// Re-encrypt the same plaintext for Agent B (fresh ciphertext at the
	// same level, identical underlying message).
	resultCtB, err := encryptor.EncryptNew(pt)
	require.NoError(t, err)

	// Run Auth on Agent A.
	ctMA, err := a.BuildAuthenticatedCt(sid, resultCtA)
	require.NoError(t, err)
	require.NotNil(t, ctMA)

	// Export and rebuild on Agent B. ExportState populates GksMaster from
	// AggregateGaloisShares; NewWithState rederives gksAuth from it via
	// hierkeys.LevelExpansion. The test does not have to thread `gks`.
	state, err := a.ExportState(sid)
	require.NoError(t, err)
	require.NotNil(t, state)
	assert.Equal(t, sid, state.SID)
	require.NotNil(t, state.SkTop)
	require.NotNil(t, state.PkAgg)
	require.NotNil(t, state.PkTop)
	require.NotNil(t, state.Rlk)
	require.NotEmpty(t, state.GksMaster, "ExportState must populate GksMaster from AggregateGaloisShares")
	_ = gks // gksAuth remains available on the live session but is rederived on the restored Agent.

	b, err := NewWithState(params, state)
	require.NoError(t, err)
	require.NotNil(t, b)

	ctMB, err := b.BuildAuthenticatedCt(sid, resultCtB)
	require.NoError(t, err)
	require.NotNil(t, ctMB)

	// Decrypt both ct_M's under the joint sk and check the §`Auth` layout
	// matches between the two Agents — non-S slots both equal m, S slots
	// both equal v[i]/Δ derived from the SAME SeedF.
	dec := rlwe.NewDecryptor(params.CKKS, joint)
	gotA := make([]float64, params.CKKS.MaxSlots())
	require.NoError(t, encoder.Decode(dec.DecryptNew(ctMA), gotA))
	gotB := make([]float64, params.CKKS.MaxSlots())
	require.NoError(t, encoder.Decode(dec.DecryptNew(ctMB), gotB))

	q0Half := new(big.Int).Rsh(new(big.Int).SetUint64(params.CKKS.Q()[0]), 1)
	vRaw, err := buildExpectedVRaw(authKey.SeedF, params.Authenticator.Lambda, authKey.S, q0Half)
	require.NoError(t, err)
	delta := params.CKKS.DefaultScale().Float64()
	inS := buildSSet(authKey.S, params.Authenticator.Lambda)
	tol := params.Authenticator.Epsilon / delta

	for i := 0; i < params.Authenticator.Lambda; i++ {
		if inS[i] {
			expected := vRaw[i] / delta
			assert.InDelta(t, expected, gotA[i], tol, "Agent A slot %d (in S): want v[%d]/Δ", i, i)
			assert.InDelta(t, expected, gotB[i], tol, "Agent B slot %d (in S): want v[%d]/Δ", i, i)
		} else {
			assert.InDelta(t, 0.7, gotA[i], tol, "Agent A slot %d (non-S): want m", i)
			assert.InDelta(t, 0.7, gotB[i], tol, "Agent B slot %d (non-S): want m", i)
		}
	}
}

// ExportState must reject unknown SIDs cleanly so the bench driver can
// surface the error instead of crashing on a nil deref.
func TestExportStateRejectsUnknownSid(t *testing.T) {
	params := smallParams(t)
	a, err := New(params)
	require.NoError(t, err)
	_, err = a.ExportState(protocol.SessionID("nope"))
	require.Error(t, err)
}

// ExportState must reject a session whose keygen has not progressed past
// AggregatePK / AggregateRLKRound2 — exporting a partial session would
// produce a NewWithState session that cannot do BuildAuthenticatedCt.
func TestExportStateRequiresCompletedKeygen(t *testing.T) {
	params := smallParams(t)
	a, err := New(params)
	require.NoError(t, err)
	sid := protocol.SessionID("partial-sid")
	require.NoError(t, a.OpenSession(sid))
	// Only OpenSession — no PK/RLK/Galois yet.
	_, err = a.ExportState(sid)
	require.Error(t, err)
}

// NewWithState must reject nil state and nil SkTop so misuse fails
// loudly instead of producing a half-built Agent that crashes later.
func TestNewWithStateRejectsInvalidInputs(t *testing.T) {
	params := smallParams(t)
	_, err := NewWithState(params, nil)
	require.Error(t, err)

	_, err = NewWithState(params, &ExportedState{SID: "x"})
	require.Error(t, err, "missing SkTop must fail")
}

// A second Agent built via NewWithState must also pass FinalizeDecryption
// against the original session — i.e., the export carries enough state for
// the full mac → joint-decrypt → Ver path, not just BuildAuthenticatedCt.
// This pins the contract the bench `finalize` subcommand relies on.
func TestNewWithStateSupportsFinalize(t *testing.T) {
	params := smallParams(t)
	a, err := New(params)
	require.NoError(t, err)
	sid := protocol.SessionID("finalize-sid")
	require.NoError(t, a.OpenSession(sid))
	stub := newVClientStub(t, params, sid)
	_, _, _ = runFullKeygen(t, a, sid, stub)

	state, err := a.ExportState(sid)
	require.NoError(t, err)
	require.NotEmpty(t, state.GksMaster, "ExportState must populate GksMaster")

	b, err := NewWithState(params, state)
	require.NoError(t, err)

	// Encrypt m=0.6 under pkAgg via Agent B's session encryptor.
	sessB := agentState(t, b, sid)
	require.NotNil(t, sessB.pkAgg)
	require.NotNil(t, sessB.authchain)
	encoder := ckks.NewEncoder(params.CKKS)
	values := make([]float64, params.CKKS.MaxSlots())
	values[0] = 0.6
	pt := ckks.NewPlaintext(params.CKKS, params.CKKS.MaxLevel())
	require.NoError(t, encoder.Encode(values, pt))
	encryptor := rlwe.NewEncryptor(params.CKKS, sessB.pkAgg)
	resultCt, err := encryptor.EncryptNew(pt)
	require.NoError(t, err)

	ctM, err := b.BuildAuthenticatedCt(sid, resultCt)
	require.NoError(t, err)

	// Drive FinalizeDecryption end-to-end. We reuse the stub's sk_c to
	// produce VClient's smudged partial-decrypt share against ct_M.
	verdict := runFinalizeOnAgentWithCtM(t, b, sid, ctM, stub, params)
	assert.Equal(t, protocol.VerdictAccept, verdict, "rebuilt Agent must verify a fresh honest ct_M")
}

// runFinalizeOnAgentWithCtM is a small helper that mirrors the keyswitch
// path inside finalize_test.go but takes an existing ct_M instead of
// running BuildAuthenticatedCt itself.
func runFinalizeOnAgentWithCtM(
	t *testing.T,
	a *Agent,
	sid protocol.SessionID,
	ctM *rlwe.Ciphertext,
	stub *vclientStub,
	params protocol.Params,
) protocol.Verdict {
	t.Helper()
	clientProto, err := multiparty.NewKeySwitchProtocol(params.CKKS, ring.DiscreteGaussian{
		Sigma: params.FloodSigma,
		Bound: 6 * params.FloodSigma,
	})
	require.NoError(t, err)
	zeroSk := rlwe.NewSecretKey(params.CKKS)
	clientShare := clientProto.AllocateShare(ctM.Level())
	clientProto.GenShare(stub.skCEval, zeroSk, ctM, &clientShare)
	verdict, err := a.FinalizeDecryption(sid, ctM, clientShare)
	require.NoError(t, err)
	return verdict
}
