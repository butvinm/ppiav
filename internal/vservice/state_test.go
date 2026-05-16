package vservice

import (
	"testing"

	"github.com/butvinm/ppiav/internal/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// TestExportStateRoundTripInfer verifies that a Service rebuilt via
// NewWithState can run Infer end-to-end on the synthetic x² circuit. We
// stay on the synthetic-x² path (orionDir="") because the plan calls for state
// seeding verification against a trivial keyset — loading the real
// compiled Orion model would require a 1.75 GB artifact that does not live
// in this repo.
//
// The round-trip exercises the contract the bench `infer` subcommand
// depends on: ExportState returns the SID, and NewWithState seeds the
// session map directly so Infer succeeds without OpenSession/StoreEvalKeys.
func TestExportStateRoundTripInfer(t *testing.T) {
	params := smallParams(t)
	a := New(params)

	sid, err := a.OpenSession()
	require.NoError(t, err)

	kgen := rlwe.NewKeyGenerator(params.CKKS)
	sk, pk := kgen.GenKeyPairNew()
	rlk := kgen.GenRelinearizationKeyNew(sk)
	require.NoError(t, a.StoreEvalKeys(sid, rlk, nil, nil))

	// Export and rebuild on a second Service. ExportState now populates
	// Rlk + PKTop + GksMasterInfer + GksInfer from the StoreEvalKeys-
	// captured values, so the test does not have to thread keys back in.
	state, err := a.ExportState(sid)
	require.NoError(t, err)
	require.NotNil(t, state)
	assert.Equal(t, sid, state.SID)
	require.NotNil(t, state.Rlk, "ExportState must populate Rlk from StoreEvalKeys")

	b, err := NewWithState(params, "", state)
	require.NoError(t, err)
	require.NotNil(t, b)

	// Encrypt 0.3 under pk; run x² on both Services; verify outputs decrypt
	// to 0.09 within tolerance.
	encoder := ckks.NewEncoder(params.CKKS)
	encryptor := rlwe.NewEncryptor(params.CKKS, pk)
	decryptor := rlwe.NewDecryptor(params.CKKS, sk)

	values := make([]float64, params.CKKS.MaxSlots())
	values[0] = 0.3
	pt := ckks.NewPlaintext(params.CKKS, params.CKKS.MaxLevel())
	require.NoError(t, encoder.Encode(values, pt))
	inputA, err := encryptor.EncryptNew(pt)
	require.NoError(t, err)
	inputB, err := encryptor.EncryptNew(pt)
	require.NoError(t, err)

	outA, err := a.Infer(sid, inputA)
	require.NoError(t, err)
	outB, err := b.Infer(sid, inputB)
	require.NoError(t, err)

	decodedA := make([]float64, params.CKKS.MaxSlots())
	decodedB := make([]float64, params.CKKS.MaxSlots())
	require.NoError(t, encoder.Decode(decryptor.DecryptNew(outA), decodedA))
	require.NoError(t, encoder.Decode(decryptor.DecryptNew(outB), decodedB))
	assert.InDelta(t, 0.09, decodedA[0], 1e-4, "original Service must run x²")
	assert.InDelta(t, 0.09, decodedB[0], 1e-4, "rebuilt Service must run x²")
}

// ExportState must reject unknown SIDs cleanly so the bench driver surfaces
// the error instead of crashing on a nil deref.
func TestExportStateRejectsUnknownSid(t *testing.T) {
	params := smallParams(t)
	s := New(params)
	_, err := s.ExportState(protocol.SessionID("nope"))
	require.Error(t, err)
}

// ExportState must reject a session that has had OpenSession but no
// StoreEvalKeys — exporting before keygen completes would produce a
// NewWithState session whose evaluator is missing.
func TestExportStateRequiresStoreEvalKeys(t *testing.T) {
	params := smallParams(t)
	s := New(params)
	sid, err := s.OpenSession()
	require.NoError(t, err)
	_, err = s.ExportState(sid)
	require.Error(t, err)
}

// NewWithState must reject nil state and nil Rlk so misuse fails loudly
// instead of producing a half-built Service that crashes at Infer time.
func TestNewWithStateRejectsInvalidInputs(t *testing.T) {
	params := smallParams(t)
	_, err := NewWithState(params, "", nil)
	require.Error(t, err)

	_, err = NewWithState(params, "", &ExportedState{SID: "x"})
	require.Error(t, err, "missing Rlk must fail")
}

// NewWithState in synthetic-x² mode (orionDir="") with valid Rlk must seed
// the session map and produce a Service whose Infer works without any
// further setup — pinning the contract the bench `infer` subcommand relies on.
func TestNewWithStateSyntheticSeedsSession(t *testing.T) {
	params := smallParams(t)
	sid := protocol.SessionID("seed-sid")

	kgen := rlwe.NewKeyGenerator(params.CKKS)
	sk, pk := kgen.GenKeyPairNew()
	rlk := kgen.GenRelinearizationKeyNew(sk)

	s, err := NewWithState(params, "", &ExportedState{SID: sid, Rlk: rlk})
	require.NoError(t, err)

	encoder := ckks.NewEncoder(params.CKKS)
	encryptor := rlwe.NewEncryptor(params.CKKS, pk)
	decryptor := rlwe.NewDecryptor(params.CKKS, sk)
	values := make([]float64, params.CKKS.MaxSlots())
	values[0] = 0.5
	pt := ckks.NewPlaintext(params.CKKS, params.CKKS.MaxLevel())
	require.NoError(t, encoder.Encode(values, pt))
	ct, err := encryptor.EncryptNew(pt)
	require.NoError(t, err)

	out, err := s.Infer(sid, ct)
	require.NoError(t, err)
	decoded := make([]float64, params.CKKS.MaxSlots())
	require.NoError(t, encoder.Decode(decryptor.DecryptNew(out), decoded))
	assert.InDelta(t, 0.25, decoded[0], 1e-4, "rebuilt Service Infer must compute x² on the seeded session")
}
