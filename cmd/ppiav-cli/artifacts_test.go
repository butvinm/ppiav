package main

import (
	"os"
	"path/filepath"
	"testing"

	hierkeys "github.com/butvinm/lattigo-hierkeys"
	"github.com/butvinm/ppiav/internal/authenticator"
	"github.com/butvinm/ppiav/internal/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// smallParams builds the CLI artifact-test profile: LogN=14 (8192 slots),
// λ=8 so 3 auth atoms, LLKN with a single 40-bit P prime to exercise the
// dual-PK + master-key write/read paths introduced by the lattigo-hierkeys
// split. Kept here so the artifact tests stay self-contained; vclient and
// vagent each maintain their own equivalents.
func smallCLIParams(t *testing.T) protocol.Params {
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
		CKKS:          ckksParams,
		LLKN:          llknParams,
		LLKNBase:      protocol.DefaultLLKNBase,
		Authenticator: authenticator.Config{Lambda: 8, Epsilon: 1.0},
		FloodSigma:    65536,
	}
}

// TestWriteReadGaloisKeysRoundTrip exercises the gks_infer.bin on-disk
// shape. The test generates a small slice of real *rlwe.GaloisKey at eval
// level via Lattigo's KeyGenerator, persists them, reads them back, and
// asserts the GaloisElement set matches.
func TestWriteReadGaloisKeysRoundTrip(t *testing.T) {
	params := smallCLIParams(t)
	dir := t.TempDir()

	kg := rlwe.NewKeyGenerator(params.CKKS)
	sk := kg.GenSecretKeyNew()
	galEls := []uint64{
		params.CKKS.GaloisElement(-1),
		params.CKKS.GaloisElement(-2),
		params.CKKS.GaloisElement(-4),
	}
	want := make([]*rlwe.GaloisKey, len(galEls))
	for i, el := range galEls {
		want[i] = kg.GenGaloisKeyNew(el, sk)
	}

	require.NoError(t, writeGaloisKeys(dir, artifactGKSInfer, want))
	got, err := readGaloisKeys(dir, artifactGKSInfer)
	require.NoError(t, err)
	require.Len(t, got, len(want))

	gotEls := make(map[uint64]bool, len(got))
	for _, gk := range got {
		gotEls[gk.GaloisElement] = true
	}
	for _, el := range galEls {
		assert.True(t, gotEls[el], "expected GaloisElement %d in readback", el)
	}

	// The artifact file must exist on disk for the bench's os.Stat path.
	info, err := os.Stat(filepath.Join(dir, artifactGKSInfer))
	require.NoError(t, err)
	assert.Positive(t, info.Size(), "gks_infer.bin must have non-zero size")
}

// TestWriteReadMasterKeysRoundTrip exercises gks_master.bin. We generate
// a DISTINCT MasterKey per atom (different rotation indices fed into the
// hierkeys Galois-key-to-master conversion) and round-trip the
// {atom -> MasterKey} map through writeMasterKeys/readMasterKeys, asserting
// each readback matches its own original bytes. Using one shared MasterKey
// across atoms would silently pass an off-by-one indexing / swap bug; the
// per-atom distinct keys make any cross-atom drift visible.
func TestWriteReadMasterKeysRoundTrip(t *testing.T) {
	params := smallCLIParams(t)
	dir := t.TempDir()

	topParams := params.LLKN.Top()
	kg := rlwe.NewKeyGenerator(topParams)
	skTop := kg.GenSecretKeyNew()

	// Generate a distinct top-level GaloisKey per atom and convert each
	// to a MasterKey. Atom values are arbitrary positive ints; what
	// matters for the round-trip test is that the per-MasterKey bytes
	// differ across atoms so cross-atom swaps are catchable.
	atoms := []int{1, 4, 16}
	want := make(map[int]*hierkeys.MasterKey, len(atoms))
	for _, atom := range atoms {
		galEl := topParams.GaloisElement(atom)
		gk := kg.GenGaloisKeyNew(galEl, skTop)
		mk, err := hierkeys.GaloisKeyToMasterKey(topParams, gk)
		require.NoError(t, err)
		want[atom] = mk
	}

	// Sanity: per-atom MasterKey bytes really do differ (otherwise the
	// round-trip below would be just as weak as the original test).
	prevBytes, err := want[atoms[0]].MarshalBinary()
	require.NoError(t, err)
	for _, atom := range atoms[1:] {
		b, err := want[atom].MarshalBinary()
		require.NoError(t, err)
		require.NotEqual(t, prevBytes, b, "per-atom MasterKeys must differ to exercise round-trip")
		prevBytes = b
	}

	require.NoError(t, writeMasterKeys(dir, artifactGKSMaster, want))
	got, err := readMasterKeys(dir, artifactGKSMaster)
	require.NoError(t, err)
	require.Len(t, got, len(want))

	for atom, mkWant := range want {
		mkGot, ok := got[atom]
		require.True(t, ok, "atom %d missing from readback", atom)
		// Per-MasterKey byte equivalence: MarshalBinary is deterministic.
		wantBytes, err := mkWant.MarshalBinary()
		require.NoError(t, err)
		gotBytes, err := mkGot.MarshalBinary()
		require.NoError(t, err)
		assert.Equalf(t, wantBytes, gotBytes, "MasterKey bytes differ for atom %d", atom)
	}

	info, err := os.Stat(filepath.Join(dir, artifactGKSMaster))
	require.NoError(t, err)
	assert.Positive(t, info.Size(), "gks_master.bin must have non-zero size")
}

// TestReadMasterKeysShortHeader guards against silent corruption of the
// length-prefixed wire format — a truncated count header must fail loudly.
func TestReadMasterKeysShortHeader(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, writeBytes(dir, artifactGKSMaster, []byte{0x00, 0x01}))
	_, err := readMasterKeys(dir, artifactGKSMaster)
	require.Error(t, err)
}

// TestWriteReadParamsRoundTrip verifies the params.json envelope (CKKS +
// InputLevel) survives a full round-trip and that loadParams re-stamps
// LLKN against the persisted CKKS.
func TestWriteReadParamsRoundTrip(t *testing.T) {
	want := smallCLIParams(t)
	want.InputLevel = 2
	dir := t.TempDir()
	require.NoError(t, writeParams(dir, want))

	got, err := loadParams(dir)
	require.NoError(t, err)
	assert.Equal(t, want.InputLevel, got.InputLevel)
	assert.Equal(t, want.CKKS.LogN(), got.CKKS.LogN())
	// LLKN re-stamped from the persisted CKKS, so its eval-level params
	// must match the original.
	assert.Equal(t, want.LLKN.Eval().LogN(), got.LLKN.Eval().LogN())
}
