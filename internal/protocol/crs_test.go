package protocol

import (
	"bytes"
	"math"
	"sort"
	"testing"

	"github.com/butvinm/ppiav/internal/authenticator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"

	"github.com/butvinm/lattigo-hierkeys/llkn"
)

func TestNewSessionCRSDeterministic(t *testing.T) {
	sid := SessionID("abc123")

	prng1, err := NewSessionCRS(sid)
	require.NoError(t, err)
	prng2, err := NewSessionCRS(sid)
	require.NoError(t, err)

	buf1 := make([]byte, 32)
	buf2 := make([]byte, 32)
	_, err = prng1.Read(buf1)
	require.NoError(t, err)
	_, err = prng2.Read(buf2)
	require.NoError(t, err)

	assert.Equal(t, buf1, buf2)
}

func TestNewSessionCRSDifferentSids(t *testing.T) {
	prng1, err := NewSessionCRS("aaaaaaaa")
	require.NoError(t, err)
	prng2, err := NewSessionCRS("bbbbbbbb")
	require.NoError(t, err)

	buf1 := make([]byte, 32)
	buf2 := make([]byte, 32)
	_, err = prng1.Read(buf1)
	require.NoError(t, err)
	_, err = prng2.Read(buf2)
	require.NoError(t, err)

	assert.False(t, bytes.Equal(buf1, buf2), "different sids must produce different CRS output")
}

func TestCanonicalAuthAtoms_Defaults(t *testing.T) {
	params, err := Defaults()
	require.NoError(t, err)
	got := CanonicalAuthAtoms(params)
	// λ=128 → powers of two up to and including 64.
	assert.Equal(t, []int{1, 2, 4, 8, 16, 32, 64}, got)
	assert.True(t, sort.IntsAreSorted(got), "auth atoms must be ascending")
	assert.Len(t, got, len(params.AuthAtoms()))
}

func TestCanonicalAuthAtoms_VariedLambda(t *testing.T) {
	cases := []struct {
		lambda int
		want   []int
	}{
		{0, nil},
		{1, nil},
		{2, []int{1}},
		{4, []int{1, 2}},
		{8, []int{1, 2, 4}},
		{128, []int{1, 2, 4, 8, 16, 32, 64}},
	}
	for _, c := range cases {
		params, err := Defaults()
		require.NoError(t, err)
		params.Authenticator.Lambda = c.lambda
		assert.Equalf(t, c.want, CanonicalAuthAtoms(params), "lambda=%d", c.lambda)
	}
}

func TestCanonicalInferAtoms_DefaultsBase4LogN16(t *testing.T) {
	params, err := Defaults()
	require.NoError(t, err)
	got := CanonicalInferAtoms(params)
	// Base=4, MaxSlots=N/2=32768 → {1,4,16,64,256,1024,4096,16384}.
	assert.Equal(t, []int{1, 4, 16, 64, 256, 1024, 4096, 16384}, got)
	assert.True(t, sort.IntsAreSorted(got), "infer atoms must be ascending")
	assert.Len(t, got, len(params.InferAtoms()))
}

// smallParamsForCRSTest builds a fast LogN=10 parameter set with a 2-prime
// LLKN top hierarchy. Same overall structure as production (eval-level
// CKKS + extended top-level) but cheap enough to run both parties' full
// canonical draw sequence in a single test.
func smallParamsForCRSTest(t *testing.T) Params {
	t.Helper()
	lit := ckks.ParametersLiteral{
		LogN:            10,
		LogQ:            []int{40, 40},
		LogP:            []int{40},
		LogDefaultScale: 30,
		RingType:        ring.Standard,
	}
	ckksParams, err := ckks.NewParametersFromLiteral(lit)
	require.NoError(t, err)
	llknParams, err := llkn.NewParameters(ckksParams.Parameters, [][]int{{40, 40}})
	require.NoError(t, err)
	return Params{
		CKKS:     ckksParams,
		LLKN:     llknParams,
		LLKNBase: DefaultLLKNBase,
		Authenticator: authenticator.Config{
			Lambda:  8, // → AuthAtoms = {1, 2, 4}
			Epsilon: math.Exp2(20),
		},
		FloodSigma: math.Exp2(16),
	}
}

// canonicalDrawAll runs the 5-step canonical CRP draw against a CRS and
// returns the binary-serialized CRP bytes per step. The order mirrors the
// package doc-comment in `crs.go`; this helper is the executable
// reference for "both parties consume the CRS identically".
//
// Returned slice layout:
//   - [0]:                       pk_eval CRP
//   - [1]:                       pk_top  CRP
//   - [2]:                       rlk     CRP
//   - [3 .. 3+|auth|):           one Galois CRP per ascending auth atom (eval-level)
//   - [3+|auth| .. end):         one Galois CRP per ascending infer atom (top-level)
func canonicalDrawAll(t *testing.T, params Params, crs *sampling.KeyedPRNG) [][]byte {
	t.Helper()
	out := make([][]byte, 0, 3+len(params.AuthAtoms())+len(params.InferAtoms()))

	// Step 1: pk_eval — eval-level public key.
	pkEval := multiparty.NewPublicKeyGenProtocol(params.CKKS)
	pkEvalCRP := pkEval.SampleCRP(crs)
	b, err := pkEvalCRP.Value.MarshalBinary()
	require.NoError(t, err)
	out = append(out, b)

	// Step 2: pk_top — top-level public key.
	pkTop := multiparty.NewPublicKeyGenProtocol(params.LLKN.Top())
	pkTopCRP := pkTop.SampleCRP(crs)
	b, err = pkTopCRP.Value.MarshalBinary()
	require.NoError(t, err)
	out = append(out, b)

	// Step 3: rlk — eval-level relinearization key (single CRP shared by both rounds).
	rlk := multiparty.NewRelinearizationKeyGenProtocol(params.CKKS)
	rlkCRP := rlk.SampleCRP(crs)
	b, err = rlkCRP.Value.MarshalBinary()
	require.NoError(t, err)
	out = append(out, b)

	// Step 4: auth atoms ascending — eval-level Galois CRPs.
	gkgEval := multiparty.NewGaloisKeyGenProtocol(params.CKKS)
	for range params.AuthAtoms() {
		crp := gkgEval.SampleCRP(crs)
		b, err := crp.Value.MarshalBinary()
		require.NoError(t, err)
		out = append(out, b)
	}

	// Step 5: infer atoms ascending — top-level Galois CRPs.
	gkgTop := multiparty.NewGaloisKeyGenProtocol(params.LLKN.Top())
	for range params.InferAtoms() {
		crp := gkgTop.SampleCRP(crs)
		b, err := crp.Value.MarshalBinary()
		require.NoError(t, err)
		out = append(out, b)
	}

	return out
}

// drawLabel returns a human-readable name for the n-th canonical draw —
// used in test failures so a regression points at the exact step.
func drawLabel(params Params, n int) string {
	authStart := 3
	authEnd := authStart + len(params.AuthAtoms())
	switch {
	case n == 0:
		return "pk_eval"
	case n == 1:
		return "pk_top"
	case n == 2:
		return "rlk"
	case n < authEnd:
		return "auth_atom"
	default:
		return "infer_atom"
	}
}

// TestCRSDrawOrderLockstep mirrors what VClient and VAgent each do during
// the collaborative keygen handshake: seed identical CRSes from the same
// session id and draw CRPs in the 5-step order documented in the package
// doc-comment. Both parties must consume the CRS in lockstep — any drift
// shifts subsequent draws out of alignment, so we compare the CRP value
// bytes after a deterministic re-serialization at each step.
func TestCRSDrawOrderLockstep(t *testing.T) {
	params := smallParamsForCRSTest(t)

	// VClient-side draws.
	clientCRS, err := NewSessionCRS("lockstep-sid")
	require.NoError(t, err)
	clientDraws := canonicalDrawAll(t, params, clientCRS)

	// VAgent-side draws against a fresh CRS seeded from the same sid.
	agentCRS, err := NewSessionCRS("lockstep-sid")
	require.NoError(t, err)
	agentDraws := canonicalDrawAll(t, params, agentCRS)

	// Step count: 1 (pk_eval) + 1 (pk_top) + 1 (rlk) + |auth| + |infer|.
	expectedSteps := 3 + len(params.AuthAtoms()) + len(params.InferAtoms())
	require.Len(t, clientDraws, expectedSteps)
	require.Len(t, agentDraws, expectedSteps)

	for i := range clientDraws {
		assert.Equalf(t, clientDraws[i], agentDraws[i],
			"step %d (%s): CRS draws diverged between parties", i, drawLabel(params, i))
	}
}

// TestCRSDrawOrderDistinct guards against the (unlikely but
// catastrophic) case where two consecutive draws return identical CRP
// bytes — that would mean SampleCRP wasn't actually consuming the CRS
// between calls, and a single byte of CRS drift would be invisible.
func TestCRSDrawOrderDistinct(t *testing.T) {
	params := smallParamsForCRSTest(t)
	crs, err := NewSessionCRS("distinct-sid")
	require.NoError(t, err)
	draws := canonicalDrawAll(t, params, crs)

	// All draws must be pairwise distinct. Different-shape CRPs (PK vs
	// RLK vs Galois) might match by accident if any one of them produced
	// a degenerate output; comparing all pairs surfaces that.
	for i := 0; i < len(draws); i++ {
		for j := i + 1; j < len(draws); j++ {
			assert.Falsef(t, bytes.Equal(draws[i], draws[j]),
				"draws at indices %d (%s) and %d (%s) collided",
				i, drawLabel(params, i), j, drawLabel(params, j))
		}
	}
}
