package orchestrator

import (
	"math"
	"testing"

	"github.com/butvinm/ppiav/internal/authenticator"
	"github.com/butvinm/ppiav/internal/protocol"
	"github.com/butvinm/ppiav/internal/vservice"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// imageLen mirrors vclient.imageLen (3·64·64). Kept private so the
// orchestrator tests don't need to import the constant; identical to
// internal/vclient/image.go.
const imageLen = 3 * 64 * 64

// testParams builds the orchestrator's unit-test profile.
//
// Tradeoff: docs/plans/20260514-phase-1-2-multiparty-ckks-and-c3ae.md
// originally suggested LogN=14 for speed, but vclient.EncryptImage hard-
// fails on len(image) != 12288 and LogN=14 only provides 8192 slots. We
// bump to LogN=15 (16384 slots, just enough to hold the 12288-element
// image padded with zeros) and keep λ=8 so the rotation count stays small
// (7 Galois keys). Slower than LogN=14 but mirrors the production path
// (image padded to MaxSlots) instead of inventing a smaller "test only"
// encryption path that production never exercises.
func testParams(t *testing.T) protocol.Params {
	t.Helper()
	lit := ckks.ParametersLiteral{
		LogN:            15,
		LogQ:            []int{55, 40, 40},
		LogP:            []int{55, 55},
		LogDefaultScale: 40,
		RingType:        ring.Standard,
	}
	ckksParams, err := ckks.NewParametersFromLiteral(lit)
	require.NoError(t, err)
	return protocol.Params{
		CKKS:          ckksParams,
		Authenticator: authenticator.Config{Lambda: 8, Epsilon: math.Exp2(20)},
		FloodSigma:    math.Exp2(16),
	}
}

// sampleImage builds a 12288-length image with slot 0 set to v and the
// rest zero. Mirrors what models/prepare_samples.py emits, minus the
// preprocessing pipeline.
func sampleImage(v float64) []float64 {
	img := make([]float64, imageLen)
	img[0] = v
	return img
}

func TestRunnerHappyPathAccept(t *testing.T) {
	params := testParams(t)
	r, err := NewRunner(params)
	require.NoError(t, err)

	sid, err := r.Open()
	require.NoError(t, err)
	require.NotEmpty(t, sid)
	require.Equal(t, sid, r.SessionID())

	require.NoError(t, r.Setup())

	// x²(0.5) = 0.25 > 0 → Accept.
	resultCt, err := r.Infer(sampleImage(0.5))
	require.NoError(t, err)
	require.NotNil(t, resultCt)

	verdict, err := r.Verify(resultCt)
	require.NoError(t, err)
	assert.Equal(t, protocol.VerdictAccept, verdict)

	// RService received the verdict via Verify.
	assert.Equal(t, protocol.VerdictAccept, r.RService().CheckAccess(sid))
}

// negatingInferrer wraps a real vservice.Service: OpenSession,
// StoreEvalKeys, and Params delegate; Infer runs the real x² circuit and
// then multiplies the result by a negative scalar so the recovered logit
// is negative → Verify should return Reject.
//
// The Mul-by-constant path on Evaluator does not need any eval keys
// beyond what StoreEvalKeys already loaded, so the wrapper can reuse the
// production evaluator transparently. Calling MulNew on the real
// vservice's evaluator would require exposing it; since we only have the
// returned ciphertext, we build a fresh Evaluator with no eval keys
// (constant multiplication needs none) for the post-process step.
type negatingInferrer struct {
	inner  *vservice.Service
	params protocol.Params
}

func (n *negatingInferrer) OpenSession() (protocol.SessionID, error) {
	return n.inner.OpenSession()
}

func (n *negatingInferrer) StoreEvalKeys(sid protocol.SessionID, rlk *rlwe.RelinearizationKey, gks []*rlwe.GaloisKey) error {
	return n.inner.StoreEvalKeys(sid, rlk, gks)
}

func (n *negatingInferrer) Params() protocol.Params { return n.params }

func (n *negatingInferrer) Infer(sid protocol.SessionID, in *rlwe.Ciphertext) (*rlwe.Ciphertext, error) {
	out, err := n.inner.Infer(sid, in)
	if err != nil {
		return nil, err
	}
	// Scalar Mul does not require relin or Galois keys. We build a fresh
	// Evaluator with no eval-key set to keep the wrapper self-contained.
	eval := ckks.NewEvaluator(n.params.CKKS, nil)
	negated, err := eval.MulNew(out, -2.0)
	if err != nil {
		return nil, err
	}
	if err := eval.Rescale(negated, negated); err != nil {
		return nil, err
	}
	return negated, nil
}

func TestRunnerRejectsNegativeLogit(t *testing.T) {
	params := testParams(t)
	// LogN=15 with LogQ=[55,40,40] gives only 3 modulus levels — x²
	// consumes 1 level and the negation consumes another. The
	// authenticated-ct construction in Auth needs one more multiplication
	// (mask × result), so we need at least one level left after the
	// negation rescale. With 3 levels: initial=2, after x² rescale=1,
	// after Mul(-2) rescale=0 → no level left for Auth's mask. Bump LogQ
	// for this test only.
	logQ := []int{55, 40, 40, 40}
	lit := ckks.ParametersLiteral{
		LogN:            15,
		LogQ:            logQ,
		LogP:            []int{55, 55},
		LogDefaultScale: 40,
		RingType:        ring.Standard,
	}
	ckksParams, err := ckks.NewParametersFromLiteral(lit)
	require.NoError(t, err)
	params.CKKS = ckksParams

	inner := vservice.New(params)
	mock := &negatingInferrer{inner: inner, params: params}

	r, err := NewRunnerWithInferrer(params, mock)
	require.NoError(t, err)

	sid, err := r.Open()
	require.NoError(t, err)
	require.NoError(t, r.Setup())

	// x²(0.5) = 0.25; mock negates by -2 → -0.5 < 0 → Reject.
	resultCt, err := r.Infer(sampleImage(0.5))
	require.NoError(t, err)

	verdict, err := r.Verify(resultCt)
	require.NoError(t, err)
	assert.Equal(t, protocol.VerdictReject, verdict)
	assert.Equal(t, protocol.VerdictReject, r.RService().CheckAccess(sid))
}

func TestRunnerF4bDenyByDefault(t *testing.T) {
	// docs/DESIGN.md §`Failure modes`: F4b ("VService unreachable, Stages
	// 2–3") collapses to a deny-by-default — RService.CheckAccess for a
	// session that never reached a verdict callback must return
	// VerdictUnknown, which the resource layer renders as 403. We pin the
	// contract here by opening + setting up but skipping Infer/Verify.
	params := testParams(t)
	r, err := NewRunner(params)
	require.NoError(t, err)

	sid, err := r.Open()
	require.NoError(t, err)
	require.NoError(t, r.Setup())

	assert.Equal(t, protocol.VerdictUnknown, r.RService().CheckAccess(sid),
		"deny-by-default: no verdict delivered → CheckAccess returns Unknown")
}

func TestRunnerEnforcesStageOrdering(t *testing.T) {
	params := testParams(t)
	r, err := NewRunner(params)
	require.NoError(t, err)

	// Verify before Setup must error.
	_, err = r.Verify(&rlwe.Ciphertext{})
	require.Error(t, err, "Verify before Open must error")

	// Infer before Setup must error.
	_, err = r.Infer(sampleImage(0.5))
	require.Error(t, err, "Infer before Open must error")

	// Setup before Open must error.
	require.Error(t, r.Setup(), "Setup before Open must error")

	// Open then Verify (skipping Setup + Infer) must error.
	_, err = r.Open()
	require.NoError(t, err)
	_, err = r.Verify(&rlwe.Ciphertext{})
	require.Error(t, err, "Verify after Open but before Setup+Infer must error")

	// Open + Setup then Verify (skipping Infer) must error.
	require.NoError(t, r.Setup())
	_, err = r.Verify(&rlwe.Ciphertext{})
	require.Error(t, err, "Verify after Setup but before Infer must error")
}

func TestNewRunnerWithInferrerRejectsNil(t *testing.T) {
	params := testParams(t)
	_, err := NewRunnerWithInferrer(params, nil)
	require.Error(t, err)
}
