package authenticator

import (
	"crypto/rand"
	"math"
	"testing"

	"github.com/butvinm/ppiav/internal/authchain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// fixtureForChain mirrors newAuthTestFixture but lets the caller supply
// LogQ explicitly. Used by the level-reservation tests to vary chain
// length while keeping LogN/LogP/lambda fixed.
func fixtureForChain(t *testing.T, lambda int, logQ []int) authTestFixture {
	t.Helper()
	p, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            14,
		LogQ:            logQ,
		LogP:            []int{55, 55},
		LogDefaultScale: 40,
		RingType:        ring.Standard,
	})
	require.NoError(t, err)

	kgen := rlwe.NewKeyGenerator(p)
	sk, pk := kgen.GenKeyPairNew()
	rlk := kgen.GenRelinearizationKeyNew(sk)

	atoms := authAtoms(lambda)
	rots := make([]int, len(atoms))
	for i, a := range atoms {
		rots[i] = -a
	}
	galEls := p.GaloisElements(rots)
	gks := kgen.GenGaloisKeysNew(galEls, sk)
	evk := rlwe.NewMemEvaluationKeySet(rlk, gks...)

	rot, err := authchain.New(p, rlk, gks, atoms)
	require.NoError(t, err)

	return authTestFixture{
		params:    p,
		kgen:      kgen,
		sk:        sk,
		pk:        pk,
		rlk:       rlk,
		gks:       gks,
		atoms:     atoms,
		evk:       evk,
		encoder:   ckks.NewEncoder(p),
		encryptor: rlwe.NewEncryptor(p, pk),
		decryptor: rlwe.NewDecryptor(p, sk),
		rot:       rot,
	}
}

// encryptAtLevel encrypts the slot-0 message at exactly the requested
// ciphertext level using NewPlaintext(params, level). Mirrors the
// approach in TestAuthRejectsLevelZeroInput.
func (f authTestFixture) encryptAtLevel(t *testing.T, m float64, level int) *rlwe.Ciphertext {
	t.Helper()
	values := make([]float64, f.params.MaxSlots())
	values[0] = m
	pt := ckks.NewPlaintext(f.params, level)
	require.NoError(t, f.encoder.Encode(values, pt))
	ct, err := f.encryptor.EncryptNew(pt)
	require.NoError(t, err)
	require.Equal(t, level, ct.Level(), "fixture precondition")
	return ct
}

// TestAuthAcceptsLevelOneInput is the positive counterpart to the
// existing TestAuthRejectsLevelZeroInput: Auth must succeed when given a
// ciphertext at level 1. This confirms level 1 is the actual minimum the
// authenticator needs, not just "more than zero".
func TestAuthAcceptsLevelOneInput(t *testing.T) {
	const lambda = 16
	logQ := []int{55, 40, 40} // 3 primes → levels 0, 1, 2

	f := fixtureForChain(t, lambda, logQ)
	require.Equal(t, 2, f.params.MaxLevel())

	cfg := Config{Lambda: lambda, Epsilon: math.Exp2(20)}
	a, err := New(cfg, f.params)
	require.NoError(t, err)
	key, err := KeyGen(cfg, rand.Reader)
	require.NoError(t, err)

	ct := f.encryptAtLevel(t, 0.5, 1)
	ctM, err := a.Auth(key, f.encryptor, f.rot, ct)
	require.NoError(t, err, "Auth must accept level-1 input")
	require.NotNil(t, ctM)
}

// TestProtocolReserveLevelHypothesis demonstrates the user's proposed
// architecture for resolving the Task 27a / bench-redesign-v2 level-0
// bug at LogN=16:
//
//	model_depth = K  (the number of multiplicative levels the model needs)
//	chain_length without protocol reserve = K+1 primes  →  result_ct at level 0
//	chain_length with protocol reserve    = K+1+1 primes (one extra for MAC)
//	                                      →  encrypt at MaxLevel of extended chain
//	                                      →  after K rescales, ct lands at level 1
//	                                      →  Auth.MulNew has the level-1 headroom it needs
//
// This isolates the level math from any Orion / C3AE specifics: we
// model "model output at level X" by encrypting directly at level X
// (the same pattern the existing TestAuthRejectsLevelZeroInput uses).
//
// Scenario A reproduces the current eval bug: model declares its own chain
// (K+1 primes), nothing extra → result at level 0 → Auth rejects.
// Scenario B applies the user's proposed protocol-side extension (+1 prime
// on top of model's K+1) → result at level 1 → Auth accepts.
func TestProtocolReserveLevelHypothesis(t *testing.T) {
	const lambda = 16
	const modelDepth = 15 // empirical from this VPS run: 15 rescales

	t.Run("A_model_owns_chain_lands_at_level_0", func(t *testing.T) {
		// K+1 primes total. The "model" encrypts at MaxLevel=K and the
		// circuit consumes K rescales → result at level 0.
		logQ := make([]int, modelDepth+1)
		logQ[0] = 55
		for i := 1; i < len(logQ); i++ {
			logQ[i] = 40
		}
		f := fixtureForChain(t, lambda, logQ)
		require.Equal(t, modelDepth, f.params.MaxLevel())

		cfg := Config{Lambda: lambda, Epsilon: math.Exp2(20)}
		a, err := New(cfg, f.params)
		require.NoError(t, err)
		key, err := KeyGen(cfg, rand.Reader)
		require.NoError(t, err)

		// Simulate "after K rescales": ct lives at level 0.
		ctAtZero := f.encryptAtLevel(t, 0.5, 0)
		_, err = a.Auth(key, f.encryptor, f.rot, ctAtZero)
		assert.Error(t, err, "Scenario A: result at level 0 — Auth must reject")
		assert.Contains(t, err.Error(), "Level() ≥ 1")
	})

	t.Run("B_protocol_extends_by_1_lands_at_level_1", func(t *testing.T) {
		// K+1+N_reserve primes. Encrypt at MaxLevel of the extended chain,
		// circuit consumes K rescales → ct at level N_reserve = 1.
		const nReserve = 1
		logQ := make([]int, modelDepth+1+nReserve)
		logQ[0] = 55
		for i := 1; i < len(logQ); i++ {
			logQ[i] = 40
		}
		f := fixtureForChain(t, lambda, logQ)
		require.Equal(t, modelDepth+nReserve, f.params.MaxLevel())

		cfg := Config{Lambda: lambda, Epsilon: math.Exp2(20)}
		a, err := New(cfg, f.params)
		require.NoError(t, err)
		key, err := KeyGen(cfg, rand.Reader)
		require.NoError(t, err)

		// Simulate "after K rescales on the EXTENDED chain": ct at level 1.
		ctAtOne := f.encryptAtLevel(t, 0.5, nReserve)
		ctM, err := a.Auth(key, f.encryptor, f.rot, ctAtOne)
		assert.NoError(t, err, "Scenario B: result at level 1 — Auth must accept")
		assert.NotNil(t, ctM)
	})
}
