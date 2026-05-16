package authenticator

import (
	"crypto/rand"
	"math"
	"testing"

	"github.com/butvinm/ppiav/internal/authchain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// authTestFixture wires up a single-party CKKS deployment with Galois
// keys for the eval-level base-2 atom set Auth's chain rotator consumes.
// The full multi-party handshake is exercised in `chain_noise_gate_test.go`
// (chain-rotation math) and `internal/vagent/*_test.go` (end-to-end).
type authTestFixture struct {
	params    ckks.Parameters
	kgen      *rlwe.KeyGenerator
	sk        *rlwe.SecretKey
	pk        *rlwe.PublicKey
	rlk       *rlwe.RelinearizationKey
	gks       []*rlwe.GaloisKey
	atoms     []int
	evk       rlwe.EvaluationKeySet
	encoder   *ckks.Encoder
	encryptor *rlwe.Encryptor
	decryptor *rlwe.Decryptor
	rot       *authchain.Evaluator
}

// authAtoms returns the powers-of-two strictly less than lambda — the
// eval-level base-2 atom set used by the chain rotator.
func authAtoms(lambda int) []int {
	if lambda <= 1 {
		return nil
	}
	out := []int{}
	for a := 1; a < lambda; a <<= 1 {
		out = append(out, a)
	}
	return out
}

func newAuthTestFixture(t *testing.T, lambda int) authTestFixture {
	t.Helper()
	p := testParams(t)
	kgen := rlwe.NewKeyGenerator(p)
	sk, pk := kgen.GenKeyPairNew()
	rlk := kgen.GenRelinearizationKeyNew(sk)

	// Generate keys only for the auth atoms (negative galEl convention).
	// The chain rotator decomposes any `j ∈ [1, lambda)` into a sum of
	// these atoms via binary expansion.
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

// encryptSlot0 encrypts a plaintext whose slot 0 is `m` and other slots
// are 0, at scale Δ and at the params' max level.
func (f authTestFixture) encryptSlot0(t *testing.T, m float64) *rlwe.Ciphertext {
	t.Helper()
	values := make([]float64, f.params.MaxSlots())
	values[0] = m
	pt := ckks.NewPlaintext(f.params, f.params.MaxLevel())
	require.NoError(t, f.encoder.Encode(values, pt))
	ct, err := f.encryptor.EncryptNew(pt)
	require.NoError(t, err)
	return ct
}

// decryptToSlots returns the decoded slot vector of ct.
func (f authTestFixture) decryptToSlots(t *testing.T, ct *rlwe.Ciphertext) []float64 {
	t.Helper()
	pt := f.decryptor.DecryptNew(ct)
	out := make([]float64, f.params.MaxSlots())
	require.NoError(t, f.encoder.Decode(pt, out))
	return out
}

func TestAuthRoundTripWithVer(t *testing.T) {
	const lambda = 16
	f := newAuthTestFixture(t, lambda)

	cfg := Config{Lambda: lambda, Epsilon: math.Exp2(20)}
	a, err := New(cfg, f.params)
	require.NoError(t, err)

	key, err := KeyGen(cfg, rand.Reader)
	require.NoError(t, err)

	resultCt := f.encryptSlot0(t, 0.5)
	ctM, err := a.Auth(key, f.encryptor, f.rot, resultCt)
	require.NoError(t, err)

	plaintext := f.decryptToSlots(t, ctM)

	// Reconstruct v[i] from key.SeedF — same derivation Ver uses.
	vRaw, err := vRawValues(key.SeedF, lambda, key.S, a.q0Half)
	require.NoError(t, err)

	delta := f.params.DefaultScale().Float64()
	inS := sInSet(key.S, lambda)

	// Slots in S carry v[i]/Δ within Epsilon (in scaled-message space).
	for i := 0; i < lambda; i++ {
		if !inS[i] {
			continue
		}
		assert.InDelta(t, vRaw[i]/delta, plaintext[i], cfg.Epsilon/delta,
			"slot %d (in S) should equal v[%d]/Δ", i, i)
	}
	// Slots in [0, lambda) \ S all carry m=0.5 within Epsilon/Δ.
	for i := 0; i < lambda; i++ {
		if inS[i] {
			continue
		}
		assert.InDelta(t, 0.5, plaintext[i], cfg.Epsilon/delta,
			"slot %d (not in S) should equal m", i)
	}

	// Ver accepts the honest decryption and returns the original m.
	m, ok := a.Ver(key, plaintext)
	assert.True(t, ok, "Ver should accept honest decryption")
	assert.InDelta(t, 0.5, m, cfg.Epsilon/delta)
}

func TestVerRejectsTamperedSlot(t *testing.T) {
	const lambda = 16
	f := newAuthTestFixture(t, lambda)

	cfg := Config{Lambda: lambda, Epsilon: math.Exp2(20)}
	a, err := New(cfg, f.params)
	require.NoError(t, err)

	key, err := KeyGen(cfg, rand.Reader)
	require.NoError(t, err)

	resultCt := f.encryptSlot0(t, 0.5)
	ctM, err := a.Auth(key, f.encryptor, f.rot, resultCt)
	require.NoError(t, err)

	plaintext := f.decryptToSlots(t, ctM)

	// Tamper: shift one S slot by 2·Epsilon (in scaled space) => 2·Epsilon/Δ in decoded space.
	delta := f.params.DefaultScale().Float64()
	tampered := append([]float64(nil), plaintext...)
	tampered[key.S[0]] += 2 * cfg.Epsilon / delta
	_, ok := a.Ver(key, tampered)
	assert.False(t, ok, "Ver must reject when an S slot is shifted by > ε")

	// Honest plaintext still verifies.
	_, ok = a.Ver(key, plaintext)
	assert.True(t, ok)
}

func TestVerRejectsTamperedValueSlot(t *testing.T) {
	const lambda = 16
	f := newAuthTestFixture(t, lambda)

	cfg := Config{Lambda: lambda, Epsilon: math.Exp2(20)}
	a, err := New(cfg, f.params)
	require.NoError(t, err)

	key, err := KeyGen(cfg, rand.Reader)
	require.NoError(t, err)

	resultCt := f.encryptSlot0(t, 0.5)
	ctM, err := a.Auth(key, f.encryptor, f.rot, resultCt)
	require.NoError(t, err)

	plaintext := f.decryptToSlots(t, ctM)

	// Tamper one non-S slot (not j*) by 2·Epsilon in scaled space.
	delta := f.params.DefaultScale().Float64()
	inS := sInSet(key.S, lambda)
	jStar := -1
	other := -1
	for i := 0; i < lambda; i++ {
		if inS[i] {
			continue
		}
		if jStar == -1 {
			jStar = i
		} else if other == -1 {
			other = i
			break
		}
	}
	require.NotEqual(t, -1, jStar)
	require.NotEqual(t, -1, other)

	tampered := append([]float64(nil), plaintext...)
	tampered[other] += 2 * cfg.Epsilon / delta
	_, ok := a.Ver(key, tampered)
	assert.False(t, ok, "Ver must reject when a non-S slot diverges from P[j*] by > ε")
}

func TestAuthMissingGaloisKeys(t *testing.T) {
	const lambda = 16
	f := newAuthTestFixture(t, lambda)

	cfg := Config{Lambda: lambda, Epsilon: math.Exp2(20)}
	a, err := New(cfg, f.params)
	require.NoError(t, err)

	key, err := KeyGen(cfg, rand.Reader)
	require.NoError(t, err)

	// Build a chain rotator with one fewer atom key than required. Auth's
	// validateGaloisKeys must flag the missing atom and refuse to run.
	partialGks := f.gks[:len(f.gks)-1]
	partialAtoms := f.atoms[:len(f.atoms)-1]
	partialRot, err := authchain.New(f.params, f.rlk, partialGks, partialAtoms)
	require.NoError(t, err)

	resultCt := f.encryptSlot0(t, 0.5)
	_, err = a.Auth(key, f.encryptor, partialRot, resultCt)
	require.Error(t, err, "Auth must error when atom Galois key set is incomplete")
}

func TestAuthRejectsMismatchedKey(t *testing.T) {
	const lambda = 16
	f := newAuthTestFixture(t, lambda)

	cfg := Config{Lambda: lambda, Epsilon: math.Exp2(20)}
	a, err := New(cfg, f.params)
	require.NoError(t, err)

	// Hand-built Key with wrong |S|.
	badKey := Key{S: []int{0, 1, 2}, SeedF: [32]byte{1, 2, 3}}
	resultCt := f.encryptSlot0(t, 0.5)
	_, err = a.Auth(badKey, f.encryptor, f.rot, resultCt)
	require.Error(t, err)
}

func TestDeriveVDeterministic(t *testing.T) {
	const lambda = 16
	p := testParams(t)
	cfg := Config{Lambda: lambda, Epsilon: math.Exp2(20)}
	a, err := New(cfg, p)
	require.NoError(t, err)
	key, err := KeyGen(cfg, rand.Reader)
	require.NoError(t, err)

	v1, err := deriveV(key.SeedF, lambda, key.S, a.q0Half, a.deltaF64)
	require.NoError(t, err)
	v2, err := deriveV(key.SeedF, lambda, key.S, a.q0Half, a.deltaF64)
	require.NoError(t, err)
	assert.Equal(t, v1, v2, "deriveV must be deterministic for a fixed seed and S")

	raw1, err := vRawValues(key.SeedF, lambda, key.S, a.q0Half)
	require.NoError(t, err)
	raw2, err := vRawValues(key.SeedF, lambda, key.S, a.q0Half)
	require.NoError(t, err)
	assert.Equal(t, raw1, raw2)

	// And deriveV's values match vRawValues / Δ for i ∈ S.
	for _, i := range key.S {
		assert.InEpsilon(t, raw1[i]/a.deltaF64, v1[i], 1e-12)
	}
}

func TestVRawValuesExposesHelperForBench(t *testing.T) {
	// VRawValues is the public hook used by cmd/ppiav-cli's verify-mac
	// subcommand to synthesize a Ver-accepting plaintext without driving a
	// full FHE round-trip. The values it returns must equal the internal
	// vRawValues call byte-for-byte so the synthetic plaintext fed to Ver
	// matches what joint decryption would produce.
	const lambda = 16
	p := testParams(t)
	cfg := Config{Lambda: lambda, Epsilon: math.Exp2(20)}
	a, err := New(cfg, p)
	require.NoError(t, err)
	key, err := KeyGen(cfg, rand.Reader)
	require.NoError(t, err)

	got, err := a.VRawValues(key)
	require.NoError(t, err)
	want, err := vRawValues(key.SeedF, lambda, key.S, a.q0Half)
	require.NoError(t, err)
	assert.Equal(t, want, got)

	// Synthesize the Ver-accepting plaintext from VRawValues + a chosen m.
	inS := sInSet(key.S, lambda)
	plaintext := make([]float64, p.MaxSlots())
	const m = 0.5
	for i := 0; i < lambda; i++ {
		if inS[i] {
			plaintext[i] = got[i] / a.deltaF64
		} else {
			plaintext[i] = m
		}
	}
	recovered, ok := a.Ver(key, plaintext)
	require.True(t, ok, "synthesized plaintext must pass Ver")
	assert.InDelta(t, m, recovered, 1e-12)
}

// VRawValues rejects bad input: wrong-sized S, or a stale Authenticator
// with an invalid config (defensive — the constructor refuses such
// configs, but we still guard the method).
func TestVRawValuesValidates(t *testing.T) {
	const lambda = 16
	p := testParams(t)
	cfg := Config{Lambda: lambda, Epsilon: math.Exp2(20)}
	a, err := New(cfg, p)
	require.NoError(t, err)
	key, err := KeyGen(cfg, rand.Reader)
	require.NoError(t, err)

	bad := key
	bad.S = key.S[:len(key.S)-1] // drop one element → |S| != lambda/2
	_, err = a.VRawValues(bad)
	require.Error(t, err)
}

func TestNewCachesOneHotMask(t *testing.T) {
	p := testParams(t)
	a, err := New(DefaultConfig(), p)
	require.NoError(t, err)
	require.NotNil(t, a.oneHot)
	assert.Len(t, a.oneHot, p.MaxSlots())
	assert.InDelta(t, 1.0, a.oneHot[0], 1e-12)
	for i := 1; i < 8; i++ {
		assert.InDelta(t, 0.0, a.oneHot[i], 1e-12)
	}
}
