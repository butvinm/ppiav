package authenticator

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"math/big"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// Authenticator bundles config and session-independent resources: the
// shared *ckks.Encoder and the cached one-hot mask vector. Both are safe
// to reuse across concurrent sessions in Lattigo v6.2.0.
//
// Implementation note: the DESIGN.md description of `pt_one_hot at scale 1`
// is not directly representable in Lattigo's CKKS encoder — a slot value
// of 1 at scale 1 produces time-domain ring coefficients of magnitude
// ~1/N that quantize to zero. We therefore cache the one-hot **slot
// vector** (not a pre-encoded plaintext) and let `eval.Mul(ct, []float64)`
// pick the scale `pt.Scale = q_level_modulus` automatically. The result
// ciphertext rides at scale `ct.Scale * q_level_modulus`; we encode `v`
// at the same scale and add. Ver remains correct because the encoder
// divides out the matched scale on decode, recovering the design's
// slot-level semantics (m at non-S slots, v[i]/Δ at S slots).
type Authenticator struct {
	cfg      Config
	params   ckks.Parameters
	encoder  *ckks.Encoder
	oneHot   []float64
	q0Half   *big.Int // floor(Q_0 / 2); F samples uniformly from (-q0Half, q0Half)
	deltaF64 float64
}

// New constructs an Authenticator with the given config and CKKS params.
// The one-hot mask is session-independent and reused across every Auth
// call (see docs/DESIGN.md §`Implementation notes`).
func New(cfg Config, params ckks.Parameters) (*Authenticator, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	encoder := ckks.NewEncoder(params)

	oneHot := make([]float64, params.MaxSlots())
	oneHot[0] = 1.0

	q0 := new(big.Int).SetUint64(params.Q()[0])
	q0Half := new(big.Int).Rsh(q0, 1)

	return &Authenticator{
		cfg:      cfg,
		params:   params,
		encoder:  encoder,
		oneHot:   oneHot,
		q0Half:   q0Half,
		deltaF64: params.DefaultScale().Float64(),
	}, nil
}

// Config returns the bundled authenticator configuration.
func (a *Authenticator) Config() Config { return a.cfg }

// Rotator is the rotation surface Auth needs from the
// chain-rotation evaluator wrapper. `RotateNew(ct, -j)` must place
// `ct`'s slot 0 at slot `j` (Lattigo convention); `Inner` exposes the
// underlying `*ckks.Evaluator` for Auth's non-rotation operations (mask
// multiply, add). `internal/authchain.Evaluator` satisfies this interface.
type Rotator interface {
	RotateNew(ct *rlwe.Ciphertext, j int) (*rlwe.Ciphertext, error)
	Inner() *ckks.Evaluator
}

// Auth runs §MPD-Auth/Auth: masks slot 0 with the cached pt_one_hot,
// rotates+sums into ct_m^Rep over [0, Lambda) \ S, encrypts v
// deterministically from key.SeedF, adds, returns ct_M.
//
// Required Galois keys on the chain rotator's inner evaluator: one per
// auth atom `a ∈ {1, 2, 4, ..., 2^k}` (powers of two strictly less than
// `Lambda`) at `GaloisElement(-a)`. The rotator's `RotateNew(ct, -j)`
// internally chains `popcount(j)` atom rotations; Auth itself sees the
// logical `-j` semantics unchanged from Phase 1-3.
func (a *Authenticator) Auth(
	key Key,
	encryptor *rlwe.Encryptor,
	rot Rotator,
	resultCt *rlwe.Ciphertext,
) (*rlwe.Ciphertext, error) {
	if err := a.cfg.validate(); err != nil {
		return nil, err
	}
	if len(key.S) != a.cfg.Lambda/2 {
		return nil, fmt.Errorf("authenticator: Key.S size=%d does not match Lambda/2=%d", len(key.S), a.cfg.Lambda/2)
	}
	if rot == nil {
		return nil, fmt.Errorf("authenticator: rotator is nil")
	}
	eval := rot.Inner()
	if err := a.validateGaloisKeys(eval); err != nil {
		return nil, err
	}

	// Step 1: mask to slot 0. We pass the cached one-hot []float64 directly
	// to eval.Mul, which auto-picks pt.Scale = q_level_modulus so the
	// quantization is well-defined (a scale-1 plaintext for [1,0,..] is
	// unrepresentable — see the package doc on Authenticator). Output scale
	// is ct.Scale * q_level_modulus; we propagate the same scale into ct_v.
	ctM, err := eval.MulNew(resultCt, a.oneHot)
	if err != nil {
		return nil, fmt.Errorf("authenticator: mask result_ct: %w", err)
	}

	// Step 4: rotate-and-sum over [0, Lambda) \ S.
	//
	// Per docs/DESIGN.md §`Auth`, the goal is "Rot(ct_m, j) has m only at
	// slot j". Lattigo's `RotateNew(ct, k)` is left-rotation: slot i ←
	// slot (i+k) mod (N/2). To place ct_m's slot 0 at slot j we therefore
	// rotate by -j (right-rotation by j). The chain rotator decomposes
	// `|j|` into `popcount(|j|)` binary atoms and applies them one at a
	// time — Auth itself stays unaware of the chaining.
	inS := sInSet(key.S, a.cfg.Lambda)
	var ctMRep *rlwe.Ciphertext
	for j := 0; j < a.cfg.Lambda; j++ {
		if inS[j] {
			continue
		}
		var term *rlwe.Ciphertext
		if j == 0 {
			term = ctM.CopyNew()
		} else {
			term, err = rot.RotateNew(ctM, -j)
			if err != nil {
				return nil, fmt.Errorf("authenticator: rotate by -%d: %w", j, err)
			}
		}
		if ctMRep == nil {
			ctMRep = term
			continue
		}
		if err = eval.Add(ctMRep, term, ctMRep); err != nil {
			return nil, fmt.Errorf("authenticator: add rotation -%d: %w", j, err)
		}
	}
	if ctMRep == nil {
		return nil, fmt.Errorf("authenticator: rotation set [0, Lambda) \\ S is empty")
	}

	// Step 3 (encoded as []float64 below): build v with each slot's float
	// value = v_raw[i] / Δ. The encoder multiplies by pt.Scale; we set
	// pt.Scale = ctMRep.Scale so that ct_v matches ctMRep's scale and can
	// be added. After joint decryption and decode (which divides by
	// ct_M.Scale), slots in S come out as v_raw[i]/Δ and slots in
	// [0, λ)\S come out as m — exactly what Ver expects.
	vScaled, err := deriveV(key.SeedF, a.cfg.Lambda, key.S, a.q0Half, a.deltaF64)
	if err != nil {
		return nil, fmt.Errorf("authenticator: derive v: %w", err)
	}

	// Step 5: encrypt v at the same scale as ct_m^Rep so the subsequent
	// addition is well-formed. ckks.NewPlaintext defaults to params.DefaultScale();
	// we override to ctMRep.Scale.
	ptV := ckks.NewPlaintext(a.params, ctMRep.Level())
	ptV.Scale = ctMRep.Scale
	if err = a.encoder.Encode(vScaled, ptV); err != nil {
		return nil, fmt.Errorf("authenticator: encode v: %w", err)
	}
	ctV, err := encryptor.EncryptNew(ptV)
	if err != nil {
		return nil, fmt.Errorf("authenticator: encrypt v: %w", err)
	}

	// Step 6: ct_M = ct_m^Rep + ct_v.
	ctMReturn, err := eval.AddNew(ctMRep, ctV)
	if err != nil {
		return nil, fmt.Errorf("authenticator: add ct_v: %w", err)
	}
	return ctMReturn, nil
}

// validateGaloisKeys checks that `eval` carries Galois keys for every
// auth atom in `{1, 2, 4, ..., 2^k}` with `2^k < Lambda`. The chain
// rotator decomposes any `j ∈ [1, Lambda)` into a sum of these atoms via
// binary expansion; missing an atom means some `j` cannot be chain-
// rotated. The required Galois element per atom is
// `params.GaloisElement(-atom)` because Auth issues `RotateNew(ct, -j)`.
func (a *Authenticator) validateGaloisKeys(eval *ckks.Evaluator) error {
	if eval == nil || eval.EvaluationKeySet == nil {
		return fmt.Errorf("authenticator: evaluator missing EvaluationKeySet")
	}

	carried := map[uint64]bool{}
	for _, galEl := range eval.EvaluationKeySet.GetGaloisKeysList() {
		carried[galEl] = true
	}
	var missing []int
	for atom := 1; atom < a.cfg.Lambda; atom <<= 1 {
		wantGalEl := a.params.GaloisElement(-atom)
		if !carried[wantGalEl] {
			missing = append(missing, atom)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("authenticator: evaluator missing Galois keys for auth atoms %v (need GaloisElement(-atom) for atom ∈ powers-of-two < %d)", missing, a.cfg.Lambda)
	}
	return nil
}

// sInSet returns a Lambda-sized boolean mask: inS[i] is true iff i ∈ S.
func sInSet(s []int, lambda int) []bool {
	out := make([]bool, lambda)
	for _, idx := range s {
		if idx >= 0 && idx < lambda {
			out[idx] = true
		}
	}
	return out
}

// deriveV is the deterministic PRG that produces v from key.SeedF. It is
// shared between Auth and Ver so the byte-for-byte sequence matches.
//
// Output layout: a []float64 of length params.MaxSlots(), with the first
// Lambda slots populated and the rest zero. For i ∈ S, v_raw[i] is sampled
// uniformly from (-q0Half, q0Half) (signed integer fitting in a big.Int);
// the returned slice carries v_raw[i] / Δ so the encoder (which multiplies
// by pt.Scale = Δ) places v_raw[i] in the underlying ring coefficient.
// For i ∉ S, v_raw[i] = 0.
//
// Total slot length is params.MaxSlots() so the encoder's slot count
// matches the ciphertext being added to in Auth step 6.
func deriveV(seed [32]byte, lambda int, s []int, q0Half *big.Int, delta float64) ([]float64, error) {
	// Use AES-CTR as a deterministic PRG keyed by seed. Counter is 16-byte
	// little-endian. Each draw consumes one block; we then reduce to a
	// signed integer in (-q0Half, q0Half) by computing `mod (2*q0Half + 1) - q0Half`
	// against the big.Int via rejection on a fixed byte-length window.
	if lambda <= 0 {
		return nil, fmt.Errorf("authenticator: deriveV needs Lambda > 0")
	}
	prg, err := newDeterministicPRG(seed)
	if err != nil {
		return nil, err
	}

	inS := sInSet(s, lambda)
	out := make([]float64, lambda)

	// 2*q0Half + 1 is the size of the symmetric interval [-q0Half, q0Half].
	// We sample r in [0, span) and map to r - q0Half. Note q0Half = floor(Q_0/2),
	// so the interval is symmetric and within the design's stated bound.
	span := new(big.Int).Lsh(q0Half, 1)
	span.Add(span, big.NewInt(1))
	byteLen := (span.BitLen() + 7) / 8
	if byteLen <= 0 {
		byteLen = 1
	}
	// Largest multiple of span that fits in 2^(8*byteLen) — used for rejection.
	maxRange := new(big.Int).Lsh(big.NewInt(1), uint(8*byteLen))
	limit := new(big.Int).Sub(maxRange, new(big.Int).Mod(maxRange, span))

	for i := 0; i < lambda; i++ {
		if !inS[i] {
			out[i] = 0
			continue
		}
		v, err := prg.sampleBoundedSigned(span, limit, q0Half, byteLen)
		if err != nil {
			return nil, fmt.Errorf("authenticator: sample v[%d]: %w", i, err)
		}
		// Convert signed big.Int to float64 (q0HalfF64 bounds the magnitude
		// at < 2^54 for typical LogQ[0]=55, so float64 has just
		// enough precision; the design accepts the rounding because Ver's
		// ε≈2^20 dominates the encoder's discretisation error).
		vF, _ := new(big.Float).SetInt(v).Float64()
		out[i] = vF / delta
	}
	return out, nil
}

// deterministicPRG wraps AES-CTR keyed by seedF (first 16 bytes used).
type deterministicPRG struct {
	stream cipher.Stream
	zero   []byte // ciphered-zero output buffer, allocated once per call
}

func newDeterministicPRG(seed [32]byte) (*deterministicPRG, error) {
	// Use the first 16 bytes as AES-128 key; the next 16 bytes as the IV.
	// Both are derived from the 32-byte SeedF deterministically.
	block, err := aes.NewCipher(seed[:16])
	if err != nil {
		return nil, fmt.Errorf("authenticator: AES init: %w", err)
	}
	var iv [16]byte
	copy(iv[:], seed[16:])
	return &deterministicPRG{
		stream: cipher.NewCTR(block, iv[:]),
	}, nil
}

func (p *deterministicPRG) read(buf []byte) {
	// XOR a zero buffer with the CTR keystream — gives us the raw PRG output.
	if len(p.zero) < len(buf) {
		p.zero = make([]byte, len(buf))
	} else {
		for i := range p.zero[:len(buf)] {
			p.zero[i] = 0
		}
	}
	p.stream.XORKeyStream(buf, p.zero[:len(buf)])
}

// sampleBoundedSigned returns r - q0Half where r is uniform in [0, span).
// Uses big-endian byte reads with rejection sampling against `limit` (the
// largest multiple of span ≤ 2^(8*byteLen)).
func (p *deterministicPRG) sampleBoundedSigned(span, limit, q0Half *big.Int, byteLen int) (*big.Int, error) {
	buf := make([]byte, byteLen)
	for tries := 0; tries < 1000; tries++ {
		p.read(buf)
		r := new(big.Int).SetBytes(buf)
		if r.Cmp(limit) < 0 {
			r.Mod(r, span)
			r.Sub(r, q0Half)
			return r, nil
		}
	}
	return nil, fmt.Errorf("authenticator: rejection sampler exhausted retries")
}

// VRawValues exposes the deterministic verification values v[i] (in
// scaled-message space — not divided by Δ) for benchmarking and test
// harnesses that need to synthesize the exact plaintext Ver expects
// without driving a full FHE protocol round. Returns one entry per
// i ∈ key.S. Honest joint decryption produces P[i] = v[i]/Δ in S slots,
// so a caller can rebuild a Ver-accepting plaintext as:
//
//	for i ∈ key.S:           plaintext[i] = vRaw[i] / a.params.DefaultScale().Float64()
//	for i ∈ [0, Λ) \ key.S:  plaintext[i] = m (the chosen message)
//
// See cmd/ppiav-cli/steps.go for the `verify-mac` subcommand's usage.
func (a *Authenticator) VRawValues(key Key) (map[int]float64, error) {
	if err := a.cfg.validate(); err != nil {
		return nil, err
	}
	if len(key.S) != a.cfg.Lambda/2 {
		return nil, fmt.Errorf("authenticator: Key.S size=%d does not match Lambda/2=%d", len(key.S), a.cfg.Lambda/2)
	}
	return vRawValues(key.SeedF, a.cfg.Lambda, key.S, a.q0Half)
}

// vRawValuesForVerification re-derives the raw (scaled-space) v[i] values
// from the seed; used by Ver to compare against P[i]·Δ. It returns the
// untyped float64 v[i] (i.e. NOT divided by Δ), one entry per i ∈ S.
func vRawValues(seed [32]byte, lambda int, s []int, q0Half *big.Int) (map[int]float64, error) {
	if lambda <= 0 {
		return nil, fmt.Errorf("authenticator: vRawValues needs Lambda > 0")
	}
	prg, err := newDeterministicPRG(seed)
	if err != nil {
		return nil, err
	}
	inS := sInSet(s, lambda)

	span := new(big.Int).Lsh(q0Half, 1)
	span.Add(span, big.NewInt(1))
	byteLen := (span.BitLen() + 7) / 8
	if byteLen <= 0 {
		byteLen = 1
	}
	maxRange := new(big.Int).Lsh(big.NewInt(1), uint(8*byteLen))
	limit := new(big.Int).Sub(maxRange, new(big.Int).Mod(maxRange, span))

	out := map[int]float64{}
	for i := 0; i < lambda; i++ {
		if !inS[i] {
			continue
		}
		v, err := prg.sampleBoundedSigned(span, limit, q0Half, byteLen)
		if err != nil {
			return nil, fmt.Errorf("authenticator: re-sample v[%d]: %w", i, err)
		}
		vF, _ := new(big.Float).SetInt(v).Float64()
		out[i] = vF
	}
	return out, nil
}

