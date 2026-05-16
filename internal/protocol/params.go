package protocol

import (
	"fmt"
	"math"
	"sort"

	"github.com/butvinm/ppiav/internal/authenticator"
	hierkeys "github.com/butvinm/lattigo-hierkeys"
	"github.com/butvinm/lattigo-hierkeys/llkn"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// DefaultFloodSigma is the discrete-Gaussian flooding σ applied by VClient
// during partial decryption (and the value `Defaults()` / `LoadOrionParams()`
// both stamp into Params.FloodSigma). See docs/DESIGN.md
// §`internal/vclient` and `internal/vclient/partial_decrypt.go`.
var DefaultFloodSigma = math.Exp2(16)

// DefaultLLKNLogPHK is the master-level auxiliary prime bit-size schedule
// for the LLKN 2-level scheme used by the inference-side hierarchical key
// derivation. Eleven 55-bit primes match the `LogN16_D15_P6` scenario in
// lattigo-hierkeys (`~/Dev/lattigo-hierkeys/internal/testutil/scenarios.go`).
var DefaultLLKNLogPHK = []int{55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55}

// DefaultLLKNBase is the radix used to decompose target rotations into the
// master atom set. Base-4 keeps the atom count at 8 across the LogN=16
// half-slot range (= `{1,4,16,...,16384}`).
const DefaultLLKNBase = 4

// Params bundles the CKKS parameters, MPD-Auth configuration, and the
// VClient flooding sigma used during partial decryption.
//
// Rotation labels carry a SIGN: a label `j` (positive or negative) means
// the keygen handshake must mint a Galois key for element
// `params.CKKS.GaloisElement(-j)`. The authenticator emits positive labels
// `j ∈ [1, Lambda)` because Auth's step 4 calls `RotateNew(ct, -j)`
// (right-rotation by j → `GaloisElement(-j)`). Orion's compiled circuit
// calls `RotateNew(ct, +k)` for positive `k`, which needs
// `GaloisElement(+k)`; to make a single keygen path produce that, the
// Orion loader stores those labels as `-k` so the `GaloisElement(-(-k))`
// path lands on `GaloisElement(+k)`. Identity (label 0) needs no Galois
// key — Lattigo short-circuits `Automorphism(galEl=1)` — and is dropped.
//
// `ExtraRotationIndices` carries the inference-circuit labels (already in
// the signed-label convention above) on top of the authenticator's
// canonical positive set. The `Defaults()` caller leaves it nil; the
// Orion path populates it via `vservice.NewWithOrion`.
// `RotationIndices()` returns the sorted union; VClient/VAgent iterate
// that union when running the collaborative GaloisKeyGen handshake.
//
// `InputLevel` is the ciphertext level at which `EncryptImage` produces
// the encrypted input. The synthetic-x² path leaves it zero, which
// `EncryptImage` interprets as "max level" — there is no compiled model to
// constrain the budget. The Orion path sets it from the manifest so the
// inference circuit runs at the level it was compiled for.
type Params struct {
	CKKS                 ckks.Parameters
	LLKN                 llkn.Parameters
	LLKNBase             int
	Authenticator        authenticator.Config
	FloodSigma           float64
	ExtraRotationIndices []int
	InputLevel           int
}

// Defaults returns the synthetic-x² parameter set from docs/DESIGN.md
// §`Implementation/Layout`. LogN=16, LogQ=[55]+[40]×15, LogP=[55]×6,
// LogDefaultScale=40, RingType=Standard. FloodSigma=2^16. No extra
// rotation indices; `RotationIndices()` returns the canonical
// `[1, Lambda)` set. InputLevel=0 makes `EncryptImage` build the
// plaintext at MaxLevel (no compiled circuit to constrain the budget).
func Defaults() (Params, error) {
	logQ := make([]int, 1+15)
	logQ[0] = 55
	for i := 1; i < len(logQ); i++ {
		logQ[i] = 40
	}
	logP := make([]int, 6)
	for i := range logP {
		logP[i] = 55
	}
	params, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            16,
		LogQ:            logQ,
		LogP:            logP,
		LogDefaultScale: 40,
		RingType:        ring.Standard,
	})
	if err != nil {
		return Params{}, fmt.Errorf("protocol: build CKKS parameters: %w", err)
	}
	llknParams, err := BuildLLKNParams(params)
	if err != nil {
		return Params{}, err
	}
	return Params{
		CKKS:          params,
		LLKN:          llknParams,
		LLKNBase:      DefaultLLKNBase,
		Authenticator: authenticator.DefaultConfig(),
		FloodSigma:    DefaultFloodSigma,
	}, nil
}

// BuildLLKNParams constructs the LLKN 2-level hierarchy on top of the
// supplied eval-level CKKS parameters using `DefaultLLKNLogPHK`. The
// hierarchy does not change the eval-level circuit, so both `Defaults()`
// and `LoadOrionParams()` stamp the same schedule. The CLI's `loadParams`
// and `vservice.NewWithOrion` / `NewWithState` use it to re-derive the
// hierarchy after a CKKS override (the persisted CKKS may differ from
// the default — re-stamping ensures the hierarchy matches).
func BuildLLKNParams(p ckks.Parameters) (llkn.Parameters, error) {
	out, err := llkn.NewParameters(p.Parameters, [][]int{DefaultLLKNLogPHK})
	if err != nil {
		return llkn.Parameters{}, fmt.Errorf("protocol: build LLKN parameters: %w", err)
	}
	return out, nil
}

// AuthAtoms returns the ascending base-2 atom set used by VAgent's
// authenticator chain-rotation. For `Authenticator.Lambda = 128` the set
// is `{1, 2, 4, 8, 16, 32, 64}` — i.e. powers of two strictly less than
// `Lambda`. Auth rotates by `-j` for `j ∈ [1, Lambda)`; each `j` is
// decomposed via `popcount` and the chain calls
// `GaloisElement(-atom)` per bit set. The set is **eval-level** and lives
// outside the lattigo-hierkeys hierarchy — the keys minted from these
// atoms are raw `*rlwe.GaloisKey`s, used directly by `*ckks.Evaluator`.
func (p Params) AuthAtoms() []int {
	if p.Authenticator.Lambda <= 1 {
		return nil
	}
	max := p.Authenticator.Lambda - 1
	out := make([]int, 0, 8)
	for a := 1; a <= max; a <<= 1 {
		out = append(out, a)
	}
	return out
}

// InferAtoms returns the ascending base-`LLKNBase` master atom set used
// by VService's inference-side hierarchical key derivation. At LogN=16
// with `LLKNBase=4` the set is `{1, 4, 16, 64, 256, 1024, 4096, 16384}`
// (8 atoms across the half-slot range). These atoms are emitted with
// **positive** Galois elements per the hierkeys convention and live at
// the **top** level of the LLKN hierarchy. VService runs
// `hierkeys.LevelExpansion` over this set to derive the full per-target
// inference key bundle locally.
//
// `LLKNBase < 2` is invalid and panics — every production caller stamps
// `LLKNBase: DefaultLLKNBase` via `Defaults()` / `LoadOrionParams()`, so
// a zero value indicates a constructed-from-scratch params bug rather
// than something to paper over with a fallback.
func (p Params) InferAtoms() []int {
	if p.LLKNBase < 2 {
		panic(fmt.Sprintf("protocol: Params.InferAtoms: LLKNBase=%d < 2 (set LLKNBase: DefaultLLKNBase)", p.LLKNBase))
	}
	return hierkeys.MasterRotationsForBase(p.LLKNBase, p.CKKS.MaxSlots())
}

// ProjectSKToEval projects the multi-party top-level secret-key share
// down to eval level. The projection is linear, so each party can derive
// `sk_eval = project(sk_top)` from their own `sk_top` without
// coordination, and the collective eval-level secret is unchanged.
// Eval-level protocol calls (RLK gen, KeySwitch / partial-decrypt, and
// the eval-level branch of the dual PK gen + auth-atom Galois gen) all
// consume the projected key.
func (p Params) ProjectSKToEval(skTop *rlwe.SecretKey) (*rlwe.SecretKey, error) {
	out, err := p.LLKN.ProjectToEvalKey(skTop)
	if err != nil {
		return nil, fmt.Errorf("protocol: project sk_top to sk_eval: %w", err)
	}
	return out, nil
}

// RotationIndices returns the sorted-ascending union of the canonical
// authenticator rotation set `[1, Lambda)` and any `ExtraRotationIndices`
// pulled from the inference-circuit manifest. Duplicates are removed.
// Label 0 (identity) is dropped — Lattigo short-circuits
// `Automorphism(galEl=1)` so no Galois key is required. Negative labels
// are kept verbatim: see the `Params` doc for the signed-label convention
// (Orion stores `-k_orion` so the keygen's `GaloisElement(-label)` lands
// on `GaloisElement(+k_orion)`).
//
// VClient and VAgent iterate this slice in lockstep when running the
// collaborative GaloisKeyGen handshake; identical inputs guarantee the
// same CRP draw order on both sides.
func (p Params) RotationIndices() []int {
	seen := map[int]struct{}{}
	for j := 1; j < p.Authenticator.Lambda; j++ {
		seen[j] = struct{}{}
	}
	for _, j := range p.ExtraRotationIndices {
		if j == 0 {
			continue
		}
		seen[j] = struct{}{}
	}
	out := make([]int, 0, len(seen))
	for j := range seen {
		out = append(out, j)
	}
	sort.Ints(out)
	return out
}
