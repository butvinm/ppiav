// Package authchain provides the binary-decompose chain-rotation wrapper
// over a `*ckks.Evaluator` that the MPD-Auth `Auth` step uses to rotate
// ciphertexts when only the base-2 atom-set Galois keys are present.
//
// Background. Phase 4's wire-transport optimization splits the canonical
// `[1, Lambda)` rotation set into a small **eval-level base-2 atom set**
// (`{1, 2, 4, ..., 2^k}` for k = floor(log2(Lambda-1))) carried as raw
// `*rlwe.GaloisKey`s. Auth's `RotateNew(ct, -j)` for arbitrary
// `j ∈ [1, Lambda)` is realised by decomposing `|j|` into binary atoms
// (`popcount(j)` atoms) and chaining the negative-direction rotations one
// atom at a time. No hierarchical key derivation is involved — this is
// purely arithmetic on top of an unchanged `*ckks.Evaluator`.
//
// This package is intentionally tiny: a struct holding the inner
// evaluator + the auth-atom int list, plus a `RotateNew(ct, j)` that walks
// the binary decomposition of `|j|`. No LLKN parameters, no hierkeys
// imports. The auth-atom keys are already final, aggregated
// `*rlwe.GaloisKey`s produced by VAgent's multi-party handshake — there is
// nothing to derive at session open.
package authchain

import (
	"fmt"
	"math/bits"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// Evaluator wraps a `*ckks.Evaluator` and exposes a chain-rotation API.
// The inner evaluator is built once over `rlwe.NewMemEvaluationKeySet(rlk,
// gksAuth...)`. Non-rotation operations (Mul, Add, AddNew, ...) are
// available via `Inner()`.
type Evaluator struct {
	inner *ckks.Evaluator
	atoms []int
}

// New constructs a chain-rotation evaluator from the supplied CKKS params,
// relinearization key, and the auth-atom Galois keys (one per ascending
// atom in `Params.AuthAtoms()`). Atom ints are taken as input (cheaper
// than recovering them from `gksAuth` via `SolveDiscreteLogGaloisElement`)
// and stored for later use by `RotateNew`.
//
// The function does NOT validate that `len(atoms) == len(gksAuth)` or
// that the Galois elements line up — VAgent owns that check before
// calling. The constructor is O(1) modulo Lattigo's evaluator wiring.
func New(
	params ckks.Parameters,
	rlk *rlwe.RelinearizationKey,
	gksAuth []*rlwe.GaloisKey,
	atoms []int,
) (*Evaluator, error) {
	if rlk == nil {
		return nil, fmt.Errorf("authchain: rlk is nil")
	}
	if len(atoms) == 0 {
		return nil, fmt.Errorf("authchain: atoms is empty")
	}
	if len(atoms) != len(gksAuth) {
		return nil, fmt.Errorf("authchain: atom count %d != gksAuth count %d", len(atoms), len(gksAuth))
	}
	evk := rlwe.NewMemEvaluationKeySet(rlk, gksAuth...)
	atomsCopy := make([]int, len(atoms))
	copy(atomsCopy, atoms)
	return &Evaluator{
		inner: ckks.NewEvaluator(params, evk),
		atoms: atomsCopy,
	}, nil
}

// Inner exposes the underlying `*ckks.Evaluator` for non-rotation
// operations Auth uses (`MulNew`, `Add`, `AddNew`, ...).
func (e *Evaluator) Inner() *ckks.Evaluator { return e.inner }

// Atoms returns a copy of the auth-atom int list the evaluator was
// constructed against. Read-only; callers must not mutate.
func (e *Evaluator) Atoms() []int {
	out := make([]int, len(e.atoms))
	copy(out, e.atoms)
	return out
}

// Decompose returns the binary expansion of `|j|` as a list of powers of
// two (ascending). `chain length == popcount(|j|)`. The result is a subset
// of the auth-atom set when `|j| < 2^len(atoms)`; the function does NOT
// validate that constraint — callers should ensure `|j| < Lambda` per the
// MPD-Auth contract.
//
// Example: Decompose(13) == {1, 4, 8} (1 + 4 + 8 = 13, popcount=3).
func Decompose(j int) []int {
	if j < 0 {
		j = -j
	}
	if j == 0 {
		return nil
	}
	out := make([]int, 0, bits.UintSize)
	for k := 0; j > 0; k++ {
		if j&1 == 1 {
			out = append(out, 1<<k)
		}
		j >>= 1
	}
	return out
}

// RotateNew rotates `ct` by `j` slots (Lattigo convention: slot i ←
// slot (i+j) mod (N/2)) by chaining the auth-atom Galois keys. The
// implementation decomposes `|j|` into binary atoms and applies
// `inner.RotateNew(cur, sign*atom)` for each atom, preserving the sign of
// `j`. Output chain length == `popcount(|j|)`.
//
// `j == 0` short-circuits to `ct.CopyNew()` — Lattigo's `RotateNew(ct, 0)`
// also returns a copy, so this preserves the identity case.
//
// Returns an error when an atom's Galois key is missing from the inner
// evaluator's key set (surfaces as the underlying `RotateNew`'s error).
func (e *Evaluator) RotateNew(ct *rlwe.Ciphertext, j int) (*rlwe.Ciphertext, error) {
	if ct == nil {
		return nil, fmt.Errorf("authchain: ct is nil")
	}
	if j == 0 {
		return ct.CopyNew(), nil
	}
	sign := 1
	if j < 0 {
		sign = -1
	}
	cur := ct
	for _, atom := range Decompose(j) {
		next, err := e.inner.RotateNew(cur, sign*atom)
		if err != nil {
			return nil, fmt.Errorf("authchain: chain rotate by %d (atom %d, sign %d): %w", j, atom, sign, err)
		}
		cur = next
	}
	return cur, nil
}
