// Package protocol owns the on-wire data types and the session-scoped CRS
// helpers that VClient and VAgent draw from in lockstep during the
// collaborative key-generation handshake.
//
// CRS canonical draw order
//
// VClient and VAgent both seed an identical `sampling.KeyedPRNG` from the
// session id (see `NewSessionCRS`) and consume it in the following fixed
// order. Identical ordering is part of the protocol contract: any drift
// shifts every subsequent CRP draw out of alignment between the two
// parties and the aggregated keys silently mismatch.
//
//  1. `multiparty.NewPublicKeyGenProtocol(params.CKKS).SampleCRP(crs)`
//     — pk_eval (eval-level public key, used for encryption).
//  2. `multiparty.NewPublicKeyGenProtocol(params.LLKN.Top()).SampleCRP(crs)`
//     — pk_top (top-level public key, fed into `hierkeys.PubToRot` to
//     seed both VAgent's and VService's `LevelExpansion`).
//  3. `multiparty.NewRelinearizationKeyGenProtocol(params.CKKS).SampleCRP(crs, evkParams)`
//     — single CRP reused for both RLK rounds (Lattigo's protocol shape).
//  4. For each atom in `params.MasterAtoms()` (ascending):
//     `multiparty.NewGaloisKeyGenProtocol(params.LLKN.Top()).SampleCRP(crs, evkParams)`
//     — top-level Galois CRP for the SINGLE master atom set consumed by
//     both VAgent (auth-atom derivation) and VService (infer-atom
//     derivation).
//
// Steps 1 and 3 are eval-level and byte-for-byte identical to the
// pre-hierkeys protocol; steps 2 and 4 are introduced by the
// lattigo-hierkeys split for the LLKN hierarchy. There is only one wire
// atom set (`MasterAtoms()`): the auth-atom and infer-atom rotation keys
// are derived locally by VAgent and VService respectively from the
// shared master atom set via `hierkeys.LevelExpansion`.
// See `docs/DESIGN.md` for the level-dimension rationale.
package protocol

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

// crsDomain is the KDF domain separator for the session-scoped CRS seed.
const crsDomain = "ppiav-crs/v1"

// NewSessionCRS returns a `sampling.KeyedPRNG` seeded deterministically
// from the session id. Both VClient and VAgent construct it identically;
// no CRS material crosses the wire. See docs/DESIGN.md §`internal/protocol`.
//
// Step 4 of the canonical CRP draw order iterates `Params.MasterAtoms()`
// (see package doc above).
func NewSessionCRS(sid SessionID) (*sampling.KeyedPRNG, error) {
	prng, err := sampling.NewKeyedPRNG([]byte(crsDomain + "|" + string(sid)))
	if err != nil {
		return nil, fmt.Errorf("protocol: build session CRS: %w", err)
	}
	return prng, nil
}
