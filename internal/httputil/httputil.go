// Package httputil holds the small JSON-error helpers shared by the
// vservice / vagent / rservice HTTP handlers. Centralised here so the
// error wire shape stays uniform across services.
package httputil

import (
	"encoding/json"
	"net/http"
)

// ErrorBody is the wire shape of all 4xx/5xx JSON responses.
type ErrorBody struct {
	Error string `json:"error"`
}

// WriteJSON marshals body and writes it with `application/json` and the
// given status. On marshal failure falls back to a plain text 500 —
// matches the previous per-package behavior.
func WriteJSON(w http.ResponseWriter, status int, body any) {
	data, err := json.Marshal(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(data)
}

// WriteError writes a JSON error envelope with the given status.
func WriteError(w http.ResponseWriter, status int, msg string) {
	WriteJSON(w, status, ErrorBody{Error: msg})
}

// Per-route body-size caps. Picked to be comfortably above the largest
// payload each route legitimately carries while still bounding a DoS POST.
// The big ones are the CKKS share/key blobs at LogN=16:
//   - VClientGaloisShares: per-atom shares for the single MasterAtoms
//     set (top level) — sized for the LogN=16 lattigo-hierkeys
//     master-atom wire payload.
//   - InferEvalKeys: aggregated RLK (eval) + PKTop (top) + the gksMaster
//     bundle (8 top-level MasterKeys at LogN=16).
//
// We split the cap by route shape so a concurrent attacker can't bank
// the same allocation on a small-share endpoint. DESIGN.md says rate
// limiting is out of scope, but per-route caps cost nothing and keep
// the worst-case allocation bounded to what the protocol actually
// demands.
const (
	// MaxJSONBody is the cap for JSON control endpoints (sessions,
	// params, callback, redirect-reply).
	MaxJSONBody int64 = 64 * 1024

	// MaxShareBody covers single-share octet-stream endpoints (pk-share,
	// rlk/round1, rlk/round2, partial-decryption). The largest of these
	// at LogN=16 is the RLK round-1 share — a GadgetCiphertext, ~66 MiB
	// (BaseRNSDecomp × 2 polynomials × (Qi+Pi) limbs × N coefficients).
	// 128 MiB gives ~2× headroom; smaller per-share endpoints
	// (pk-share/rlk-round2/partial-decryption) cap the same allocation.
	MaxShareBody int64 = 128 * 1024 * 1024

	// MaxGksSharesBody covers the aggregated Galois-shares blob
	// (gks-shares): MasterShares (top level, 8 atoms at LogN=16).
	// Top-level shares are larger than eval-level (extra P-prime limbs).
	// Sized to ≥1 GiB to keep margin for the LogN=16 master-atom
	// payload, which lands in the ~400-500 MiB range by estimate.
	MaxGksSharesBody int64 = 2 * 1024 * 1024 * 1024

	// MaxEvalKeysBody covers the InferEvalKeys forwarded to VService
	// (RLK + PKTop + GKSMaster) and the encrypted image. Sized for
	// LogN=16 lattigo-hierkeys: at base-4 the master atom set is 8 keys,
	// each ~233 MiB (top-level GaloisKey with extra P primes), totalling
	// ~1.86 GiB; RLK + PKTop push the body past 1.93 GiB. 3 GiB gives a
	// safety margin over the LogN=16 production target.
	MaxEvalKeysBody int64 = 3 * 1024 * 1024 * 1024
)
