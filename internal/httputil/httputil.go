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
//   - VClientGaloisKeyShare: ~Lambda shares × per-rotation share size
//   - InferEvalKeys: aggregated RLK + per-rotation GaloisKey
//
// We split the cap by route shape so a concurrent attacker can't bank
// the same 1 GiB allocation on a small-share endpoint. The 1 GiB ceiling
// is preserved only for routes that legitimately need it (eval-keys, the
// encrypted image, and the aggregated Galois shares payload at LogN=16
// × Lambda=128). DESIGN.md says rate limiting is out of scope, but
// per-route caps cost nothing and keep the worst-case allocation bounded
// to what the protocol actually demands. Phase-4 hierkeys cuts the GKS
// down to a single master and will let us tighten the largest cap.
const (
	// MaxJSONBody is the cap for JSON control endpoints (sessions,
	// params, callback, redirect-reply).
	MaxJSONBody int64 = 64 * 1024

	// MaxShareBody covers single-share octet-stream endpoints whose
	// payload is one CKKS share or one key-switch share (pk-share,
	// rlk/round1, rlk/round2, partial-decryption). Sized for LogN=16
	// with a comfortable head-room over the largest per-share encoding.
	MaxShareBody int64 = 16 * 1024 * 1024

	// MaxGksSharesBody covers the aggregated Galois-share blob
	// (gks-shares): Lambda × per-rotation share. At LogN=16 × Lambda=128
	// this stays under 512 MiB with margin.
	MaxGksSharesBody int64 = 512 * 1024 * 1024

	// MaxEvalKeysBody covers the largest octet-stream payloads — the
	// aggregated eval-keys forwarded to VService and the encrypted image
	// ciphertext. Sized for LogN=16 × Lambda=128 (GaloisKey set
	// dominates).
	MaxEvalKeysBody int64 = 1024 * 1024 * 1024

	// MaxCiphertextBody is an alias kept for back-compat with callers
	// that haven't been migrated to the per-route caps yet. New code
	// should use one of MaxShareBody / MaxGksSharesBody / MaxEvalKeysBody
	// instead.
	MaxCiphertextBody int64 = MaxEvalKeysBody
)
