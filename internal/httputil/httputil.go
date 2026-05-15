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
// 64 MiB covers Phase-3 LogN=16 with Lambda<=16; Phase-4 hierkeys cuts
// the GKS down to a single master.
const (
	// MaxJSONBody is the cap for JSON control endpoints (sessions,
	// params, callback, redirect-reply).
	MaxJSONBody int64 = 64 * 1024

	// MaxCiphertextBody is the cap for octet-stream ciphertext/share
	// endpoints (image, pk-share, rlk/*, gks-shares, eval-keys,
	// partial-decryption).
	MaxCiphertextBody int64 = 64 * 1024 * 1024
)
