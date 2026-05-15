package rservice

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/butvinm/ppiav/internal/protocol"
)

// Server wraps a *Service with the HTTP handlers RService exposes:
//
//	GET  /protected               (cookie-gated; stub HTML for Task 2)
//	POST /api/callback/:sid       (VerdictNotification from VAgent)
//
// Per docs/DESIGN.md §`Components`, sid is carried in the URL path. The
// callback payload is the `VerdictNotification` wire struct as JSON.
//
// NOTE: full Stage-1 server-to-server flow (RService → VAgent
// POST /sessions → set cookie + 302 to VAgent /verify?sid=) is implemented
// in Task 18. Task 2 returns Unknown verdict (HTTP 403) for missing sid.
type Server struct {
	svc       *Service
	addr      string
	vagentURL string
	mux       *http.ServeMux
}

// NewServer wires a Server around `svc`. `vagentURL` is stored for the
// Stage-1 redirect implemented in Task 18; Task 2's `GET /protected` does
// not use it yet but the field is declared up front to keep the
// constructor stable. The constructor is named `NewServer` rather than
// `New` to avoid shadowing the existing `rservice.New()` Service
// constructor — same pattern as `vservice.NewServer`.
func NewServer(svc *Service, vagentURL, addr string) *Server {
	s := &Server{svc: svc, addr: addr, vagentURL: vagentURL, mux: http.NewServeMux()}
	s.register()
	return s
}

// Handler exposes the mux for composition with httptest.NewServer.
func (s *Server) Handler() http.Handler { return s.mux }

// ListenAndServe boots an http.Server on s.addr.
func (s *Server) ListenAndServe() error {
	srv := &http.Server{Addr: s.addr, Handler: s.mux}
	return srv.ListenAndServe()
}

func (s *Server) register() {
	s.mux.HandleFunc("/protected", s.handleProtected)
	s.mux.HandleFunc("/api/callback/", s.handleCallback)
}

func (s *Server) handleProtected(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	c, err := r.Cookie("sid")
	if err != nil || c.Value == "" {
		// Task-2 stub: no Stage-1 redirect yet. Task 18 wires the
		// server-to-server VAgent flow here.
		writeHTML(w, http.StatusForbidden, protectedPage("", protocol.VerdictUnknown))
		return
	}
	sid := protocol.SessionID(c.Value)
	verdict := s.svc.CheckAccess(sid)
	status := http.StatusOK
	if verdict != protocol.VerdictAccept {
		status = http.StatusForbidden
	}
	writeHTML(w, status, protectedPage(sid, verdict))
}

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/callback/")
	if rest == "" || strings.Contains(rest, "/") {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	sid := protocol.SessionID(rest)

	var notif protocol.VerdictNotification
	if err := json.NewDecoder(r.Body).Decode(&notif); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("decode VerdictNotification: %s", err))
		return
	}
	if err := s.svc.AcceptVerdict(sid, notif.Verdict); err != nil {
		// AcceptVerdict only errors on VerdictUnknown — a wire-shape
		// violation per DESIGN.md (callback never delivers Unknown).
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusOK)
}

// protectedPage renders a minimal HTML page reflecting the verdict for
// the given sid. Task 16/18 will replace this with the embedded RClient
// SPA; the stub keeps the cookie-gated read path testable.
func protectedPage(sid protocol.SessionID, v protocol.Verdict) string {
	body := fmt.Sprintf(
		`<!doctype html><html><head><title>RService</title></head><body><h1>Protected resource</h1><p>sid: %s</p><p>verdict: %s</p></body></html>`,
		sid, v,
	)
	return body
}

// errorBody is the wire shape of all 4xx/5xx JSON responses, mirroring
// vservice/http.go so error-handling stays uniform across services.
type errorBody struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	data, err := json.Marshal(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(data)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errorBody{Error: msg})
}

func writeHTML(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}
