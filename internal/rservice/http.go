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

// protectedPage renders the RClient SPA shell with the verdict injected
// as JSON via `<script>window.verdict = {...}</script>` before the closing
// `</body>` tag. The RClient `main.ts` reads `window.verdict` and renders
// it into `#status`. Task 17 will swap the inline HTML for embed.FS-served
// `web/rclient/index.html` + `web/rclient/dist/main.js`; for now the page
// is self-contained so the cookie-gated read path stays testable.
//
// sid and verdict are passed through `encoding/json` rather than spliced
// directly so any future field changes propagate without manual escaping.
func protectedPage(sid protocol.SessionID, v protocol.Verdict) string {
	injection := struct {
		Sid     string `json:"sid"`
		Verdict string `json:"verdict"`
	}{Sid: string(sid), Verdict: v.String()}
	// json.Marshal handles escaping; both sid and verdict are server-trusted
	// (sid comes from the cookie which we set; verdict is an enum).
	payload, err := json.Marshal(injection)
	if err != nil {
		// Marshaling a flat struct of strings cannot fail in practice;
		// fall back to a minimal escape-free shell so the handler still
		// returns valid HTML.
		payload = []byte(`{"sid":"","verdict":"unknown"}`)
	}
	return fmt.Sprintf(
		`<!doctype html><html><head><title>RClient</title></head><body><h1>Protected resource</h1><div id="status">Loading...</div><script>window.verdict = %s;</script></body></html>`,
		payload,
	)
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
