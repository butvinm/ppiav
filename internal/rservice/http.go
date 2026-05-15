package rservice

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/butvinm/ppiav/internal/protocol"
	"github.com/butvinm/ppiav/web/rclient"
)

// Server wraps a *Service with the HTTP handlers RService exposes:
//
//	GET  /protected               (cookie-gated; Stage-1 redirect when no sid)
//	POST /api/callback/:sid       (VerdictNotification from VAgent)
//
// Per docs/DESIGN.md §`Components`, sid is carried in the URL path. The
// callback payload is the `VerdictNotification` wire struct as JSON.
//
// Stage-1 flow (DESIGN.md §3 Stage 1): `GET /protected` with no sid cookie
// triggers a synchronous server-to-server `POST <vagentURL>/sessions`.
// On success RService sets `Set-Cookie: sid=<sid>; Path=/; HttpOnly` and
// 302s to `<vagentURL>/verify?sid=<sid>`. On VAgent failure RService
// returns a 5xx with no cookie set (F4a).
type Server struct {
	svc        *Service
	addr       string
	vagentURL  string
	mux        *http.ServeMux
	httpClient *http.Client
}

// NewServer wires a Server around `svc`. `vagentURL` is the VAgent base
// URL (e.g., `http://localhost:8081`) used by the Stage-1 server-to-server
// hop. The constructor is named `NewServer` rather than `New` to avoid
// shadowing the existing `rservice.New()` Service constructor — same
// pattern as `vservice.NewServer`.
func NewServer(svc *Service, vagentURL, addr string) *Server {
	s := &Server{
		svc:        svc,
		addr:       addr,
		vagentURL:  vagentURL,
		mux:        http.NewServeMux(),
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}
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
	s.mux.HandleFunc("/dist/", s.handleRClientAsset)
	s.mux.HandleFunc("/api/callback/", s.handleCallback)
}

// handleRClientAsset serves files from the embedded RClient FS — the
// compiled TS bundle under `/dist/*`. The RClient SPA `index.html`
// references `./dist/main.js`, which resolves to `/dist/main.js` once
// served at `/protected`.
func (s *Server) handleRClientAsset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	http.FileServer(http.FS(rclient.FS)).ServeHTTP(w, r)
}

func (s *Server) handleProtected(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	c, err := r.Cookie("sid")
	if err != nil || c.Value == "" {
		s.beginStage1(w, r)
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

// beginStage1 implements DESIGN.md §3 Stage 1 (RService side): allocate a
// sid via VAgent `POST /sessions` (server-to-server, no body), set the sid
// cookie, and 302 the browser to `<vagentURL>/verify?sid=<sid>`. Any
// failure on the VAgent hop surfaces as a 5xx with no cookie set — F4a.
func (s *Server) beginStage1(w http.ResponseWriter, r *http.Request) {
	if s.vagentURL == "" {
		writeError(w, http.StatusInternalServerError, "rservice: vagentURL not configured")
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, s.vagentURL+"/sessions", nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("build vagent request: %s", err))
		return
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("call vagent /sessions: %s", err))
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("vagent /sessions returned %d", resp.StatusCode))
		return
	}
	var sess protocol.VerificationSession
	if err := json.NewDecoder(resp.Body).Decode(&sess); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("decode VerificationSession: %s", err))
		return
	}
	if sess.SessionID == "" {
		writeError(w, http.StatusBadGateway, "vagent returned empty sid")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "sid",
		Value:    string(sess.SessionID),
		Path:     "/",
		HttpOnly: true,
	})
	http.Redirect(w, r, fmt.Sprintf("%s/verify?sid=%s", s.vagentURL, sess.SessionID), http.StatusFound)
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

// protectedPage renders the RClient SPA shell (embedded index.html) with
// the verdict injected as JSON via `<script>window.verdict = {...}</script>`
// inserted immediately before the closing `</body>` tag. The RClient
// `main.ts` reads `window.verdict` and renders it into `#status`.
//
// sid and verdict are passed through `encoding/json` rather than spliced
// directly so any future field changes propagate without manual escaping.
// If the embedded index.html lookup or </body> insertion fails we fall
// back to a minimal self-contained shell so the handler still returns
// valid HTML (impossible-by-build, since embed validates at compile time).
func protectedPage(sid protocol.SessionID, v protocol.Verdict) string {
	injection := struct {
		Sid     string `json:"sid"`
		Verdict string `json:"verdict"`
	}{Sid: string(sid), Verdict: v.String()}
	payload, err := json.Marshal(injection)
	if err != nil {
		payload = []byte(`{"sid":"","verdict":"unknown"}`)
	}
	script := []byte(fmt.Sprintf(`<script>window.verdict = %s;</script>`, payload))

	raw, err := fs.ReadFile(rclient.FS, "index.html")
	if err != nil {
		return fmt.Sprintf(
			`<!doctype html><html><head><title>RClient</title></head><body><h1>Protected resource</h1><div id="status">Loading...</div>%s</body></html>`,
			script,
		)
	}
	closeTag := []byte("</body>")
	idx := bytes.LastIndex(raw, closeTag)
	if idx < 0 {
		// No </body> — append before EOF so the script still executes.
		return string(raw) + string(script)
	}
	out := make([]byte, 0, len(raw)+len(script))
	out = append(out, raw[:idx]...)
	out = append(out, script...)
	out = append(out, raw[idx:]...)
	return string(out)
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
