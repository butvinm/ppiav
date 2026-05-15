package rservice

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/butvinm/ppiav/internal/httputil"
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
// — or a sid cookie that resolves to VerdictUnknown (stale / unfinished)
// — triggers a synchronous server-to-server `POST <vagentURL>/sessions`.
// On success RService sets `Set-Cookie: sid=<sid>; Path=/; HttpOnly` and
// 302s to `<vagentPublicURL>/verify?sid=<sid>`. On VAgent failure RService
// returns a 5xx with no cookie set (F4a).
type Server struct {
	svc             *Service
	vagentURL       string
	vagentPublicURL string
	mux             *http.ServeMux
	httpClient      *http.Client
}

// NewServer wires a Server around `svc`. `vagentURL` is the VAgent base
// URL used by the Stage-1 server-to-server `POST /sessions` hop (e.g.,
// `http://vagent:8081` inside Docker). `vagentPublicURL` is the
// browser-visible VAgent URL emitted in the Stage-1 redirect's `Location`
// header (e.g., `http://localhost:8081` so the host browser can reach
// it). When `vagentPublicURL` is empty it falls back to `vagentURL`,
// preserving the localhost single-host flow. The constructor is named
// `NewServer` rather than `New` to avoid shadowing the existing
// `rservice.New()` Service constructor — same pattern as
// `vservice.NewServer`.
func NewServer(svc *Service, vagentURL, vagentPublicURL string) *Server {
	vagentURL = strings.TrimRight(vagentURL, "/")
	vagentPublicURL = strings.TrimRight(vagentPublicURL, "/")
	if vagentPublicURL == "" {
		vagentPublicURL = vagentURL
	}
	s := &Server{
		svc:             svc,
		vagentURL:       vagentURL,
		vagentPublicURL: vagentPublicURL,
		mux:             http.NewServeMux(),
		httpClient:      &http.Client{Timeout: 5 * time.Second},
	}
	s.register()
	return s
}

// Handler exposes the mux for composition with httptest.NewServer.
func (s *Server) Handler() http.Handler { return s.mux }

// ListenAndServe boots an http.Server on addr.
func (s *Server) ListenAndServe(addr string) error {
	srv := &http.Server{Addr: addr, Handler: s.mux}
	return srv.ListenAndServe()
}

func (s *Server) register() {
	s.mux.HandleFunc("/protected", s.handleProtected)
	s.mux.HandleFunc("/dist/", s.handleRClientAsset)
	s.mux.HandleFunc("/styles.css", s.handleRClientAsset)
	s.mux.HandleFunc("/api/callback/", s.handleCallback)
}

// handleRClientAsset serves files from the embedded RClient FS — the
// compiled TS bundle under `/dist/*`. The RClient SPA `index.html`
// references `./dist/main.js`, which resolves to `/dist/main.js` once
// served at `/protected`.
func (s *Server) handleRClientAsset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	http.FileServer(http.FS(rclient.FS)).ServeHTTP(w, r)
}

func (s *Server) handleProtected(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	c, err := r.Cookie("sid")
	if err != nil || c.Value == "" {
		s.beginStage1(w, r)
		return
	}
	sid := protocol.SessionID(c.Value)
	verdict := s.svc.CheckAccess(sid)
	// VerdictUnknown means the sid was never followed by a callback —
	// stale cookie from an abandoned verification, or a value the
	// browser carried over without ever finishing Stage 1. Restart
	// rather than render an unrecoverable "unknown" verdict.
	if verdict == protocol.VerdictUnknown {
		s.beginStage1(w, r)
		return
	}
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
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, s.vagentURL+"/sessions", nil)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("build vagent request: %s", err))
		return
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		httputil.WriteError(w, http.StatusBadGateway, fmt.Sprintf("call vagent /sessions: %s", err))
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		httputil.WriteError(w, http.StatusBadGateway, fmt.Sprintf("vagent /sessions returned %d", resp.StatusCode))
		return
	}
	var sess protocol.VerificationSession
	if err := json.NewDecoder(resp.Body).Decode(&sess); err != nil {
		httputil.WriteError(w, http.StatusBadGateway, fmt.Sprintf("decode VerificationSession: %s", err))
		return
	}
	if sess.SessionID == "" {
		httputil.WriteError(w, http.StatusBadGateway, "vagent returned empty sid")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "sid",
		Value:    string(sess.SessionID),
		Path:     "/",
		HttpOnly: true,
	})
	http.Redirect(w, r, fmt.Sprintf("%s/verify?sid=%s", s.vagentPublicURL, url.QueryEscape(string(sess.SessionID))), http.StatusFound)
}

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/callback/")
	if rest == "" || strings.Contains(rest, "/") {
		httputil.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	sid := protocol.SessionID(rest)

	var notif protocol.VerdictNotification
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, httputil.MaxJSONBody)).Decode(&notif); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, fmt.Sprintf("decode VerdictNotification: %s", err))
		return
	}
	if err := s.svc.AcceptVerdict(sid, notif.Verdict); err != nil {
		// AcceptVerdict only errors on VerdictUnknown — a wire-shape
		// violation per DESIGN.md (callback never delivers Unknown).
		httputil.WriteError(w, http.StatusBadRequest, err.Error())
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
// `json.Marshal` on a two-string struct and `fs.ReadFile` on a
// compile-time-validated embed.FS path cannot fail; both errors are
// dropped.
func protectedPage(sid protocol.SessionID, v protocol.Verdict) string {
	injection := struct {
		Sid     string `json:"sid"`
		Verdict string `json:"verdict"`
	}{Sid: string(sid), Verdict: v.String()}
	payload, _ := json.Marshal(injection)
	script := []byte(fmt.Sprintf(`<script>window.verdict = %s;</script>`, payload))

	raw, _ := fs.ReadFile(rclient.FS, "index.html")
	closeTag := []byte("</body>")
	idx := bytes.LastIndex(raw, closeTag)
	// `</body>` is required by the embedded RClient template; if a
	// future edit drops it, append the script at the end rather than
	// panic on `raw[:idx]` with idx==-1.
	if idx < 0 {
		out := make([]byte, 0, len(raw)+len(script))
		out = append(out, raw...)
		out = append(out, script...)
		return string(out)
	}
	out := make([]byte, 0, len(raw)+len(script))
	out = append(out, raw[:idx]...)
	out = append(out, script...)
	out = append(out, raw[idx:]...)
	return string(out)
}

func writeHTML(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}
