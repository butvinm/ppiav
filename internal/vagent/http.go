package vagent

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	urlpath "net/url"
	"strings"
	"time"

	"github.com/butvinm/ppiav/internal/httputil"
	"github.com/butvinm/ppiav/internal/protocol"
	"github.com/butvinm/ppiav/web/ppiav"
	"github.com/butvinm/ppiav/web/vclient"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

// Server wraps an *Agent with the HTTP routes VClient and RService drive.
// Routes follow docs/DESIGN.md §`Protocol` exactly; share- and key-bearing
// endpoints use application/octet-stream per Task-4 Technical Details
// (`pk-share`, `rlk/round1`, `rlk/round2`, `gks-shares` — and the outbound
// `InferEvalKeys` POST to VService `/sessions/:sid/eval-keys`). Control
// endpoints (`POST /sessions`, `GET /sessions/:sid/params`) use JSON.
//
// Image (`POST /sessions/:sid/image`), SSE result (`GET
// /sessions/:sid/result`) and partial-decryption
// (`POST /sessions/:sid/partial-decryption`) handlers are wired in this
// file (added in Tasks 6 and 7). The `/verify` SPA handler is added in
// Task 16.
//
// `rservicePublicURL` is a browser-visible base URL distinct from
// `rserviceURL` (which is the server-to-server URL). In a docker-compose
// deployment the server-to-server URL might be `http://rservice:8082`
// (Docker DNS) while the public URL is `http://localhost:8082` (host
// port mapping). When unset, falls back to `rserviceURL`.
type Server struct {
	agent             *Agent
	vserviceURL       string
	rserviceURL       string
	rservicePublicURL string
	httpClient        *http.Client
	mux               *http.ServeMux
}

// NewServer wires a Server around `agent`. `vserviceURL` is the base URL
// of the VService HTTP server (e.g., `http://localhost:8080`) — used both
// for the Stage-1 `POST /sessions` proxy and for forwarding `InferEvalKeys`
// at the end of Stage 2d. `rserviceURL` is the base URL of the RService
// HTTP server (e.g., `http://localhost:8082`) — used by the Stage-4b
// verdict callback added in Task 7. `rservicePublicURL` is the
// browser-visible RService URL emitted in Stage-4b redirect bodies; when
// empty it defaults to `rserviceURL` (preserving the localhost case).
//
// The constructor is named `NewServer` (not `New`) to avoid shadowing the
// existing `vagent.New(params)` Agent constructor — same convention as
// `vservice.NewServer` and `rservice.NewServer`.
func NewServer(agent *Agent, vserviceURL, rserviceURL, rservicePublicURL string) *Server {
	rsvcURL := strings.TrimRight(rserviceURL, "/")
	rsvcPubURL := strings.TrimRight(rservicePublicURL, "/")
	if rsvcPubURL == "" {
		rsvcPubURL = rsvcURL
	}
	s := &Server{
		agent:             agent,
		vserviceURL:       strings.TrimRight(vserviceURL, "/"),
		rserviceURL:       rsvcURL,
		rservicePublicURL: rsvcPubURL,
		// 30s is well above the longest legitimate VService /image
		// turnaround (Phase-2 Orion inference) but bounds hung
		// peers so handler goroutines do not leak.
		httpClient: &http.Client{Timeout: 30 * time.Second},
		mux:        http.NewServeMux(),
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
	s.mux.HandleFunc("/verify", s.handleVerify)
	s.mux.HandleFunc("/dist/", s.handleVClientAsset)
	s.mux.HandleFunc("/wasm_exec.js", s.handleVClientAsset)
	s.mux.HandleFunc("/ppiav.wasm", s.handlePpiavWASM)
	s.mux.HandleFunc("/sessions", s.handleSessions)
	s.mux.HandleFunc("/sessions/", s.handleSession)
}

// handleVerify serves the VClient SPA's index.html (embedded via
// web/vclient/embed.go). The browser lands here after RService's Stage-1
// 302 (URL carries `?sid=<sid>`). Companion assets — `/dist/*`,
// `/wasm_exec.js`, `/ppiav.wasm` — live on sibling routes so the SPA can
// fetch them with absolute paths.
func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	data, err := fs.ReadFile(vclient.FS, "index.html")
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("read vclient index.html: %s", err))
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// handleVClientAsset serves files from the embedded VClient FS — namely
// `/dist/*` (compiled TS bundle) and `/wasm_exec.js` (the Go runtime
// shim). The file path inside the FS is the request path with the leading
// slash stripped. Missing files return 404 via http.FileServer.
func (s *Server) handleVClientAsset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	http.FileServer(http.FS(vclient.FS)).ServeHTTP(w, r)
}

// handlePpiavWASM serves the embedded compiled WASM blob at
// `/ppiav.wasm`. Browsers require `application/wasm` for the streaming
// `WebAssembly.instantiateStreaming` path used by the VClient main.ts.
func (s *Server) handlePpiavWASM(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	w.Header().Set("Content-Type", "application/wasm")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(ppiav.WASM)
}

// handleSessions is the Stage-1 entry point. Called server-to-server by
// RService's `GET /protected` handler (not the browser). Allocates a sid
// via VService, registers it locally, returns VerificationSession{sid} as
// JSON. F4a (VService unreachable) surfaces as a 5xx to RService.
func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	resp, err := s.httpClient.Post(s.vserviceURL+"/sessions", "application/json", nil)
	if err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("call vservice /sessions: %s", err))
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		writeError(w, http.StatusBadGateway, fmt.Sprintf("vservice /sessions returned %d: %s", resp.StatusCode, body))
		return
	}
	var sess protocol.VerificationSession
	if err := json.NewDecoder(resp.Body).Decode(&sess); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("decode VerificationSession: %s", err))
		return
	}
	if sess.SessionID == "" {
		writeError(w, http.StatusBadGateway, "vservice returned empty sid")
		return
	}
	if err := s.agent.OpenSession(sess.SessionID); err != nil {
		// TODO(phase-3-followup): VService allocated `sess.SessionID` but
		// our local OpenSession rejected it (typically a duplicate sid),
		// so the sid leaks into VService's sessions map. Not exploitable —
		// no key material yet — but allows unbounded growth on repeated
		// failure. Out of scope for Phase 3; a follow-up should add a
		// `DELETE /sessions/:sid` route on VService and invoke it here.
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("agent open session: %s", err))
		return
	}
	writeJSON(w, http.StatusOK, sess)
}

// handleSession dispatches `/sessions/:sid/<sub>` and `/sessions/:sid/rlk/<round>`.
// stdlib ServeMux only gives us the prefix; we parse the rest ourselves.
func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/sessions/")
	if rest == "" || rest == r.URL.Path {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	sid, sub, ok := strings.Cut(rest, "/")
	if !ok || sid == "" || sub == "" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	sessID := protocol.SessionID(sid)
	switch {
	case sub == "params":
		s.handleParams(w, r)
	case sub == "pk-share":
		s.handlePKShare(w, r, sessID)
	case sub == "rlk/round1":
		s.handleRLKRound1(w, r, sessID)
	case sub == "rlk/round2":
		s.handleRLKRound2(w, r, sessID)
	case sub == "gks-shares":
		s.handleGKSShares(w, r, sessID)
	case sub == "result":
		s.handleResultSSE(w, r, sessID)
	case sub == "image":
		s.handleImage(w, r, sessID)
	case sub == "partial-decryption":
		s.handlePartialDecryption(w, r, sessID)
	default:
		writeError(w, http.StatusNotFound, "not found")
	}
}

// handleResultSSE implements `GET /sessions/:sid/result` (Stage 4a SSE).
// Opens before the image POST so the ct_M deposit can never miss the
// receiver (capacity-1 channel covers the pre-arrival case too). Streams a
// single base64-encoded AuthenticatedResult event, then closes — SSE
// framing is text-only by spec, so we eat ~33% inflation on this one event
// in exchange for the simplest "open before image POST" semantics.
//
// Cancellable: a `select` on `r.Context().Done()` ends the handler cleanly
// when the browser disconnects, which `sync.Cond.Wait` cannot.
func (s *Server) handleResultSSE(w http.ResponseWriter, r *http.Request, sid protocol.SessionID) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	ch, ok := s.agent.SessionAuthResult(sid)
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Sprintf("vagent: unknown session id %q", sid))
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "response writer does not support flushing")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	// Tell the EventSource not to reconnect after we close. Without this
	// hint the browser auto-reconnects in ~3s, leaving a stray request
	// against a now-evicted session — wasteful and noisy.
	_, _ = fmt.Fprintf(w, "retry: %d\n\n", 86_400_000)
	flusher.Flush()

	select {
	case ct := <-ch:
		if ct == nil {
			return
		}
		data, err := ct.MarshalBinary()
		if err != nil {
			// Headers already written — cannot upgrade to 500. Emit an SSE
			// error event so the browser can surface it (best-effort).
			_, _ = fmt.Fprintf(w, "event: error\ndata: marshal AuthenticatedResult: %s\n\n", err)
			flusher.Flush()
			return
		}
		encoded := base64.StdEncoding.EncodeToString(data)
		_, _ = fmt.Fprintf(w, "data: %s\n\n", encoded)
		flusher.Flush()
	case <-r.Context().Done():
		return
	}
}

// handleParams proxies `GET /sessions/:sid/params` to VService `/params`.
// Phase 3 returns one params set for all sessions; the sid is in the URL
// for symmetry with the rest of the protocol and forward-compatibility.
func (s *Server) handleParams(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	resp, err := s.httpClient.Get(s.vserviceURL + "/params")
	if err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("call vservice /params: %s", err))
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("read vservice /params: %s", err))
		return
	}
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(body)
}

func (s *Server) handlePKShare(w http.ResponseWriter, r *http.Request, sid protocol.SessionID) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	// Check sid existence before reading the body so unknown-sid is
	// surfaced as 404 regardless of body well-formedness.
	if _, err := s.agent.session(sid); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, httputil.MaxShareBody))
	if err != nil {
		s.rejectAndEvict(w, http.StatusBadRequest, sid, fmt.Sprintf("read body: %s", err))
		return
	}
	var client protocol.VClientPKShare
	if err := client.UnmarshalBinary(body); err != nil {
		s.rejectAndEvict(w, http.StatusBadRequest, sid, fmt.Sprintf("unmarshal VClientPKShare: %s", err))
		return
	}
	// GenPKShare must run before AggregatePK to set up the protocol/CRP/local
	// share. The order mirrors orchestrator.runner's keygen sequence.
	agentShare, err := s.agent.GenPKShare(sid)
	if err != nil {
		writeError(w, sidErrorStatus(err), err.Error())
		return
	}
	if err := s.agent.AggregatePK(sid, client.Share); err != nil {
		// AggregatePK fails when the wire share is semantically malformed
		// (wrong ring, wrong degree). Still F2 per DESIGN.md §`Failure modes`:
		// "Malformed wire input … plus Verdict = Reject. Session torn down."
		s.rejectAndEvict(w, http.StatusBadRequest, sid, err.Error())
		return
	}
	writeBinary(w, protocol.VAgentPKShare{Share: agentShare})
}

func (s *Server) handleRLKRound1(w http.ResponseWriter, r *http.Request, sid protocol.SessionID) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if _, err := s.agent.session(sid); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, httputil.MaxShareBody))
	if err != nil {
		s.rejectAndEvict(w, http.StatusBadRequest, sid, fmt.Sprintf("read body: %s", err))
		return
	}
	var client protocol.VClientRLKRound1
	if err := client.UnmarshalBinary(body); err != nil {
		s.rejectAndEvict(w, http.StatusBadRequest, sid, fmt.Sprintf("unmarshal VClientRLKRound1: %s", err))
		return
	}
	agentShare, err := s.agent.GenRLKShareRound1(sid)
	if err != nil {
		writeError(w, sidErrorStatus(err), err.Error())
		return
	}
	if err := s.agent.AggregateRLKRound1(sid, client.Share); err != nil {
		s.rejectAndEvict(w, http.StatusBadRequest, sid, err.Error())
		return
	}
	writeBinary(w, protocol.VAgentRLKRound1{Share: agentShare})
}

func (s *Server) handleRLKRound2(w http.ResponseWriter, r *http.Request, sid protocol.SessionID) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if _, err := s.agent.session(sid); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, httputil.MaxShareBody))
	if err != nil {
		s.rejectAndEvict(w, http.StatusBadRequest, sid, fmt.Sprintf("read body: %s", err))
		return
	}
	var client protocol.VClientRLKRound2
	if err := client.UnmarshalBinary(body); err != nil {
		s.rejectAndEvict(w, http.StatusBadRequest, sid, fmt.Sprintf("unmarshal VClientRLKRound2: %s", err))
		return
	}
	// GenRLKShareRound2 sets up the agent's round-2 share state needed by
	// AggregateRLKRound2 — same gen-then-aggregate ordering as Round 1 / PK.
	if _, err := s.agent.GenRLKShareRound2(sid); err != nil {
		writeError(w, sidErrorStatus(err), err.Error())
		return
	}
	if err := s.agent.AggregateRLKRound2(sid, client.Share); err != nil {
		s.rejectAndEvict(w, http.StatusBadRequest, sid, err.Error())
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleGKSShares(w http.ResponseWriter, r *http.Request, sid protocol.SessionID) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if _, err := s.agent.session(sid); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, httputil.MaxGksSharesBody))
	if err != nil {
		s.rejectAndEvict(w, http.StatusBadRequest, sid, fmt.Sprintf("read body: %s", err))
		return
	}
	var client protocol.VClientGaloisKeyShare
	if err := client.UnmarshalBinary(body); err != nil {
		s.rejectAndEvict(w, http.StatusBadRequest, sid, fmt.Sprintf("unmarshal VClientGaloisKeyShare: %s", err))
		return
	}
	// GenGaloisShares draws CRPs in canonical label order; the resulting
	// labels slice is what AggregateGaloisShares cross-checks against the
	// client's parallel labels (both sides derive the labels from
	// `params.RotationIndices()` so the agent slice is authoritative).
	_, agentLabels, err := s.agent.GenGaloisShares(sid)
	if err != nil {
		writeError(w, sidErrorStatus(err), err.Error())
		return
	}
	rlk, gks, err := s.agent.AggregateGaloisShares(sid, client.Shares, agentLabels)
	if err != nil {
		// Count-mismatch / share-shape mismatch is F2 (malformed wire input).
		s.rejectAndEvict(w, http.StatusBadRequest, sid, err.Error())
		return
	}
	keys := protocol.InferEvalKeys{RLK: rlk, GKS: gks}
	keysBytes, err := keys.MarshalBinary()
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("marshal InferEvalKeys: %s", err))
		return
	}
	url := s.vserviceURL + "/sessions/" + urlpath.PathEscape(string(sid)) + "/eval-keys"
	resp, err := s.httpClient.Post(url, "application/octet-stream", bytes.NewReader(keysBytes))
	if err != nil {
		// F3: VService unreachable / inference layer unreachable mid-keygen.
		// AggregateGaloisShares already mutated session state; rejectAndEvict
		// fires the Verdict=Reject callback and tears down the session.
		s.rejectAndEvict(w, http.StatusBadGateway, sid, fmt.Sprintf("call vservice eval-keys: %s", err))
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		s.rejectAndEvict(w, http.StatusBadGateway, sid, fmt.Sprintf("vservice eval-keys returned %d: %s", resp.StatusCode, respBody))
		return
	}
	w.WriteHeader(http.StatusOK)
}

// handleImage runs Stages 3 and the first half of 4a. Reads the marshaled
// encrypted image from the request body, forwards the bytes to VService's
// matching `POST /sessions/:sid/image` route, parses the returned
// ciphertext, calls `BuildAuthenticatedCt` to fold in MPD-Auth's random
// values, deposits the resulting ct_M into the SSE channel for the
// already-opened result GET, and caches it in the session so the
// subsequent partial-decryption call can pass it to FinalizeDecryption.
//
// Error mapping:
//   - unknown sid → 404 (handled implicitly by `agent.session` + BuildAuthenticatedCt)
//   - malformed body → 400
//   - VService unreachable / non-200 → 502 (F4a wire shape)
//   - BuildAuthenticatedCt failure → 500 (impossible-by-protocol once Stage 2d completed)
func (s *Server) handleImage(w http.ResponseWriter, r *http.Request, sid protocol.SessionID) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if _, err := s.agent.session(sid); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, httputil.MaxEvalKeysBody))
	if err != nil {
		s.rejectAndEvict(w, http.StatusBadRequest, sid, fmt.Sprintf("read body: %s", err))
		return
	}
	inCt := &rlwe.Ciphertext{}
	if err := inCt.UnmarshalBinary(body); err != nil {
		s.rejectAndEvict(w, http.StatusBadRequest, sid, fmt.Sprintf("unmarshal EncryptedImage: %s", err))
		return
	}

	url := s.vserviceURL + "/sessions/" + urlpath.PathEscape(string(sid)) + "/image"
	// Forward the original bytes verbatim — we already unmarshaled to
	// validate, but the VService handler unmarshals from the bytes itself.
	resp, err := s.httpClient.Post(url, "application/octet-stream", bytes.NewReader(body))
	if err != nil {
		// F3: inference unreachable.
		s.rejectAndEvict(w, http.StatusBadGateway, sid, fmt.Sprintf("call vservice /image: %s", err))
		return
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		s.rejectAndEvict(w, http.StatusBadGateway, sid, fmt.Sprintf("read vservice /image: %s", err))
		return
	}
	if resp.StatusCode != http.StatusOK {
		// F3: VService returned an error during inference.
		s.rejectAndEvict(w, http.StatusBadGateway, sid, fmt.Sprintf("vservice /image returned %d: %s", resp.StatusCode, respBody))
		return
	}
	resultCt := &rlwe.Ciphertext{}
	if err := resultCt.UnmarshalBinary(respBody); err != nil {
		// F3: VService returned a malformed ciphertext.
		s.rejectAndEvict(w, http.StatusBadGateway, sid, fmt.Sprintf("unmarshal vservice /image response: %s", err))
		return
	}

	ctM, err := s.agent.BuildAuthenticatedCt(sid, resultCt)
	if err != nil {
		// `BuildAuthenticatedCt` only fails on unknown sid (404) or impossible-
		// by-protocol nil authKey (would only happen if OpenSession was never
		// called). The unknown-sid branch keeps writeError because there is no
		// session to tear down.
		status := sidErrorStatus(err)
		if status == http.StatusNotFound {
			writeError(w, status, err.Error())
		} else {
			s.rejectAndEvict(w, status, sid, err.Error())
		}
		return
	}
	// Cache ct_M for the upcoming partial-decryption call.
	if ok := s.agent.storeAuthenticatedCt(sid, ctM); !ok {
		// Sid was deleted between session() and storeAuthenticatedCt — race
		// only possible from a concurrent FinalizeDecryption, which we don't
		// expect on this code path. Surface as 404 for consistency.
		writeError(w, http.StatusNotFound, fmt.Sprintf("vagent: unknown session id %q", sid))
		return
	}
	// Non-blocking SSE deposit: covers both the pre-arrival case (SSE handler
	// not yet attached — buffer 1 absorbs it) and the impossible-by-protocol
	// duplicate-image case (default branch silently drops). See agent.go
	// sessionState.authResult.
	ch, ok := s.agent.SessionAuthResult(sid)
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Sprintf("vagent: unknown session id %q", sid))
		return
	}
	select {
	case ch <- ctM:
	default:
		// Capacity-1 channel already holds a ct from an earlier image POST.
		// Impossible per the protocol (one image per session), but log so
		// operators see misbehaving clients. The latest ct_M is still
		// cached on the session for partial-decryption to use.
		log.Printf("vagent: duplicate image POST for sid %q; SSE channel already full", sid)
	}
	w.WriteHeader(http.StatusOK)
}

// handlePartialDecryption runs Stage 4a/b: receives VClient's smudged
// KeySwitchShare, calls FinalizeDecryption against the cached ct_M, posts
// the resulting verdict back to RService, and tells the browser where to
// navigate next. Per docs/DESIGN.md §`Failure modes`:
//
//   - unknown sid → 404, no callback (no session means no RService cookie)
//   - malformed share (known sid) → callback Reject (F2) **then** 4xx
//   - Ver=false / FinalizeDecryption error → callback Reject **then** 4xx
//   - clean Accept/Reject verdict → callback verdict **then** 200 + JSON
//     `{"redirect":"<rservicePublicURL>/protected"}`
//
// We return JSON + 200 instead of a 302: browsers strip headers from
// `fetch(redirect: "manual")` responses (opaqueredirect), and using
// `redirect: "follow"` would force the browser to re-POST partial-
// decryption (which is single-shot — second POST 404s). JSON 200 lets the
// SPA explicitly call `window.location.assign(body.redirect)`.
//
// The verdict callback always runs **before** the HTTP response is
// written so RService stores it regardless of whether the client reads
// our body.
func (s *Server) handlePartialDecryption(w http.ResponseWriter, r *http.Request, sid protocol.SessionID) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	// Unknown sid is 404 with no callback.
	if _, err := s.agent.session(sid); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, httputil.MaxShareBody))
	if err != nil {
		// Known sid + read failure → F2 (wire-shape violation): callback
		// Reject, then 400, plus evict the session so a follow-up valid
		// retry cannot flip the upserted verdict back to Accept.
		s.rejectAndEvict(w, http.StatusBadRequest, sid, fmt.Sprintf("read body: %s", err))
		return
	}
	var pd protocol.PartialDecryption
	if err := pd.UnmarshalBinary(body); err != nil {
		s.rejectAndEvict(w, http.StatusBadRequest, sid, fmt.Sprintf("unmarshal PartialDecryption: %s", err))
		return
	}
	ctM, ok := s.agent.SessionAuthenticatedCt(sid)
	if !ok {
		// Race: session vanished between the initial check and now.
		writeError(w, http.StatusNotFound, fmt.Sprintf("vagent: unknown session id %q", sid))
		return
	}
	if ctM == nil {
		// F3: partial-decryption called before image POST stored ct_M.
		// Known sid with no ct cached → callback Reject (F3 wire shape),
		// then 400. Evict so a subsequent valid retry cannot upsert Accept.
		s.rejectAndEvict(w, http.StatusBadRequest, sid, "vagent: partial-decryption called before image submission")
		return
	}
	verdict, err := s.agent.FinalizeDecryption(sid, ctM, pd.Share)
	if err != nil {
		// FinalizeDecryption already evicts via its deferred cleanup; we
		// just post the Reject callback. Use postVerdict directly (not
		// rejectAndEvict) to avoid a redundant EvictSession.
		_ = s.postVerdict(sid, protocol.VerdictReject)
		writeError(w, http.StatusBadRequest, fmt.Sprintf("finalize decryption: %s", err))
		return
	}
	// Clean finalize: callback the actual verdict (Accept or Reject).
	if err := s.postVerdict(sid, verdict); err != nil {
		// Callback failed: surface 502 so the operator can see the wire
		// fault. The session is already evicted by FinalizeDecryption.
		writeError(w, http.StatusBadGateway, fmt.Sprintf("rservice callback: %s", err))
		return
	}
	if s.rservicePublicURL == "" {
		// No place to redirect to. Treat as misconfiguration → 500.
		writeError(w, http.StatusInternalServerError, "vagent: rservicePublicURL not configured")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"redirect": s.rservicePublicURL + "/protected"})
}

// rejectAndEvict is the centralised handler for F2 (malformed wire input)
// and F3 (inference error) per docs/DESIGN.md §`Failure modes`:
//
//	"HTTP 4xx/5xx to the offending party plus Verdict = Reject to
//	 RService. Session torn down."
//
// Order matters: post the Reject callback first (so RService records it
// even if EvictSession races a concurrent request), then evict so the
// authKey + skShare + cached ct_M cannot be re-used by a follow-up
// request to flip RService's upserted verdict back to Accept (replay
// weakness: rservice.Service.AcceptVerdict is last-write-wins). Finally
// write the HTTP error response.
//
// Callback failure is logged best-effort — the session is still evicted
// and the HTTP error still goes out. If RService is down, the session
// state becomes Unknown (deny-by-default), which is the safest fallback.
//
// Callers must hold a known sid. For unknown sids the design says
// "no session, nothing to tear down" — use writeError directly.
func (s *Server) rejectAndEvict(w http.ResponseWriter, status int, sid protocol.SessionID, msg string) {
	if err := s.postVerdict(sid, protocol.VerdictReject); err != nil {
		log.Printf("vagent: post Reject callback for sid %q failed: %s", sid, err)
	}
	s.agent.EvictSession(sid)
	writeError(w, status, msg)
}

// postVerdict POSTs `VerdictNotification{verdict}` to RService's
// `/api/callback/:sid` route. Returns an error if the RService URL is
// unset or the call fails; callers decide whether to surface it.
func (s *Server) postVerdict(sid protocol.SessionID, verdict protocol.Verdict) error {
	if s.rserviceURL == "" {
		return fmt.Errorf("vagent: rserviceURL not configured")
	}
	notif := protocol.VerdictNotification{Verdict: verdict}
	notifBytes, err := json.Marshal(notif)
	if err != nil {
		return fmt.Errorf("marshal VerdictNotification: %w", err)
	}
	url := s.rserviceURL + "/api/callback/" + urlpath.PathEscape(string(sid))
	resp, err := s.httpClient.Post(url, "application/json", bytes.NewReader(notifBytes))
	if err != nil {
		return fmt.Errorf("post: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("rservice returned %d: %s", resp.StatusCode, respBody)
	}
	return nil
}

// sidErrorStatus maps Agent errors to HTTP statuses. The Agent reports
// unknown sids via fmt.Errorf("vagent: unknown session id %q", sid); we
// surface that as 404, everything else as 400 (malformed protocol state).
// Only called from non-nil error paths.
func sidErrorStatus(err error) int {
	if strings.Contains(err.Error(), "unknown session id") {
		return http.StatusNotFound
	}
	return http.StatusBadRequest
}

// errorBody re-exports the shared JSON error wire shape for tests that
// previously unmarshaled `errorBody` directly. Implementation now lives
// in internal/httputil.
type errorBody = httputil.ErrorBody

var (
	writeJSON  = httputil.WriteJSON
	writeError = httputil.WriteError
)

// writeBinary marshals `m` and writes the bytes with
// `application/octet-stream`. Errors during MarshalBinary become 500.
type binaryMarshaler interface {
	MarshalBinary() ([]byte, error)
}

func writeBinary(w http.ResponseWriter, m binaryMarshaler) {
	data, err := m.MarshalBinary()
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("marshal response: %s", err))
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}
