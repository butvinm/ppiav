package vagent

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"strings"

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
type Server struct {
	agent       *Agent
	vserviceURL string
	rserviceURL string
	addr        string
	httpClient  *http.Client
	mux         *http.ServeMux
}

// NewServer wires a Server around `agent`. `vserviceURL` is the base URL
// of the VService HTTP server (e.g., `http://localhost:8080`) — used both
// for the Stage-1 `POST /sessions` proxy and for forwarding `InferEvalKeys`
// at the end of Stage 2d. `rserviceURL` is the base URL of the RService
// HTTP server (e.g., `http://localhost:8082`) — used by the Stage-4b
// verdict callback added in Task 7. `addr` is forwarded verbatim to
// http.Server.Addr.
//
// The constructor is named `NewServer` (not `New`) to avoid shadowing the
// existing `vagent.New(params)` Agent constructor — same convention as
// `vservice.NewServer` and `rservice.NewServer`.
func NewServer(agent *Agent, vserviceURL, rserviceURL, addr string) *Server {
	s := &Server{
		agent:       agent,
		vserviceURL: strings.TrimRight(vserviceURL, "/"),
		rserviceURL: strings.TrimRight(rserviceURL, "/"),
		addr:        addr,
		httpClient:  &http.Client{},
		mux:         http.NewServeMux(),
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
	if s.vserviceURL == "" {
		writeError(w, http.StatusInternalServerError, "vagent: vserviceURL not configured")
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
	if s.vserviceURL == "" {
		writeError(w, http.StatusInternalServerError, "vagent: vserviceURL not configured")
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
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("read body: %s", err))
		return
	}
	var client protocol.VClientPKShare
	if err := client.UnmarshalBinary(body); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unmarshal VClientPKShare: %s", err))
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
		writeError(w, http.StatusBadRequest, err.Error())
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
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("read body: %s", err))
		return
	}
	var client protocol.VClientRLKRound1
	if err := client.UnmarshalBinary(body); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unmarshal VClientRLKRound1: %s", err))
		return
	}
	agentShare, err := s.agent.GenRLKShareRound1(sid)
	if err != nil {
		writeError(w, sidErrorStatus(err), err.Error())
		return
	}
	if err := s.agent.AggregateRLKRound1(sid, client.Share); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
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
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("read body: %s", err))
		return
	}
	var client protocol.VClientRLKRound2
	if err := client.UnmarshalBinary(body); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unmarshal VClientRLKRound2: %s", err))
		return
	}
	// GenRLKShareRound2 sets up the agent's round-2 share state needed by
	// AggregateRLKRound2 — same gen-then-aggregate ordering as Round 1 / PK.
	if _, err := s.agent.GenRLKShareRound2(sid); err != nil {
		writeError(w, sidErrorStatus(err), err.Error())
		return
	}
	if err := s.agent.AggregateRLKRound2(sid, client.Share); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
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
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("read body: %s", err))
		return
	}
	var client protocol.VClientGaloisKeyShare
	if err := client.UnmarshalBinary(body); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unmarshal VClientGaloisKeyShare: %s", err))
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
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	keys := protocol.InferEvalKeys{RLK: rlk, GKS: gks}
	keysBytes, err := keys.MarshalBinary()
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("marshal InferEvalKeys: %s", err))
		return
	}
	if s.vserviceURL == "" {
		writeError(w, http.StatusInternalServerError, "vagent: vserviceURL not configured")
		return
	}
	url := s.vserviceURL + "/sessions/" + string(sid) + "/eval-keys"
	resp, err := s.httpClient.Post(url, "application/octet-stream", bytes.NewReader(keysBytes))
	if err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("call vservice eval-keys: %s", err))
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		writeError(w, http.StatusBadGateway, fmt.Sprintf("vservice eval-keys returned %d: %s", resp.StatusCode, respBody))
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
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("read body: %s", err))
		return
	}
	inCt := &rlwe.Ciphertext{}
	if err := inCt.UnmarshalBinary(body); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unmarshal EncryptedImage: %s", err))
		return
	}

	if s.vserviceURL == "" {
		writeError(w, http.StatusInternalServerError, "vagent: vserviceURL not configured")
		return
	}
	url := s.vserviceURL + "/sessions/" + string(sid) + "/image"
	// Forward the original bytes verbatim — we already unmarshaled to
	// validate, but the VService handler unmarshals from the bytes itself.
	resp, err := s.httpClient.Post(url, "application/octet-stream", bytes.NewReader(body))
	if err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("call vservice /image: %s", err))
		return
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("read vservice /image: %s", err))
		return
	}
	if resp.StatusCode != http.StatusOK {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("vservice /image returned %d: %s", resp.StatusCode, respBody))
		return
	}
	resultCt := &rlwe.Ciphertext{}
	if err := resultCt.UnmarshalBinary(respBody); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("unmarshal vservice /image response: %s", err))
		return
	}

	ctM, err := s.agent.BuildAuthenticatedCt(sid, resultCt)
	if err != nil {
		writeError(w, sidErrorStatus(err), err.Error())
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
	}
	w.WriteHeader(http.StatusOK)
}

// handlePartialDecryption runs Stage 4a/b: receives VClient's smudged
// KeySwitchShare, calls FinalizeDecryption against the cached ct_M, posts
// the resulting verdict back to RService, and redirects the browser to
// RService's /protected. Per docs/DESIGN.md §`Failure modes`:
//
//   - unknown sid → 404, no callback (no session means no RService cookie)
//   - malformed share (known sid) → callback Reject (F2) **then** 4xx
//   - Ver=false / FinalizeDecryption error → callback Reject **then** 4xx
//   - clean Accept/Reject verdict → callback verdict **then** 302 to RService
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
	body, err := io.ReadAll(r.Body)
	if err != nil {
		// Known sid + read failure → F2 (wire-shape violation): callback
		// Reject, then 400.
		_ = s.postVerdict(sid, protocol.VerdictReject)
		writeError(w, http.StatusBadRequest, fmt.Sprintf("read body: %s", err))
		return
	}
	var pd protocol.PartialDecryption
	if err := pd.UnmarshalBinary(body); err != nil {
		_ = s.postVerdict(sid, protocol.VerdictReject)
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unmarshal PartialDecryption: %s", err))
		return
	}
	ctM, populated, ok := s.agent.SessionAuthenticatedCt(sid)
	if !ok {
		// Race: session vanished between the initial check and now.
		writeError(w, http.StatusNotFound, fmt.Sprintf("vagent: unknown session id %q", sid))
		return
	}
	if !populated {
		// F3: partial-decryption called before image POST stored ct_M.
		// Known sid with no ct cached → callback Reject (F3 wire shape),
		// then 400.
		_ = s.postVerdict(sid, protocol.VerdictReject)
		writeError(w, http.StatusBadRequest, "vagent: partial-decryption called before image submission")
		return
	}
	verdict, err := s.agent.FinalizeDecryption(sid, ctM, pd.Share)
	if err != nil {
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
	if s.rserviceURL == "" {
		// No place to redirect to. Treat as misconfiguration → 500.
		writeError(w, http.StatusInternalServerError, "vagent: rserviceURL not configured")
		return
	}
	http.Redirect(w, r, s.rserviceURL+"/protected", http.StatusFound)
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
	url := s.rserviceURL + "/api/callback/" + string(sid)
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
func sidErrorStatus(err error) int {
	if err == nil {
		return http.StatusOK
	}
	if strings.Contains(err.Error(), "unknown session id") {
		return http.StatusNotFound
	}
	return http.StatusBadRequest
}

// errorBody mirrors the wire shape used in vservice/rservice handlers.
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
