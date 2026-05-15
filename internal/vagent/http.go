package vagent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/butvinm/ppiav/internal/protocol"
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
// (`POST /sessions/:sid/partial-decryption`) handlers are added in Tasks
// 6 and 7; this file only carries the keygen plus Stage-1 session-open
// surface. The `/verify` SPA handler is added in Task 16.
type Server struct {
	agent       *Agent
	vserviceURL string
	addr        string
	httpClient  *http.Client
	mux         *http.ServeMux
}

// NewServer wires a Server around `agent`. `vserviceURL` is the base URL
// of the VService HTTP server (e.g., `http://localhost:8080`) — used both
// for the Stage-1 `POST /sessions` proxy and for forwarding `InferEvalKeys`
// at the end of Stage 2d. `addr` is forwarded verbatim to http.Server.Addr.
//
// The constructor is named `NewServer` (not `New`) to avoid shadowing the
// existing `vagent.New(params)` Agent constructor — same convention as
// `vservice.NewServer` and `rservice.NewServer`.
func NewServer(agent *Agent, vserviceURL, addr string) *Server {
	s := &Server{
		agent:       agent,
		vserviceURL: strings.TrimRight(vserviceURL, "/"),
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
	s.mux.HandleFunc("/sessions", s.handleSessions)
	s.mux.HandleFunc("/sessions/", s.handleSession)
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
	default:
		writeError(w, http.StatusNotFound, "not found")
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
