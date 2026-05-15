package vservice

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/butvinm/ppiav/internal/httputil"
	"github.com/butvinm/ppiav/internal/protocol"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

// Server wraps a *Service with the HTTP handlers VAgent uses to drive
// inference. Routes mirror docs/DESIGN.md §`Protocol` exactly:
//
//	GET  /params
//	POST /sessions
//	POST /sessions/:sid/eval-keys
//	POST /sessions/:sid/image
//
// JSON for control endpoints, application/octet-stream for share- and
// key-bearing endpoints (see docs/plans Technical Details).
type Server struct {
	svc *Service
	mux *http.ServeMux
}

// NewServer wires a Server around `svc`. The constructor is named
// `NewServer` rather than `New` to avoid shadowing the existing
// `vservice.New(params)` Service constructor.
func NewServer(svc *Service) *Server {
	s := &Server{svc: svc, mux: http.NewServeMux()}
	s.register()
	return s
}

// Handler exposes the mux for use with httptest.NewServer / external
// composition.
func (s *Server) Handler() http.Handler { return s.mux }

// ListenAndServe boots an http.Server on addr.
func (s *Server) ListenAndServe(addr string) error {
	srv := &http.Server{Addr: addr, Handler: s.mux}
	return srv.ListenAndServe()
}

func (s *Server) register() {
	s.mux.HandleFunc("/params", s.handleParams)
	s.mux.HandleFunc("/sessions", s.handleSessions)
	// Subroutes under /sessions/:sid/... are dispatched by handleSession.
	s.mux.HandleFunc("/sessions/", s.handleSession)
}

func (s *Server) handleParams(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if err := writeParams(w, s.svc.Params()); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
}

func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	sid, err := s.svc.OpenSession()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, protocol.VerificationSession{SessionID: sid})
}

// handleSession dispatches /sessions/:sid/<sub>. Stdlib ServeMux gives us
// the bare prefix match; we parse the remaining path ourselves.
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
	switch sub {
	case "eval-keys":
		s.handleEvalKeys(w, r, protocol.SessionID(sid))
	case "image":
		s.handleImage(w, r, protocol.SessionID(sid))
	default:
		writeError(w, http.StatusNotFound, "not found")
	}
}

func (s *Server) handleEvalKeys(w http.ResponseWriter, r *http.Request, sid protocol.SessionID) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, httputil.MaxCiphertextBody))
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("read body: %s", err))
		return
	}
	var keys protocol.InferEvalKeys
	if err := keys.UnmarshalBinary(body); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unmarshal InferEvalKeys: %s", err))
		return
	}
	if err := s.svc.StoreEvalKeys(sid, keys.RLK, keys.GKS); err != nil {
		// Unknown sid is the only common error path here.
		if strings.Contains(err.Error(), "unknown session") {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusOK)
}

// handleImage runs Stage 3: read the client's `EncryptedImage.Ct` bytes,
// unmarshal into an *rlwe.Ciphertext, run `svc.Infer` to produce the
// result ciphertext, and write its MarshalBinary back as
// application/octet-stream. The wire encoding is the bare ciphertext (no
// JSON envelope) — same convention as the keygen handlers in VAgent's
// http.go. Errors map per docs/DESIGN.md §`Failure modes`:
//   - unknown sid → 404 (no evaluator → caller hasn't completed Stage 2d)
//   - malformed body → 400 (F2 wire-shape violation)
//   - infer failure (level exhaustion, Orion graph error) → 500
func (s *Server) handleImage(w http.ResponseWriter, r *http.Request, sid protocol.SessionID) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, httputil.MaxCiphertextBody))
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("read body: %s", err))
		return
	}
	ct := &rlwe.Ciphertext{}
	if err := ct.UnmarshalBinary(body); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unmarshal EncryptedImage: %s", err))
		return
	}
	out, err := s.svc.Infer(sid, ct)
	if err != nil {
		if strings.Contains(err.Error(), "unknown session") || strings.Contains(err.Error(), "no evaluator") {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	outBytes, err := out.MarshalBinary()
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("marshal result ciphertext: %s", err))
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(outBytes)
}

// paramsWire is the JSON representation of protocol.Params on the wire.
// `ckks.Parameters` is JSON-marshaled directly (Lattigo provides the codec);
// the rest of Params is small scalar config that survives `encoding/json`
// untouched. Phase 4 may swap CKKS for a precomputed manifest.
type paramsWire struct {
	CKKS                 json.RawMessage `json:"ckks"`
	AuthenticatorLambda  int             `json:"authenticator_lambda"`
	AuthenticatorEpsilon float64         `json:"authenticator_epsilon"`
	FloodSigma           float64         `json:"flood_sigma"`
	ExtraRotationIndices []int           `json:"extra_rotation_indices,omitempty"`
	InputLevel           int             `json:"input_level"`
}

func writeParams(w http.ResponseWriter, p protocol.Params) error {
	ckksBytes, err := p.CKKS.MarshalJSON()
	if err != nil {
		return fmt.Errorf("marshal CKKS params: %w", err)
	}
	pw := paramsWire{
		CKKS:                 ckksBytes,
		AuthenticatorLambda:  p.Authenticator.Lambda,
		AuthenticatorEpsilon: p.Authenticator.Epsilon,
		FloodSigma:           p.FloodSigma,
		ExtraRotationIndices: p.ExtraRotationIndices,
		InputLevel:           p.InputLevel,
	}
	writeJSON(w, http.StatusOK, pw)
	return nil
}

// errorBody re-exports the shared JSON error wire shape for tests that
// previously unmarshaled `errorBody` directly. Implementation now lives
// in internal/httputil.
type errorBody = httputil.ErrorBody

var (
	writeJSON  = httputil.WriteJSON
	writeError = httputil.WriteError
)

// Compile-time check that handler functions match http.HandlerFunc.
var _ http.HandlerFunc = (&Server{}).handleParams
