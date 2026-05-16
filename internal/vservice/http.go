package vservice

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/butvinm/ppiav/internal/httputil"
	"github.com/butvinm/ppiav/internal/protocol"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

// Server exposes the VService HTTP routes. See docs/DESIGN.md §`Protocol`.
type Server struct {
	svc *Service
	mux *http.ServeMux
}

// NewServer is named NewServer (not New) to avoid shadowing vservice.New.
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
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if err := writeParams(w, s.svc.Params()); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
}

func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	sid, err := s.svc.OpenSession()
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	httputil.WriteJSON(w, http.StatusOK, protocol.VerificationSession{SessionID: sid})
}

// handleSession dispatches /sessions/:sid/<sub>. Stdlib ServeMux gives us
// the bare prefix match; we parse the remaining path ourselves.
func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/sessions/")
	if rest == "" || rest == r.URL.Path {
		httputil.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	sid, sub, ok := strings.Cut(rest, "/")
	if !ok || sid == "" || sub == "" {
		httputil.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	switch sub {
	case "eval-keys":
		s.handleEvalKeys(w, r, protocol.SessionID(sid))
	case "image":
		s.handleImage(w, r, protocol.SessionID(sid))
	default:
		httputil.WriteError(w, http.StatusNotFound, "not found")
	}
}

func (s *Server) handleEvalKeys(w http.ResponseWriter, r *http.Request, sid protocol.SessionID) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, httputil.MaxEvalKeysBody))
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, fmt.Sprintf("read body: %s", err))
		return
	}
	var keys protocol.InferEvalKeys
	if err := keys.UnmarshalBinary(body); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, fmt.Sprintf("unmarshal InferEvalKeys: %s", err))
		return
	}
	// TODO(task 7): wire `keys.PKTop` + `keys.GKSMasterInfer` through
	// `hierkeys.LevelExpansion` to derive the full `gks_infer` set
	// VService stores. Until Task 7 lands, pass an empty Galois-key
	// slice — vservice tests fail by design under the Task 6 boundary.
	if err := s.svc.StoreEvalKeys(sid, keys.RLK, nil); err != nil {
		// Unknown sid is the only common error path here.
		if errors.Is(err, ErrUnknownSession) {
			httputil.WriteError(w, http.StatusNotFound, err.Error())
			return
		}
		httputil.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusOK)
}

// handleImage runs Stage 3 inference and returns the result ciphertext.
func (s *Server) handleImage(w http.ResponseWriter, r *http.Request, sid protocol.SessionID) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, httputil.MaxEvalKeysBody))
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, fmt.Sprintf("read body: %s", err))
		return
	}
	ct := &rlwe.Ciphertext{}
	if err := ct.UnmarshalBinary(body); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, fmt.Sprintf("unmarshal EncryptedImage: %s", err))
		return
	}
	out, err := s.svc.Infer(sid, ct)
	if err != nil {
		// errors.Is (not strings.Contains) because the synthetic-x² and Orion
		// paths wrap ErrNoEvaluator with different messages.
		if errors.Is(err, ErrUnknownSession) || errors.Is(err, ErrNoEvaluator) {
			httputil.WriteError(w, http.StatusNotFound, err.Error())
			return
		}
		httputil.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	outBytes, err := out.MarshalBinary()
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("marshal result ciphertext: %s", err))
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(outBytes)
}

// paramsWire is the JSON representation of protocol.Params. CKKS uses
// Lattigo's codec; the rest survives encoding/json untouched.
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
	httputil.WriteJSON(w, http.StatusOK, pw)
	return nil
}

