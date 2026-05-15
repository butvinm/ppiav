package rservice

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/butvinm/ppiav/internal/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestServer() *Server {
	return NewServer(New(), "http://vagent.local", "")
}

func TestHTTPGetProtected_NoCookie(t *testing.T) {
	srv := newTestServer()

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	require.Equal(t, http.StatusForbidden, w.Code)
	require.Equal(t, "text/html; charset=utf-8", w.Header().Get("Content-Type"))
	body := w.Body.String()
	assert.Contains(t, body, "verdict: unknown")
}

func TestHTTPGetProtected_CookieAccept(t *testing.T) {
	srv := newTestServer()
	require.NoError(t, srv.svc.AcceptVerdict("sid-1", protocol.VerdictAccept))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "sid", Value: "sid-1"})
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "verdict: accept")
	assert.Contains(t, body, "sid-1")
}

func TestHTTPGetProtected_CookieReject(t *testing.T) {
	srv := newTestServer()
	require.NoError(t, srv.svc.AcceptVerdict("sid-2", protocol.VerdictReject))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "sid", Value: "sid-2"})
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	require.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "verdict: reject")
}

func TestHTTPGetProtected_CookieUnknownSid(t *testing.T) {
	srv := newTestServer()

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "sid", Value: "not-seen-before"})
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	require.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "verdict: unknown")
}

func TestHTTPGetProtected_RejectsPost(t *testing.T) {
	srv := newTestServer()

	req := httptest.NewRequest(http.MethodPost, "/protected", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	require.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestHTTPCallback_AcceptUpsertsVerdict(t *testing.T) {
	srv := newTestServer()

	payload, err := json.Marshal(protocol.VerdictNotification{Verdict: protocol.VerdictAccept})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/callback/sid-cb-1", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, protocol.VerdictAccept, srv.svc.CheckAccess("sid-cb-1"))
}

func TestHTTPCallback_RejectUpsertsVerdict(t *testing.T) {
	srv := newTestServer()

	payload, err := json.Marshal(protocol.VerdictNotification{Verdict: protocol.VerdictReject})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/callback/sid-cb-2", bytes.NewReader(payload))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, protocol.VerdictReject, srv.svc.CheckAccess("sid-cb-2"))
}

func TestHTTPCallback_MalformedJSONReturns400(t *testing.T) {
	srv := newTestServer()

	req := httptest.NewRequest(http.MethodPost, "/api/callback/sid-bad", bytes.NewReader([]byte("{not json")))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
	var body errorBody
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.NotEmpty(t, body.Error)
	// Service must not have stored anything.
	assert.Equal(t, protocol.VerdictUnknown, srv.svc.CheckAccess("sid-bad"))
}

func TestHTTPCallback_UnknownVerdictReturns400(t *testing.T) {
	srv := newTestServer()

	payload, err := json.Marshal(protocol.VerdictNotification{Verdict: protocol.VerdictUnknown})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/callback/sid-unknown", bytes.NewReader(payload))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
	var body errorBody
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.NotEmpty(t, body.Error)
}

func TestHTTPCallback_RejectsGet(t *testing.T) {
	srv := newTestServer()

	req := httptest.NewRequest(http.MethodGet, "/api/callback/sid-x", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	require.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestHTTPCallback_MissingSidReturns404(t *testing.T) {
	srv := newTestServer()

	cases := []struct {
		name string
		path string
	}{
		{"empty sid", "/api/callback/"},
		{"trailing slash", "/api/callback/sid/"},
		{"nested path", "/api/callback/sid/extra"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(`{"Verdict":1}`))
			w := httptest.NewRecorder()
			srv.Handler().ServeHTTP(w, req)
			require.Equal(t, http.StatusNotFound, w.Code)
		})
	}
}

func TestHTTPCallback_FollowedByProtected(t *testing.T) {
	// End-to-end through the handler: post a verdict, then read it back
	// via /protected with the matching cookie.
	srv := newTestServer()

	payload, err := json.Marshal(protocol.VerdictNotification{Verdict: protocol.VerdictAccept})
	require.NoError(t, err)

	cbReq := httptest.NewRequest(http.MethodPost, "/api/callback/sid-e2e", bytes.NewReader(payload))
	cbW := httptest.NewRecorder()
	srv.Handler().ServeHTTP(cbW, cbReq)
	require.Equal(t, http.StatusOK, cbW.Code)

	getReq := httptest.NewRequest(http.MethodGet, "/protected", nil)
	getReq.AddCookie(&http.Cookie{Name: "sid", Value: "sid-e2e"})
	getW := httptest.NewRecorder()
	srv.Handler().ServeHTTP(getW, getReq)
	require.Equal(t, http.StatusOK, getW.Code)
	assert.Contains(t, getW.Body.String(), "verdict: accept")
}
