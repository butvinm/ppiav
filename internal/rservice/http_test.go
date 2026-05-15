package rservice

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/butvinm/ppiav/internal/httputil"
	"github.com/butvinm/ppiav/internal/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestServer builds a Server pointing at `vagentURL` (defaulting to a
// dead address when empty). `publicURL` overrides the browser-visible
// URL — leave empty to fall back to vagentURL.
func newTestServer(vagentURL, publicURL string) *Server {
	if vagentURL == "" {
		vagentURL = "http://vagent.local"
	}
	return NewServer(New(), vagentURL, publicURL)
}

func TestHTTPGetProtected_CookieAccept(t *testing.T) {
	srv := newTestServer("", "")
	require.NoError(t, srv.svc.AcceptVerdict("sid-1", protocol.VerdictAccept))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "sid", Value: "sid-1"})
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, `"verdict":"accept"`)
	assert.Contains(t, body, `"sid":"sid-1"`)
}

func TestHTTPGetProtected_CookieReject(t *testing.T) {
	srv := newTestServer("", "")
	require.NoError(t, srv.svc.AcceptVerdict("sid-2", protocol.VerdictReject))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "sid", Value: "sid-2"})
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	require.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), `"verdict":"reject"`)
	assert.Contains(t, w.Body.String(), `"sid":"sid-2"`)
}

// A stale or never-finished sid (CheckAccess returns VerdictUnknown) is
// indistinguishable from a brand-new visitor in terms of next action:
// restart Stage 1. /protected must redirect via VAgent and overwrite the
// cookie with a fresh sid.
func TestHTTPGetProtected_CookieUnknownSidRedirectsViaVAgent(t *testing.T) {
	var calls int
	vagent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/sessions", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(protocol.VerificationSession{SessionID: "sid-fresh"})
	}))
	defer vagent.Close()

	srv := newTestServer(vagent.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "sid", Value: "not-seen-before"})
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	require.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, 1, calls, "vagent /sessions hit exactly once")
	assert.Equal(t, vagent.URL+"/verify?sid=sid-fresh", w.Header().Get("Location"))

	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	c := cookies[0]
	assert.Equal(t, "sid", c.Name)
	assert.Equal(t, "sid-fresh", c.Value, "stale sid overwritten with fresh allocation")
}

func TestHTTPGetProtected_RejectsPost(t *testing.T) {
	srv := newTestServer("", "")

	req := httptest.NewRequest(http.MethodPost, "/protected", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	require.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestHTTPCallback_AcceptUpsertsVerdict(t *testing.T) {
	srv := newTestServer("", "")

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
	srv := newTestServer("", "")

	payload, err := json.Marshal(protocol.VerdictNotification{Verdict: protocol.VerdictReject})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/callback/sid-cb-2", bytes.NewReader(payload))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, protocol.VerdictReject, srv.svc.CheckAccess("sid-cb-2"))
}

func TestHTTPCallback_MalformedJSONReturns400(t *testing.T) {
	srv := newTestServer("", "")

	req := httptest.NewRequest(http.MethodPost, "/api/callback/sid-bad", bytes.NewReader([]byte("{not json")))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
	var body httputil.ErrorBody
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.NotEmpty(t, body.Error)
	// Service must not have stored anything.
	assert.Equal(t, protocol.VerdictUnknown, srv.svc.CheckAccess("sid-bad"))
}

func TestHTTPCallback_UnknownVerdictReturns400(t *testing.T) {
	srv := newTestServer("", "")

	payload, err := json.Marshal(protocol.VerdictNotification{Verdict: protocol.VerdictUnknown})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/callback/sid-unknown", bytes.NewReader(payload))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
	var body httputil.ErrorBody
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.NotEmpty(t, body.Error)
}

// Empty body on /api/callback is a wire-shape violation ⇒ 400.
func TestHTTPCallback_EmptyBodyReturns400(t *testing.T) {
	srv := newTestServer("", "")
	req := httptest.NewRequest(http.MethodPost, "/api/callback/sid-empty", bytes.NewReader(nil))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, protocol.VerdictUnknown, srv.svc.CheckAccess("sid-empty"))
}

func TestHTTPCallback_RejectsGet(t *testing.T) {
	srv := newTestServer("", "")

	req := httptest.NewRequest(http.MethodGet, "/api/callback/sid-x", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	require.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestHTTPCallback_MissingSidReturns404(t *testing.T) {
	srv := newTestServer("", "")

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

// `GET /protected` serves the embedded RClient index.html with the
// verdict script injected before `</body>`.
func TestHTTPGetProtected_EmbedsRClientHTML(t *testing.T) {
	srv := newTestServer("", "")
	require.NoError(t, srv.svc.AcceptVerdict("sid-embed", protocol.VerdictAccept))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "sid", Value: "sid-embed"})
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	// Embedded RClient bootstrap reference.
	assert.Contains(t, body, `./dist/main.js`)
	// Injected verdict block sits before </body>.
	assert.Contains(t, body, `<script>window.verdict = `)
	assert.Contains(t, body, `"sid":"sid-embed"`)
	assert.Contains(t, body, `"verdict":"accept"`)
	scriptIdx := strings.Index(body, `<script>window.verdict =`)
	bodyEndIdx := strings.LastIndex(body, `</body>`)
	require.GreaterOrEqual(t, scriptIdx, 0)
	require.Greater(t, bodyEndIdx, scriptIdx)
}

// `/dist/main.js` is served from the embedded RClient FS.
func TestHTTPRClientDist_ReturnsJS(t *testing.T) {
	srv := newTestServer("", "")
	req := httptest.NewRequest(http.MethodGet, "/dist/main.js", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	// Go's http.FileServer sniffs Content-Type from the .js extension.
	assert.Contains(t, w.Header().Get("Content-Type"), "javascript")
	assert.NotEmpty(t, w.Body.Bytes())
}

// Stage-1: no sid cookie triggers a server-to-server VAgent `POST
// /sessions`, RService sets the sid cookie and 302s to `/verify?sid=...`.
func TestHTTPGetProtected_NoCookieRedirectsViaVAgent(t *testing.T) {
	var calls int
	vagent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/sessions", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(protocol.VerificationSession{SessionID: "sid-stage1"})
	}))
	defer vagent.Close()

	srv := newTestServer(vagent.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	require.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, 1, calls, "vagent /sessions hit exactly once")
	assert.Equal(t, vagent.URL+"/verify?sid=sid-stage1", w.Header().Get("Location"))

	// Set-Cookie must be sent on the success path.
	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	c := cookies[0]
	assert.Equal(t, "sid", c.Name)
	assert.Equal(t, "sid-stage1", c.Value)
	assert.Equal(t, "/", c.Path)
	assert.True(t, c.HttpOnly, "HttpOnly cookie")
}

// F4a: VAgent returns 5xx ⇒ RService surfaces 5xx with no cookie.
func TestHTTPGetProtected_NoCookieVAgent5xx_NoSetCookie(t *testing.T) {
	vagent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer vagent.Close()

	srv := newTestServer(vagent.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	require.GreaterOrEqual(t, w.Code, 500)
	require.Less(t, w.Code, 600)
	assert.Empty(t, w.Header().Get("Location"), "no redirect on failure")
	assert.Empty(t, w.Result().Cookies(), "no Set-Cookie on failure (F4a)")
}

// F4a: VAgent unreachable (connection refused) ⇒ RService 5xx, no cookie.
func TestHTTPGetProtected_NoCookieVAgentUnreachable_NoSetCookie(t *testing.T) {
	vagent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	addr := vagent.URL
	vagent.Close()

	srv := newTestServer(addr, "")
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	require.GreaterOrEqual(t, w.Code, 500)
	require.Less(t, w.Code, 600)
	assert.Empty(t, w.Header().Get("Location"), "no redirect on failure")
	assert.Empty(t, w.Result().Cookies(), "no Set-Cookie on failure (F4a)")
}

// Malformed VerificationSession from VAgent ⇒ 5xx, no cookie.
func TestHTTPGetProtected_NoCookieVAgentBadJSON_NoSetCookie(t *testing.T) {
	vagent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{not json"))
	}))
	defer vagent.Close()

	srv := newTestServer(vagent.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	require.GreaterOrEqual(t, w.Code, 500)
	require.Less(t, w.Code, 600)
	assert.Empty(t, w.Result().Cookies())
}

// Empty sid from VAgent ⇒ 5xx, no cookie.
func TestHTTPGetProtected_NoCookieVAgentEmptySid_NoSetCookie(t *testing.T) {
	vagent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(protocol.VerificationSession{SessionID: ""})
	}))
	defer vagent.Close()

	srv := newTestServer(vagent.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	require.GreaterOrEqual(t, w.Code, 500)
	require.Less(t, w.Code, 600)
	assert.Empty(t, w.Result().Cookies())
}

// NewServer must trim trailing slashes on vagentURL and vagentPublicURL
// so `--vagent-url http://localhost:8081/` does not produce `//sessions`.
func TestNewServerTrimsTrailingSlash(t *testing.T) {
	srv := NewServer(New(), "http://vagent.local/", "http://public.local/")
	assert.Equal(t, "http://vagent.local", srv.vagentURL)
	assert.Equal(t, "http://public.local", srv.vagentPublicURL)
}

// When vagentPublicURL differs from vagentURL, the redirect Location
// points at the public (browser-visible) URL while the server-to-server
// POST still hits vagentURL.
func TestHTTPGetProtected_UsesPublicURLInRedirect(t *testing.T) {
	var calls int
	vagent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(protocol.VerificationSession{SessionID: "sid-pub"})
	}))
	defer vagent.Close()

	const browserURL = "http://browser.local:9999"
	srv := newTestServer(vagent.URL, browserURL)
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	require.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, 1, calls)
	// Redirect must point at the public URL, not the docker-internal URL.
	assert.Equal(t, browserURL+"/verify?sid=sid-pub", w.Header().Get("Location"))
}

func TestHTTPCallback_FollowedByProtected(t *testing.T) {
	// End-to-end through the handler: post a verdict, then read it back
	// via /protected with the matching cookie.
	srv := newTestServer("", "")

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
	assert.Contains(t, getW.Body.String(), `"verdict":"accept"`)
	assert.Contains(t, getW.Body.String(), `"sid":"sid-e2e"`)
}

