package vservice

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/butvinm/ppiav/internal/httputil"
	"github.com/butvinm/ppiav/internal/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// httpSvcParams returns a small Service+Params pair for HTTP handler
// tests. Reuses the LogN=14 fixture from `smallParams` (infer_test.go)
// for speed.
func httpSvcParams(t *testing.T) (*Service, protocol.Params) {
	t.Helper()
	params := smallParams(t)
	return New(params), params
}

func TestHTTPGetParams(t *testing.T) {
	svc, params := httpSvcParams(t)
	srv := NewServer(svc)

	req := httptest.NewRequest(http.MethodGet, "/params", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var wire paramsWire
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &wire))
	assert.Equal(t, params.Authenticator.Lambda, wire.AuthenticatorLambda)
	assert.Equal(t, params.Authenticator.Epsilon, wire.AuthenticatorEpsilon)
	assert.Equal(t, params.FloodSigma, wire.FloodSigma)
	assert.Equal(t, params.InputLevel, wire.InputLevel)
	assert.NotEmpty(t, wire.CKKS, "CKKS params JSON should be embedded")
}

func TestHTTPGetParamsRejectsPost(t *testing.T) {
	svc, _ := httpSvcParams(t)
	srv := NewServer(svc)

	req := httptest.NewRequest(http.MethodPost, "/params", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	require.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestHTTPOpenSession(t *testing.T) {
	svc, _ := httpSvcParams(t)
	srv := NewServer(svc)

	const n = 5
	seen := map[protocol.SessionID]struct{}{}
	for i := 0; i < n; i++ {
		req := httptest.NewRequest(http.MethodPost, "/sessions", nil)
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code, "POST /sessions iteration %d", i)
		var sess protocol.VerificationSession
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &sess))
		require.NotEmpty(t, string(sess.SessionID))

		_, dup := seen[sess.SessionID]
		require.False(t, dup, "sids must be distinct across POST /sessions calls")
		seen[sess.SessionID] = struct{}{}
	}
}

func TestHTTPOpenSessionRejectsGet(t *testing.T) {
	svc, _ := httpSvcParams(t)
	srv := NewServer(svc)

	req := httptest.NewRequest(http.MethodGet, "/sessions", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	require.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestHTTPStoreEvalKeysHappyPath(t *testing.T) {
	svc, params := httpSvcParams(t)
	srv := NewServer(svc)

	// Open a session via the HTTP route, then POST eval-keys for it.
	openReq := httptest.NewRequest(http.MethodPost, "/sessions", nil)
	openW := httptest.NewRecorder()
	srv.Handler().ServeHTTP(openW, openReq)
	require.Equal(t, http.StatusOK, openW.Code)
	var sess protocol.VerificationSession
	require.NoError(t, json.Unmarshal(openW.Body.Bytes(), &sess))

	// Build a minimal but valid eval-keys payload. The x² circuit uses no
	// rotations, so a non-empty rlk + empty GKS slice is the cheapest
	// fixture.
	kgen := rlwe.NewKeyGenerator(params.CKKS)
	sk := kgen.GenSecretKeyNew()
	rlk := kgen.GenRelinearizationKeyNew(sk)
	payload, err := protocol.InferEvalKeys{RLK: rlk, GKS: nil}.MarshalBinary()
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/sessions/"+string(sess.SessionID)+"/eval-keys", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/octet-stream")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code, "body=%s", w.Body.String())
}

func TestHTTPStoreEvalKeysUnknownSid(t *testing.T) {
	svc, params := httpSvcParams(t)
	srv := NewServer(svc)

	kgen := rlwe.NewKeyGenerator(params.CKKS)
	sk := kgen.GenSecretKeyNew()
	rlk := kgen.GenRelinearizationKeyNew(sk)
	payload, err := protocol.InferEvalKeys{RLK: rlk}.MarshalBinary()
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/sessions/does-not-exist/eval-keys", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/octet-stream")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	require.Equal(t, http.StatusNotFound, w.Code)
	var body httputil.ErrorBody
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Contains(t, body.Error, "unknown session")
}

func TestHTTPStoreEvalKeysMalformedBody(t *testing.T) {
	svc, _ := httpSvcParams(t)
	srv := NewServer(svc)

	// Open a session so the 400 path isn't masked by a 404.
	openReq := httptest.NewRequest(http.MethodPost, "/sessions", nil)
	openW := httptest.NewRecorder()
	srv.Handler().ServeHTTP(openW, openReq)
	require.Equal(t, http.StatusOK, openW.Code)
	var sess protocol.VerificationSession
	require.NoError(t, json.Unmarshal(openW.Body.Bytes(), &sess))

	req := httptest.NewRequest(http.MethodPost, "/sessions/"+string(sess.SessionID)+"/eval-keys", bytes.NewReader([]byte{0x00, 0x01, 0x02}))
	req.Header.Set("Content-Type", "application/octet-stream")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
	var body httputil.ErrorBody
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.NotEmpty(t, body.Error)
}

func TestHTTPStoreEvalKeysRejectsGet(t *testing.T) {
	svc, _ := httpSvcParams(t)
	srv := NewServer(svc)

	req := httptest.NewRequest(http.MethodGet, "/sessions/abc/eval-keys", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	require.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

// TestHTTPImageHappyPath drives POST /sessions/:sid/image end-to-end:
// open a session, store eval keys, encrypt 0.3 under the same pk, POST
// the marshaled ct, parse back the result, decrypt, verify 0.3² ≈ 0.09.
func TestHTTPImageHappyPath(t *testing.T) {
	svc, params := httpSvcParams(t)
	srv := NewServer(svc)

	sid, err := svc.OpenSession()
	require.NoError(t, err)

	kgen := rlwe.NewKeyGenerator(params.CKKS)
	sk, pk := kgen.GenKeyPairNew()
	rlk := kgen.GenRelinearizationKeyNew(sk)
	require.NoError(t, svc.StoreEvalKeys(sid, rlk, nil))

	encoder := ckks.NewEncoder(params.CKKS)
	encryptor := rlwe.NewEncryptor(params.CKKS, pk)
	decryptor := rlwe.NewDecryptor(params.CKKS, sk)

	values := make([]float64, params.CKKS.MaxSlots())
	values[0] = 0.3
	pt := ckks.NewPlaintext(params.CKKS, params.CKKS.MaxLevel())
	require.NoError(t, encoder.Encode(values, pt))
	inputCt, err := encryptor.EncryptNew(pt)
	require.NoError(t, err)
	inputBytes, err := inputCt.MarshalBinary()
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/sessions/"+string(sid)+"/image", bytes.NewReader(inputBytes))
	req.Header.Set("Content-Type", "application/octet-stream")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code, "body=%s", w.Body.String())
	assert.Contains(t, w.Header().Get("Content-Type"), "application/octet-stream")

	respBody, err := io.ReadAll(w.Body)
	require.NoError(t, err)
	outCt := &rlwe.Ciphertext{}
	require.NoError(t, outCt.UnmarshalBinary(respBody))

	decoded := make([]float64, params.CKKS.MaxSlots())
	require.NoError(t, encoder.Decode(decryptor.DecryptNew(outCt), decoded))
	assert.InDelta(t, 0.09, decoded[0], 1e-4, "image POST must apply x² circuit")
}

func TestHTTPImageUnknownSid(t *testing.T) {
	svc, params := httpSvcParams(t)
	srv := NewServer(svc)

	// Build a syntactically valid ciphertext so the body parses; only the
	// sid is missing. Without StoreEvalKeys, Infer surfaces "unknown session"
	// or "no evaluator" — both map to 404 per handleImage.
	kgen := rlwe.NewKeyGenerator(params.CKKS)
	_, pk := kgen.GenKeyPairNew()
	encoder := ckks.NewEncoder(params.CKKS)
	encryptor := rlwe.NewEncryptor(params.CKKS, pk)
	values := make([]float64, params.CKKS.MaxSlots())
	pt := ckks.NewPlaintext(params.CKKS, params.CKKS.MaxLevel())
	require.NoError(t, encoder.Encode(values, pt))
	ct, err := encryptor.EncryptNew(pt)
	require.NoError(t, err)
	body, err := ct.MarshalBinary()
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/sessions/does-not-exist/image", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/octet-stream")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	require.Equal(t, http.StatusNotFound, w.Code, "body=%s", w.Body.String())
	var berr httputil.ErrorBody
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &berr))
	assert.NotEmpty(t, berr.Error)
}

func TestHTTPImageMalformedBody(t *testing.T) {
	svc, _ := httpSvcParams(t)
	srv := NewServer(svc)

	sid, err := svc.OpenSession()
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/sessions/"+string(sid)+"/image", bytes.NewReader([]byte{0xff, 0xff, 0xff}))
	req.Header.Set("Content-Type", "application/octet-stream")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
	var body httputil.ErrorBody
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.NotEmpty(t, body.Error)
}

func TestHTTPImageRejectsGet(t *testing.T) {
	svc, _ := httpSvcParams(t)
	srv := NewServer(svc)

	req := httptest.NewRequest(http.MethodGet, "/sessions/abc/image", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	require.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestHTTPUnknownPath(t *testing.T) {
	svc, _ := httpSvcParams(t)
	srv := NewServer(svc)

	cases := []struct {
		name string
		path string
	}{
		{"empty sid", "/sessions/"},
		{"empty sub", "/sessions/sid/"},
		{"unknown sub", "/sessions/sid/whatever"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tc.path, nil)
			w := httptest.NewRecorder()
			srv.Handler().ServeHTTP(w, req)
			require.Equal(t, http.StatusNotFound, w.Code)
		})
	}
}
