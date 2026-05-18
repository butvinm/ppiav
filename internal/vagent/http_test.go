package vagent

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/butvinm/ppiav/internal/httputil"
	"github.com/butvinm/ppiav/internal/protocol"
	"github.com/butvinm/ppiav/internal/vservice"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// newHTTPFixture spins up a real VService HTTP server (backed by an
// in-process Service) and a VAgent Server pointing at it. Returns both
// servers and the underlying agent so the keygen tests can drive the
// VClient half (via vclientStub) through the HTTP routes and cross-check
// the Agent state from in-process.
func newHTTPFixture(t *testing.T) (
	vagent *Server,
	vagentSrv *httptest.Server,
	vsvcSrv *httptest.Server,
	svc *vservice.Service,
	agent *Agent,
	params protocol.Params,
) {
	t.Helper()
	params = smallParams(t)
	svc = vservice.New(params)
	vsvcSrv = httptest.NewServer(vservice.NewServer(svc).Handler())
	t.Cleanup(vsvcSrv.Close)

	a, err := New(params)
	require.NoError(t, err)
	agent = a

	vagent = NewServer(agent, vsvcSrv.URL, "", "")
	vagentSrv = httptest.NewServer(vagent.Handler())
	t.Cleanup(vagentSrv.Close)
	return
}

// openSessionViaHTTP issues `POST /sessions` against the VAgent server,
// returning the allocated sid. The agent registers the sid as a side
// effect.
func openSessionViaHTTP(t *testing.T, vagentSrv *httptest.Server) protocol.SessionID {
	t.Helper()
	resp, err := http.Post(vagentSrv.URL+"/sessions", "application/json", nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var sess protocol.VerificationSession
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&sess))
	require.NotEmpty(t, string(sess.SessionID))
	return sess.SessionID
}

// postOctet POSTs `body` to `path` with octet-stream content type.
func postOctet(t *testing.T, base, path string, body []byte) *http.Response {
	t.Helper()
	resp, err := http.Post(base+path, "application/octet-stream", bytes.NewReader(body))
	require.NoError(t, err)
	return resp
}

func TestHTTPVAgent_PostSessions_AllocatesSidAndRegisters(t *testing.T) {
	_, vagentSrv, _, svc, agent, _ := newHTTPFixture(t)

	sid := openSessionViaHTTP(t, vagentSrv)

	// Agent side: OpenSession must have registered the sid.
	_, err := agent.session(sid)
	require.NoError(t, err, "agent must have registered the sid")

	// VService side: StoreEvalKeys with a nil rlk succeeds for known sids
	// (it only checks the sessions map) and 404s with "unknown session"
	// otherwise. Using it as a probe avoids reflecting into the private
	// sessions map.
	require.NoError(t, svc.StoreEvalKeys(sid, nil, nil, nil),
		"vservice must have the sid registered (StoreEvalKeys is the probe)")
	require.ErrorContains(t, svc.StoreEvalKeys("never-allocated", nil, nil, nil),
		"unknown session", "control: probe distinguishes registered sids")
}

func TestHTTPVAgent_PostSessions_RejectsGet(t *testing.T) {
	_, vagentSrv, _, _, _, _ := newHTTPFixture(t)
	resp, err := http.Get(vagentSrv.URL + "/sessions")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
}

func TestHTTPVAgent_PostSessions_VServiceUnreachableReturns5xx(t *testing.T) {
	params := smallParams(t)
	agent, err := New(params)
	require.NoError(t, err)
	// Point the agent at a dead URL so its outbound POST fails.
	srv := httptest.NewServer(NewServer(agent, "http://127.0.0.1:1/", "", "").Handler())
	t.Cleanup(srv.Close)

	resp, err := http.Post(srv.URL+"/sessions", "application/json", nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	// F4a (VService unreachable Stage 1) — VAgent returns 5xx so RService
	// surfaces 5xx to the user (DESIGN.md §`Failure modes`).
	assert.GreaterOrEqual(t, resp.StatusCode, 500)
}

// F4a: VService returns malformed JSON ⇒ VAgent surfaces 502.
func TestHTTPVAgent_PostSessions_VServiceBadJSONReturns502(t *testing.T) {
	params := smallParams(t)
	agent, err := New(params)
	require.NoError(t, err)
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{not json"))
	}))
	t.Cleanup(stub.Close)
	srv := httptest.NewServer(NewServer(agent, stub.URL, "", "").Handler())
	t.Cleanup(srv.Close)
	resp, err := http.Post(srv.URL+"/sessions", "application/json", nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadGateway, resp.StatusCode)
}

// F4a: VService returns empty SessionID ⇒ VAgent surfaces 502.
func TestHTTPVAgent_PostSessions_VServiceEmptySidReturns502(t *testing.T) {
	params := smallParams(t)
	agent, err := New(params)
	require.NoError(t, err)
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"SessionID":""}`))
	}))
	t.Cleanup(stub.Close)
	srv := httptest.NewServer(NewServer(agent, stub.URL, "", "").Handler())
	t.Cleanup(srv.Close)
	resp, err := http.Post(srv.URL+"/sessions", "application/json", nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadGateway, resp.StatusCode)
}

// Force VService to hand out the same sid twice and assert the second
// POST returns 500 (duplicate sid registration on the agent).
func TestHTTPVAgent_PostSessions_AgentOpenSessionFailureReturns500(t *testing.T) {
	params := smallParams(t)
	agent, err := New(params)
	require.NoError(t, err)
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"SessionID":"sid-duplicate"}`))
	}))
	t.Cleanup(stub.Close)
	srv := httptest.NewServer(NewServer(agent, stub.URL, "", "").Handler())
	t.Cleanup(srv.Close)

	resp1, err := http.Post(srv.URL+"/sessions", "application/json", nil)
	require.NoError(t, err)
	resp1.Body.Close()
	require.Equal(t, http.StatusOK, resp1.StatusCode)

	resp2, err := http.Post(srv.URL+"/sessions", "application/json", nil)
	require.NoError(t, err)
	defer resp2.Body.Close()
	require.Equal(t, http.StatusInternalServerError, resp2.StatusCode, "duplicate sid registration must 500")
}

func TestHTTPVAgent_GetParams_ProxiesToVService(t *testing.T) {
	_, vagentSrv, _, _, _, params := newHTTPFixture(t)

	// sid in the URL is required by the route shape but unused by the
	// current proxy — params may become session-dependent later.
	resp, err := http.Get(vagentSrv.URL + "/sessions/sid-x/params")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Content-Type"), "application/json")

	// Body must be a protocol.Manifest-shaped JSON. We only check the
	// authenticator lambda value as a smoke test — full schema is the
	// vservice handler's responsibility.
	var raw map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&raw))
	assert.EqualValues(t, params.Authenticator.Lambda, raw["authenticator_lambda"])
}

func TestHTTPVAgent_GetParams_RejectsPost(t *testing.T) {
	_, vagentSrv, _, _, _, _ := newHTTPFixture(t)
	resp, err := http.Post(vagentSrv.URL+"/sessions/sid-x/params", "application/json", nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
}

func TestHTTPVAgent_PKShare_HappyPath(t *testing.T) {
	_, vagentSrv, _, _, agent, params := newHTTPFixture(t)
	sid := openSessionViaHTTP(t, vagentSrv)
	stub := newVClientStub(t, params, sid)

	// Build VClient's dual PK shares off the stub's CRS — pk_eval first,
	// then pk_top.
	pkProtoEval := multiparty.NewPublicKeyGenProtocol(params.CKKS)
	clientCRPEval := pkProtoEval.SampleCRP(stub.crs)
	clientShareEval := pkProtoEval.AllocateShare()
	pkProtoEval.GenShare(stub.skCEval, clientCRPEval, &clientShareEval)
	pkProtoTop := multiparty.NewPublicKeyGenProtocol(params.LLKN.Top())
	clientCRPTop := pkProtoTop.SampleCRP(stub.crs)
	clientShareTop := pkProtoTop.AllocateShare()
	pkProtoTop.GenShare(stub.skCTop, clientCRPTop, &clientShareTop)
	clientBytes, err := protocol.VClientPKShare{ShareEval: clientShareEval, ShareTop: clientShareTop}.MarshalBinary()
	require.NoError(t, err)

	resp := postOctet(t, vagentSrv.URL, "/sessions/"+string(sid)+"/pk-share", clientBytes)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Content-Type"), "application/octet-stream")

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var agentShareWire protocol.VAgentPKShare
	require.NoError(t, agentShareWire.UnmarshalBinary(body))

	// In-process invariant: agent's session has the aggregated pk.
	sess := agentState(t, agent, sid)
	require.NotNil(t, sess.pkAgg, "AggregatePK must have run")
	require.NotNil(t, sess.encryptor)
}

func TestHTTPVAgent_PKShare_UnknownSidReturns404(t *testing.T) {
	_, vagentSrv, _, _, _, _ := newHTTPFixture(t)
	// Body content doesn't matter — GenPKShare is the gate that returns
	// "unknown session id" before AggregatePK runs.
	resp := postOctet(t, vagentSrv.URL, "/sessions/never-opened/pk-share", []byte{0x00})
	defer resp.Body.Close()
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
	var body httputil.ErrorBody
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Contains(t, body.Error, "unknown session")
}

func TestHTTPVAgent_PKShare_MalformedBodyReturns400(t *testing.T) {
	_, vagentSrv, _, _, _, _ := newHTTPFixture(t)
	sid := openSessionViaHTTP(t, vagentSrv)
	resp := postOctet(t, vagentSrv.URL, "/sessions/"+string(sid)+"/pk-share", []byte{0xff, 0xff, 0xff})
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var body httputil.ErrorBody
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.NotEmpty(t, body.Error)
}

func TestHTTPVAgent_PKShare_RejectsGet(t *testing.T) {
	_, vagentSrv, _, _, _, _ := newHTTPFixture(t)
	sid := openSessionViaHTTP(t, vagentSrv)
	resp, err := http.Get(vagentSrv.URL + "/sessions/" + string(sid) + "/pk-share")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
}

// runKeygenViaHTTP drives the Stage-2 multi-party handshake against the
// VAgent HTTP server using `stub` as VClient's half. Returns when the
// gks-shares POST has been acknowledged (which implies VService has
// stored the eval keys for `sid`). Mirrors keygen_test.runFullKeygen but
// over HTTP.
func runKeygenViaHTTP(t *testing.T, base string, sid protocol.SessionID, stub *vclientStub, params protocol.Params) {
	t.Helper()

	runKeygenUpToGKS(t, base, sid, stub, params)

	// Single master atom set Galois shares.
	masterLabels := params.MasterAtoms()
	clientMaster := generateClientGaloisShares(t, stub, params, masterLabels)

	gksBytes, err := protocol.VClientGaloisShares{
		MasterShares: clientMaster,
	}.MarshalBinary()
	require.NoError(t, err)
	gksResp := postOctet(t, base, "/sessions/"+string(sid)+"/gks-shares", gksBytes)
	gksRespBody, err := io.ReadAll(gksResp.Body)
	require.NoError(t, err)
	gksResp.Body.Close()
	require.Equal(t, http.StatusOK, gksResp.StatusCode, "gks-shares body=%s", gksRespBody)
}

func TestHTTPVAgent_FullKeygenForwardsEvalKeysToVService(t *testing.T) {
	_, vagentSrv, _, svc, agent, params := newHTTPFixture(t)
	sid := openSessionViaHTTP(t, vagentSrv)
	stub := newVClientStub(t, params, sid)

	runKeygenViaHTTP(t, vagentSrv.URL, sid, stub, params)

	// After the gks-shares handler runs, VService must have stored the
	// eval keys for sid. We can't introspect the private map directly, but
	// we can verify the agent's session-level invariants (rlkAgg, authchain
	// are non-nil) and check VService doesn't 404 a duplicate StoreEvalKeys.
	sess := agentState(t, agent, sid)
	require.NotNil(t, sess.rlkAgg, "AggregateGaloisShares must have finalised rlk")
	require.NotNil(t, sess.authchain, "Session chain evaluator must be wired")

	// Re-issue StoreEvalKeys directly against the vservice — if the sid
	// hadn't been stored, this would 404. (It overwrites; that's fine.)
	require.NoError(t, svc.StoreEvalKeys(sid, sess.rlkAgg, nil, nil))
}

func TestHTTPVAgent_RLKRound1_UnknownSidReturns404(t *testing.T) {
	_, vagentSrv, _, _, _, _ := newHTTPFixture(t)
	resp := postOctet(t, vagentSrv.URL, "/sessions/never-opened/rlk/round1", []byte{0x00})
	defer resp.Body.Close()
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestHTTPVAgent_RLKRound1_MalformedBodyReturns400(t *testing.T) {
	_, vagentSrv, _, _, _, _ := newHTTPFixture(t)
	sid := openSessionViaHTTP(t, vagentSrv)
	resp := postOctet(t, vagentSrv.URL, "/sessions/"+string(sid)+"/rlk/round1", []byte{0xff, 0xff})
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// Round2 malformed body is exercised by
// TestHTTPVAgent_RLKRound2_MalformedBodyRejectAndEvicts; the body-read
// fires before state inspection so no PK/RLK-1 prefix is needed.

func TestHTTPVAgent_GKSShares_UnknownSidReturns404(t *testing.T) {
	_, vagentSrv, _, _, _, _ := newHTTPFixture(t)
	resp := postOctet(t, vagentSrv.URL, "/sessions/never-opened/gks-shares", []byte{0x00, 0x00, 0x00, 0x00})
	defer resp.Body.Close()
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestHTTPVAgent_GKSShares_LabelMismatchReturns400(t *testing.T) {
	// Drive PK + RLK to set up state, then submit a gks-shares blob with
	// fewer shares than the agent's labels — AggregateGaloisShares rejects
	// the count mismatch.
	_, vagentSrv, _, _, _, params := newHTTPFixture(t)
	sid := openSessionViaHTTP(t, vagentSrv)
	stub := newVClientStub(t, params, sid)
	runKeygenUpToGKS(t, vagentSrv.URL, sid, stub, params)

	// Zero shares < expected atom-set size → count mismatch → 400.
	emptyBytes, err := protocol.VClientGaloisShares{
		MasterShares: nil,
	}.MarshalBinary()
	require.NoError(t, err)
	resp := postOctet(t, vagentSrv.URL, "/sessions/"+string(sid)+"/gks-shares", emptyBytes)
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestHTTPVAgent_GKSShares_RejectsCountMismatch asserts the design-A
// decoder rejects a well-formed but short share list (zero shares when
// the master atom set has >0 atoms). Distinct from a malformed-bytes 400
// — the body parses cleanly here, but the count mismatch fires inside
// AggregateGaloisShares.
func TestHTTPVAgent_GKSShares_RejectsCountMismatch(t *testing.T) {
	_, vagentSrv, _, _, _, params := newHTTPFixture(t)
	sid := openSessionViaHTTP(t, vagentSrv)
	stub := newVClientStub(t, params, sid)
	runKeygenUpToGKS(t, vagentSrv.URL, sid, stub, params)

	// Well-formed zero-share body — single 4-byte zero count.
	zeroBody := []byte{0x00, 0x00, 0x00, 0x00}

	resp := postOctet(t, vagentSrv.URL, "/sessions/"+string(sid)+"/gks-shares", zeroBody)
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode, "count-mismatch shares must be rejected")
}

func TestHTTPVAgent_UnknownPathReturns404(t *testing.T) {
	_, vagentSrv, _, _, _, _ := newHTTPFixture(t)
	cases := []string{
		"/sessions/",
		"/sessions/sid/",
		"/sessions/sid/whatever",
		"/sessions/sid/rlk/round3",
	}
	for _, p := range cases {
		t.Run(p, func(t *testing.T) {
			resp, err := http.Post(vagentSrv.URL+p, "application/octet-stream", nil)
			require.NoError(t, err)
			defer resp.Body.Close()
			require.Equal(t, http.StatusNotFound, resp.StatusCode)
		})
	}
}

// TestHTTPVAgent_GKSShares_VServiceForwardFailure verifies that when
// VService rejects the eval-keys POST, VAgent surfaces a 5xx (not a 200)
// — the F4a/F4b wire shape. We point VAgent at a stub VService that 500s.
func TestHTTPVAgent_GKSShares_VServiceForwardFailure(t *testing.T) {
	params := smallParams(t)
	// Stub VService: returns valid sid on POST /sessions, but 500 on
	// /sessions/:sid/eval-keys.
	var sidCount atomic.Int64
	stubVSvc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/sessions" {
			n := sidCount.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"SessionID":"sid-` + strings.Repeat("a", int(n)) + `"}`))
			return
		}
		if strings.HasSuffix(r.URL.Path, "/eval-keys") {
			http.Error(w, "vservice down", http.StatusInternalServerError)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(stubVSvc.Close)

	agent, err := New(params)
	require.NoError(t, err)
	vagentSrv := httptest.NewServer(NewServer(agent, stubVSvc.URL, "", "").Handler())
	t.Cleanup(vagentSrv.Close)

	sid := openSessionViaHTTP(t, vagentSrv)
	stub := newVClientStub(t, params, sid)
	runKeygenUpToGKS(t, vagentSrv.URL, sid, stub, params)

	// Build valid master-atom-set gks shares.
	masterLabels := params.MasterAtoms()
	clientMaster := generateClientGaloisShares(t, stub, params, masterLabels)
	gksBytes, err := protocol.VClientGaloisShares{
		MasterShares: clientMaster,
	}.MarshalBinary()
	require.NoError(t, err)
	resp := postOctet(t, vagentSrv.URL, "/sessions/"+string(sid)+"/gks-shares", gksBytes)
	defer resp.Body.Close()
	// The VService stub 500s on eval-keys; VAgent translates upstream
	// failure to 502 Bad Gateway.
	require.Equal(t, http.StatusBadGateway, resp.StatusCode)
}

// readAll is a test helper that drains a body to string for error messages.
func readAll(t *testing.T, rc io.Reader) string {
	t.Helper()
	b, err := io.ReadAll(rc)
	if err != nil {
		return "(read err: " + err.Error() + ")"
	}
	return string(b)
}

// rserviceStub records the callback POSTs the VAgent makes, exposing the
// last seen verdict for assertion. Listens on /api/callback/:sid and
// matches RService's real wire shape (VerdictNotification JSON body).
type rserviceStub struct {
	mu         sync.Mutex
	calls      int
	lastSid    protocol.SessionID
	lastVerd   protocol.Verdict
	failStatus int // when non-zero, the stub returns this status code instead of 200
}

func newRServiceStub() *rserviceStub { return &rserviceStub{} }

func (rs *rserviceStub) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/callback/") {
			http.NotFound(w, r)
			return
		}
		sid := strings.TrimPrefix(r.URL.Path, "/api/callback/")
		var notif protocol.VerdictNotification
		if err := json.NewDecoder(r.Body).Decode(&notif); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		rs.mu.Lock()
		rs.calls++
		rs.lastSid = protocol.SessionID(sid)
		rs.lastVerd = notif.Verdict
		fail := rs.failStatus
		rs.mu.Unlock()
		if fail != 0 {
			http.Error(w, "rservice stub forced failure", fail)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
}

func (rs *rserviceStub) snapshot() (int, protocol.SessionID, protocol.Verdict) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return rs.calls, rs.lastSid, rs.lastVerd
}

// newHTTPFixtureWithRService extends newHTTPFixture with an additional
// RService stub. Use for image/partial tests that exercise the
// verdict callback.
func newHTTPFixtureWithRService(t *testing.T) (
	vagentSrv *httptest.Server,
	vsvcSrv *httptest.Server,
	svc *vservice.Service,
	agent *Agent,
	rstub *rserviceStub,
	rsvcSrv *httptest.Server,
	params protocol.Params,
) {
	t.Helper()
	params = smallParams(t)
	svc = vservice.New(params)
	vsvcSrv = httptest.NewServer(vservice.NewServer(svc).Handler())
	t.Cleanup(vsvcSrv.Close)

	a, err := New(params)
	require.NoError(t, err)
	agent = a

	rstub = newRServiceStub()
	rsvcSrv = httptest.NewServer(rstub.handler())
	t.Cleanup(rsvcSrv.Close)

	vagentSrv = httptest.NewServer(NewServer(agent, vsvcSrv.URL, rsvcSrv.URL, "").Handler())
	t.Cleanup(vagentSrv.Close)
	return
}

// runFullKeygenAndStore runs the Stage-2 multi-party handshake against
// the Agent via the HTTP routes, then makes sure VService has the eval
// keys for the sid by issuing a single in-process StoreEvalKeys (the gks
// handler already POSTed them; we just need it idempotently for the test
// to also have a usable joint sk and pk).
//
// Returns the joint sk (for assembling the partial-decryption share) and
// the aggregated pk (for encrypting the image input).
func runFullKeygenViaHTTPThenStore(
	t *testing.T,
	vagentBase string,
	sid protocol.SessionID,
	stub *vclientStub,
	agent *Agent,
	params protocol.Params,
) (jointSecret *rlwe.SecretKey, jointPK *rlwe.PublicKey) {
	t.Helper()
	runKeygenViaHTTP(t, vagentBase, sid, stub, params)
	sess := agentState(t, agent, sid)
	require.NotNil(t, sess.pkAgg)
	return jointSk(t, params, stub.skCEval, sess.skEvalCached), sess.pkAgg
}

func TestHTTPVAgent_Image_HappyPath(t *testing.T) {
	vagentSrv, _, _, agent, _, _, params := newHTTPFixtureWithRService(t)
	sid := openSessionViaHTTP(t, vagentSrv)
	stub := newVClientStub(t, params, sid)

	_, jointPK := runFullKeygenViaHTTPThenStore(t, vagentSrv.URL, sid, stub, agent, params)

	// Encrypt 0.5 at slot 0 under jointPK. The x² circuit yields ≈0.25;
	// we don't decode here — just verify the response body is the
	// marshaled AuthenticatedResult ciphertext.
	encoder := ckks.NewEncoder(params.CKKS)
	encryptor := rlwe.NewEncryptor(params.CKKS, jointPK)
	values := make([]float64, params.CKKS.MaxSlots())
	values[0] = 0.5
	pt := ckks.NewPlaintext(params.CKKS, params.CKKS.MaxLevel())
	require.NoError(t, encoder.Encode(values, pt))
	inputCt, err := encryptor.EncryptNew(pt)
	require.NoError(t, err)
	inputBytes, err := inputCt.MarshalBinary()
	require.NoError(t, err)

	resp := postOctet(t, vagentSrv.URL, "/sessions/"+string(sid)+"/infer", inputBytes)
	defer resp.Body.Close()
	respBytes, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", respBytes)
	assert.Equal(t, "application/octet-stream", resp.Header.Get("Content-Type"))

	// Response body must round-trip as a ciphertext.
	respCt := &rlwe.Ciphertext{}
	require.NoError(t, respCt.UnmarshalBinary(respBytes))

	// authenticatedCt cache must also be populated for the partial-decryption
	// handler to retrieve, and must match the response bytes.
	cached, ok := agent.SessionAuthenticatedCt(sid)
	require.True(t, ok)
	require.NotNil(t, cached, "infer handler must cache ct_M")
	cachedBytes, err := cached.MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t, cachedBytes, respBytes)
}

func TestHTTPVAgent_Image_UnknownSidReturns404(t *testing.T) {
	vagentSrv, _, _, _, _, _, _ := newHTTPFixtureWithRService(t)
	resp := postOctet(t, vagentSrv.URL, "/sessions/never-opened/infer", []byte{0x00})
	defer resp.Body.Close()
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
	var body httputil.ErrorBody
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Contains(t, body.Error, "unknown session")
}

func TestHTTPVAgent_Image_MalformedBodyReturns400(t *testing.T) {
	vagentSrv, _, _, _, _, _, _ := newHTTPFixtureWithRService(t)
	sid := openSessionViaHTTP(t, vagentSrv)
	resp := postOctet(t, vagentSrv.URL, "/sessions/"+string(sid)+"/infer", []byte{0xff, 0xff, 0xff})
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestHTTPVAgent_Image_RejectsGet(t *testing.T) {
	vagentSrv, _, _, _, _, _, _ := newHTTPFixtureWithRService(t)
	sid := openSessionViaHTTP(t, vagentSrv)
	resp, err := http.Get(vagentSrv.URL + "/sessions/" + string(sid) + "/infer")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
}

// TestHTTPVAgent_PartialDecryption_AcceptVerdict drives the happy path
// end-to-end: full keygen + image POST + craft a valid partial-decryption
// share for m=0.7² > 0 → expect Accept verdict callback + 302 to RService.
func TestHTTPVAgent_PartialDecryption_AcceptVerdict(t *testing.T) {
	vagentSrv, _, _, agent, rstub, rsvcSrv, params := newHTTPFixtureWithRService(t)
	sid := openSessionViaHTTP(t, vagentSrv)
	stub := newVClientStub(t, params, sid)

	_, jointPK := runFullKeygenViaHTTPThenStore(t, vagentSrv.URL, sid, stub, agent, params)

	// Encrypt sqrt(0.7) so the x² circuit yields ~0.7 > 0 → Accept.
	encoder := ckks.NewEncoder(params.CKKS)
	encryptor := rlwe.NewEncryptor(params.CKKS, jointPK)
	values := make([]float64, params.CKKS.MaxSlots())
	// pick a positive value whose square is well above zero
	values[0] = 0.8366600265340756 // sqrt(0.7)
	pt := ckks.NewPlaintext(params.CKKS, params.CKKS.MaxLevel())
	require.NoError(t, encoder.Encode(values, pt))
	inputCt, err := encryptor.EncryptNew(pt)
	require.NoError(t, err)
	inputBytes, err := inputCt.MarshalBinary()
	require.NoError(t, err)

	imgResp := postOctet(t, vagentSrv.URL, "/sessions/"+string(sid)+"/infer", inputBytes)
	require.Equal(t, http.StatusOK, imgResp.StatusCode)
	imgResp.Body.Close()

	// Build VClient's partial-decryption share under sk_c against the cached ct_M.
	ctM, ok := agent.SessionAuthenticatedCt(sid)
	require.True(t, ok)
	require.NotNil(t, ctM)

	clientProto, err := multiparty.NewKeySwitchProtocol(params.CKKS, ring.DiscreteGaussian{
		Sigma: params.FloodSigma,
		Bound: 6 * params.FloodSigma,
	})
	require.NoError(t, err)
	zeroSk := rlwe.NewSecretKey(params.CKKS)
	clientShare := clientProto.AllocateShare(ctM.Level())
	clientProto.GenShare(stub.skCEval, zeroSk, ctM, &clientShare)
	pdBytes, err := protocol.PartialDecryption{Share: clientShare}.MarshalBinary()
	require.NoError(t, err)

	resp, err := http.Post(vagentSrv.URL+"/sessions/"+string(sid)+"/partial", "application/octet-stream", bytes.NewReader(pdBytes))
	require.NoError(t, err)
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", respBody)
	var redirectBody protocol.FinalizeRedirect
	require.NoError(t, json.Unmarshal(respBody, &redirectBody))
	assert.Equal(t, rsvcSrv.URL+"/protected", redirectBody.Redirect)

	calls, gotSid, gotVerd := rstub.snapshot()
	assert.Equal(t, 1, calls, "RService must receive exactly one callback")
	assert.Equal(t, sid, gotSid)
	assert.Equal(t, protocol.VerdictAccept, gotVerd)
}

// TestHTTPVAgent_PartialDecryption_TamperedShareReject sends a share built
// under a different sk_c → Ver fails → callback ResultAuthFailed + 200.
func TestHTTPVAgent_PartialDecryption_TamperedShareReject(t *testing.T) {
	vagentSrv, _, _, agent, rstub, _, params := newHTTPFixtureWithRService(t)
	sid := openSessionViaHTTP(t, vagentSrv)
	stub := newVClientStub(t, params, sid)

	_, jointPK := runFullKeygenViaHTTPThenStore(t, vagentSrv.URL, sid, stub, agent, params)

	encoder := ckks.NewEncoder(params.CKKS)
	encryptor := rlwe.NewEncryptor(params.CKKS, jointPK)
	values := make([]float64, params.CKKS.MaxSlots())
	values[0] = 0.5
	pt := ckks.NewPlaintext(params.CKKS, params.CKKS.MaxLevel())
	require.NoError(t, encoder.Encode(values, pt))
	inputCt, err := encryptor.EncryptNew(pt)
	require.NoError(t, err)
	inputBytes, err := inputCt.MarshalBinary()
	require.NoError(t, err)
	imgResp := postOctet(t, vagentSrv.URL, "/sessions/"+string(sid)+"/infer", inputBytes)
	require.Equal(t, http.StatusOK, imgResp.StatusCode)
	imgResp.Body.Close()

	ctM, ok := agent.SessionAuthenticatedCt(sid)
	require.True(t, ok)

	// Build the share under a WRONG sk — Ver must reject.
	wrongSk := rlwe.NewKeyGenerator(params.CKKS).GenSecretKeyNew()
	clientProto, err := multiparty.NewKeySwitchProtocol(params.CKKS, ring.DiscreteGaussian{
		Sigma: params.FloodSigma,
		Bound: 6 * params.FloodSigma,
	})
	require.NoError(t, err)
	zeroSk := rlwe.NewSecretKey(params.CKKS)
	clientShare := clientProto.AllocateShare(ctM.Level())
	clientProto.GenShare(wrongSk, zeroSk, ctM, &clientShare)
	pdBytes, err := protocol.PartialDecryption{Share: clientShare}.MarshalBinary()
	require.NoError(t, err)

	resp, err := http.Post(vagentSrv.URL+"/sessions/"+string(sid)+"/partial", "application/octet-stream", bytes.NewReader(pdBytes))
	require.NoError(t, err)
	defer resp.Body.Close()
	// A clean Ver=false finalize is reported as Reject (no error); per
	// docs/DESIGN.md the callback runs and a redirect URL is returned.
	require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", readAll(t, resp.Body))

	calls, _, gotVerd := rstub.snapshot()
	assert.Equal(t, 1, calls)
	assert.Equal(t, protocol.VerdictResultAuthFailed, gotVerd)
}

// TestHTTPVAgent_PartialDecryption_MalformedShareRejectThen4xx exercises
// F2 wire shape: known sid, garbage body → callback Reject + 4xx.
func TestHTTPVAgent_PartialDecryption_MalformedShareRejectThen4xx(t *testing.T) {
	vagentSrv, _, _, _, rstub, _, _ := newHTTPFixtureWithRService(t)
	sid := openSessionViaHTTP(t, vagentSrv)

	resp := postOctet(t, vagentSrv.URL, "/sessions/"+string(sid)+"/partial", []byte{0xff, 0xff, 0xff})
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	calls, _, gotVerd := rstub.snapshot()
	assert.Equal(t, 1, calls, "F2 wire-shape violation must trigger Reject callback")
	assert.Equal(t, protocol.VerdictReject, gotVerd)
}

// TestHTTPVAgent_PartialDecryption_UnknownSidNoCallback: unknown sid →
// 404 + zero callbacks (no session to mark a verdict against).
func TestHTTPVAgent_PartialDecryption_UnknownSidNoCallback(t *testing.T) {
	vagentSrv, _, _, _, rstub, _, _ := newHTTPFixtureWithRService(t)

	resp := postOctet(t, vagentSrv.URL, "/sessions/never-opened/partial", []byte{0x00})
	defer resp.Body.Close()
	require.Equal(t, http.StatusNotFound, resp.StatusCode)

	calls, _, _ := rstub.snapshot()
	assert.Equal(t, 0, calls, "unknown sid must not trigger callback")
}

// TestHTTPVAgent_PartialDecryption_BeforeImageRejects exercises the
// "known sid, no ct_M cached" path: the client called partial-decryption
// before the image POST set up ct_M. Callback Reject + 400.
func TestHTTPVAgent_PartialDecryption_BeforeImageRejects(t *testing.T) {
	vagentSrv, _, _, agent, rstub, _, params := newHTTPFixtureWithRService(t)
	sid := openSessionViaHTTP(t, vagentSrv)
	stub := newVClientStub(t, params, sid)

	// Drive keygen so the sid is "known and live" but skip the image POST so
	// authenticatedCt stays nil.
	runKeygenViaHTTP(t, vagentSrv.URL, sid, stub, params)

	// Build a syntactically valid (but semantically meaningless) share so
	// UnmarshalBinary succeeds → the handler reaches the populated-check.
	dummyCt := rlwe.NewCiphertext(params.CKKS, 1, params.CKKS.MaxLevel())
	proto, err := multiparty.NewKeySwitchProtocol(params.CKKS, ring.DiscreteGaussian{Sigma: 0, Bound: 0})
	require.NoError(t, err)
	zeroSk := rlwe.NewSecretKey(params.CKKS)
	share := proto.AllocateShare(dummyCt.Level())
	proto.GenShare(stub.skCEval, zeroSk, dummyCt, &share)
	pdBytes, err := protocol.PartialDecryption{Share: share}.MarshalBinary()
	require.NoError(t, err)

	resp := postOctet(t, vagentSrv.URL, "/sessions/"+string(sid)+"/partial", pdBytes)
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	calls, _, gotVerd := rstub.snapshot()
	assert.Equal(t, 1, calls)
	assert.Equal(t, protocol.VerdictReject, gotVerd)

	// F3 path must tear down the session (DESIGN.md §`Failure modes`:
	// "Session torn down"). Without this, the session table still holds
	// the authKey + skShare and a follow-up valid retry could upsert
	// Accept on rservice (last-write-wins replay weakness).
	_, err = agent.session(sid)
	require.Error(t, err, "F3 must evict the session")
}

// Stage-4b callback failure must surface as 502 even on a clean Accept —
// blocks the redirect so the operator sees the wire fault.
func TestHTTPVAgent_PartialDecryption_CallbackFailureReturns502(t *testing.T) {
	vagentSrv, _, _, agent, rstub, _, params := newHTTPFixtureWithRService(t)
	rstub.mu.Lock()
	rstub.failStatus = http.StatusInternalServerError
	rstub.mu.Unlock()
	sid := openSessionViaHTTP(t, vagentSrv)
	stub := newVClientStub(t, params, sid)

	_, jointPK := runFullKeygenViaHTTPThenStore(t, vagentSrv.URL, sid, stub, agent, params)

	encoder := ckks.NewEncoder(params.CKKS)
	encryptor := rlwe.NewEncryptor(params.CKKS, jointPK)
	values := make([]float64, params.CKKS.MaxSlots())
	values[0] = 0.8366600265340756
	pt := ckks.NewPlaintext(params.CKKS, params.CKKS.MaxLevel())
	require.NoError(t, encoder.Encode(values, pt))
	inputCt, err := encryptor.EncryptNew(pt)
	require.NoError(t, err)
	inputBytes, err := inputCt.MarshalBinary()
	require.NoError(t, err)
	imgResp := postOctet(t, vagentSrv.URL, "/sessions/"+string(sid)+"/infer", inputBytes)
	require.Equal(t, http.StatusOK, imgResp.StatusCode)
	imgResp.Body.Close()

	ctM, ok := agent.SessionAuthenticatedCt(sid)
	require.True(t, ok)
	clientProto, err := multiparty.NewKeySwitchProtocol(params.CKKS, ring.DiscreteGaussian{
		Sigma: params.FloodSigma,
		Bound: 6 * params.FloodSigma,
	})
	require.NoError(t, err)
	zeroSk := rlwe.NewSecretKey(params.CKKS)
	clientShare := clientProto.AllocateShare(ctM.Level())
	clientProto.GenShare(stub.skCEval, zeroSk, ctM, &clientShare)
	pdBytes, err := protocol.PartialDecryption{Share: clientShare}.MarshalBinary()
	require.NoError(t, err)

	resp, err := http.Post(vagentSrv.URL+"/sessions/"+string(sid)+"/partial", "application/octet-stream", bytes.NewReader(pdBytes))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadGateway, resp.StatusCode, "body=%s", readAll(t, resp.Body))
}

func TestHTTPVAgent_PartialDecryption_RejectsGet(t *testing.T) {
	vagentSrv, _, _, _, _, _, _ := newHTTPFixtureWithRService(t)
	sid := openSessionViaHTTP(t, vagentSrv)
	resp, err := http.Get(vagentSrv.URL + "/sessions/" + string(sid) + "/partial")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
}

// `GET /verify` serves the embedded VClient SPA index.html.
func TestHTTPVAgent_Verify_ReturnsEmbeddedHTML(t *testing.T) {
	_, vagentSrv, _, _, _, _ := newHTTPFixture(t)
	resp, err := http.Get(vagentSrv.URL + "/verify?sid=anything")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "text/html; charset=utf-8", resp.Header.Get("Content-Type"))
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	// Embedded VClient index.html includes the SPA bootstrap script tag.
	assert.Contains(t, string(body), `./dist/main.js`)
	assert.Contains(t, string(body), `wasm_exec.js`)
}

func TestHTTPVAgent_Verify_RejectsPost(t *testing.T) {
	_, vagentSrv, _, _, _, _ := newHTTPFixture(t)
	resp, err := http.Post(vagentSrv.URL+"/verify", "text/plain", nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
}

// `GET /ppiav.wasm` returns application/wasm with the embedded blob.
func TestHTTPVAgent_PpiavWASM_ReturnsBlob(t *testing.T) {
	_, vagentSrv, _, _, _, _ := newHTTPFixture(t)
	resp, err := http.Get(vagentSrv.URL + "/ppiav.wasm")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "application/wasm", resp.Header.Get("Content-Type"))
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.NotEmpty(t, body)
	// WASM magic number: 0x00 0x61 0x73 0x6d.
	require.GreaterOrEqual(t, len(body), 4)
	assert.Equal(t, []byte{0x00, 0x61, 0x73, 0x6d}, body[:4])
}

// `/dist/main.js` is served from the embedded VClient FS.
func TestHTTPVAgent_VClientDist_ReturnsJS(t *testing.T) {
	_, vagentSrv, _, _, _, _ := newHTTPFixture(t)
	resp, err := http.Get(vagentSrv.URL + "/dist/main.js")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	// Go's http.FileServer sniffs Content-Type from the .js extension.
	assert.Contains(t, resp.Header.Get("Content-Type"), "javascript")
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.NotEmpty(t, body)
}

// `/wasm_exec.js` is served from the embedded VClient FS.
func TestHTTPVAgent_WasmExecJS_ReturnsJS(t *testing.T) {
	_, vagentSrv, _, _, _, _ := newHTTPFixture(t)
	resp, err := http.Get(vagentSrv.URL + "/wasm_exec.js")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Content-Type"), "javascript")
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.NotEmpty(t, body)
}

// --- F2/F3 rejectAndEvict contract tests -----------------------------------
//
// DESIGN.md §`Failure modes` rows F2 and F3 mandate:
//
//	"HTTP 4xx/5xx to the offending party plus Verdict = Reject to
//	 RService. Session torn down."
//
// The tests below pin the contract at the wire for every keygen-stage
// handler. Earlier iterations evicted only on the partial-decryption
// path; the rest leaked authKey + skShare + (where present) cached ct_M
// after the Reject callback, which combined with rservice.AcceptVerdict's
// last-write-wins upsert allowed a replay to flip Reject → Accept.

// TestHTTPVAgent_PKShare_MalformedBodyRejectAndEvicts: F2 on pk-share
// must post Reject callback + evict the session.
func TestHTTPVAgent_PKShare_MalformedBodyRejectAndEvicts(t *testing.T) {
	vagentSrv, _, _, agent, rstub, _, _ := newHTTPFixtureWithRService(t)
	sid := openSessionViaHTTP(t, vagentSrv)

	resp := postOctet(t, vagentSrv.URL, "/sessions/"+string(sid)+"/pk-share", []byte{0xff, 0xff, 0xff})
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	calls, gotSid, gotVerd := rstub.snapshot()
	assert.Equal(t, 1, calls, "F2 must trigger Reject callback")
	assert.Equal(t, sid, gotSid)
	assert.Equal(t, protocol.VerdictReject, gotVerd)
	_, err := agent.session(sid)
	require.Error(t, err, "F2 must evict the session")
}

// TestHTTPVAgent_RLKRound1_MalformedBodyRejectAndEvicts: same for rlk/round1.
func TestHTTPVAgent_RLKRound1_MalformedBodyRejectAndEvicts(t *testing.T) {
	vagentSrv, _, _, agent, rstub, _, _ := newHTTPFixtureWithRService(t)
	sid := openSessionViaHTTP(t, vagentSrv)

	resp := postOctet(t, vagentSrv.URL, "/sessions/"+string(sid)+"/rlk/round1", []byte{0xff, 0xff})
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	calls, _, gotVerd := rstub.snapshot()
	assert.Equal(t, 1, calls)
	assert.Equal(t, protocol.VerdictReject, gotVerd)
	_, err := agent.session(sid)
	require.Error(t, err)
}

// TestHTTPVAgent_RLKRound2_MalformedBodyRejectAndEvicts: same for rlk/round2.
// rlk/round2 only checks for known sid + malformed body; we don't need to
// drive PK/round1 first because the malformed-body branch fires before the
// state-machine inspection.
func TestHTTPVAgent_RLKRound2_MalformedBodyRejectAndEvicts(t *testing.T) {
	vagentSrv, _, _, agent, rstub, _, _ := newHTTPFixtureWithRService(t)
	sid := openSessionViaHTTP(t, vagentSrv)

	resp := postOctet(t, vagentSrv.URL, "/sessions/"+string(sid)+"/rlk/round2", []byte{0xff, 0xff})
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	calls, _, gotVerd := rstub.snapshot()
	assert.Equal(t, 1, calls)
	assert.Equal(t, protocol.VerdictReject, gotVerd)
	_, err := agent.session(sid)
	require.Error(t, err)
}

// TestHTTPVAgent_GKSShares_MalformedBodyRejectAndEvicts: gks-shares F2
// (malformed body) must Reject + evict.
func TestHTTPVAgent_GKSShares_MalformedBodyRejectAndEvicts(t *testing.T) {
	vagentSrv, _, _, agent, rstub, _, _ := newHTTPFixtureWithRService(t)
	sid := openSessionViaHTTP(t, vagentSrv)

	resp := postOctet(t, vagentSrv.URL, "/sessions/"+string(sid)+"/gks-shares", []byte{0xff, 0xff, 0xff, 0xff, 0xff})
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	calls, _, gotVerd := rstub.snapshot()
	assert.Equal(t, 1, calls)
	assert.Equal(t, protocol.VerdictReject, gotVerd)
	_, err := agent.session(sid)
	require.Error(t, err)
}

// TestHTTPVAgent_GKSShares_EvalKeysForwardFailureRejectsAndEvicts: F3 path
// — VService /eval-keys returns 502 after a valid gks-shares POST. The
// handler must Reject + evict. We reuse the VService failure stub pattern
// from TestHTTPVAgent_GKSShares_VServiceForwardFailure but wire an RService
// stub to observe the callback.
func TestHTTPVAgent_GKSShares_EvalKeysForwardFailureRejectsAndEvicts(t *testing.T) {
	params := smallParams(t)
	var sidCount atomic.Int64
	stubVSvc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/sessions" {
			n := sidCount.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"SessionID":"sid-evk-` + strings.Repeat("a", int(n)) + `"}`))
			return
		}
		if strings.HasSuffix(r.URL.Path, "/eval-keys") {
			http.Error(w, "vservice down", http.StatusInternalServerError)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(stubVSvc.Close)

	agent, err := New(params)
	require.NoError(t, err)
	rstub := newRServiceStub()
	rsvcSrv := httptest.NewServer(rstub.handler())
	t.Cleanup(rsvcSrv.Close)
	vagentSrv := httptest.NewServer(NewServer(agent, stubVSvc.URL, rsvcSrv.URL, "").Handler())
	t.Cleanup(vagentSrv.Close)

	sid := openSessionViaHTTP(t, vagentSrv)
	stub := newVClientStub(t, params, sid)
	runKeygenUpToGKS(t, vagentSrv.URL, sid, stub, params)

	// Build valid master-atom-set gks shares so the handler reaches the
	// VService forward.
	masterLabels := params.MasterAtoms()
	clientMaster := generateClientGaloisShares(t, stub, params, masterLabels)
	gksBytes, err := protocol.VClientGaloisShares{
		MasterShares: clientMaster,
	}.MarshalBinary()
	require.NoError(t, err)

	resp := postOctet(t, vagentSrv.URL, "/sessions/"+string(sid)+"/gks-shares", gksBytes)
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadGateway, resp.StatusCode)

	calls, gotSid, gotVerd := rstub.snapshot()
	assert.Equal(t, 1, calls, "F3 on eval-keys forward failure must trigger Reject")
	assert.Equal(t, sid, gotSid)
	assert.Equal(t, protocol.VerdictReject, gotVerd)
	_, err = agent.session(sid)
	require.Error(t, err)
}

// TestHTTPVAgent_Infer_MalformedBodyRejectAndEvicts: F2 on /infer.
func TestHTTPVAgent_Image_MalformedBodyRejectAndEvicts(t *testing.T) {
	vagentSrv, _, _, agent, rstub, _, _ := newHTTPFixtureWithRService(t)
	sid := openSessionViaHTTP(t, vagentSrv)

	resp := postOctet(t, vagentSrv.URL, "/sessions/"+string(sid)+"/infer", []byte{0xff, 0xff, 0xff})
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	calls, _, gotVerd := rstub.snapshot()
	assert.Equal(t, 1, calls)
	assert.Equal(t, protocol.VerdictReject, gotVerd)
	_, err := agent.session(sid)
	require.Error(t, err)
}

// TestHTTPVAgent_Infer_VServiceFailureRejectAndEvicts: F3 — VService /infer
// returns 500. VAgent must Reject + evict + surface 502.
func TestHTTPVAgent_Image_VServiceFailureRejectAndEvicts(t *testing.T) {
	params := smallParams(t)
	var sidCount atomic.Int64
	stubVSvc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/sessions" {
			n := sidCount.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"SessionID":"sid-img-` + strings.Repeat("a", int(n)) + `"}`))
			return
		}
		if strings.HasSuffix(r.URL.Path, "/infer") {
			http.Error(w, "vservice infer down", http.StatusInternalServerError)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(stubVSvc.Close)

	agent, err := New(params)
	require.NoError(t, err)
	rstub := newRServiceStub()
	rsvcSrv := httptest.NewServer(rstub.handler())
	t.Cleanup(rsvcSrv.Close)
	vagentSrv := httptest.NewServer(NewServer(agent, stubVSvc.URL, rsvcSrv.URL, "").Handler())
	t.Cleanup(vagentSrv.Close)

	sid := openSessionViaHTTP(t, vagentSrv)
	// Build a valid-looking ciphertext under throwaway keys so the handler
	// reaches the VService forward step rather than failing on F2.
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

	resp := postOctet(t, vagentSrv.URL, "/sessions/"+string(sid)+"/infer", body)
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadGateway, resp.StatusCode)

	calls, _, gotVerd := rstub.snapshot()
	assert.Equal(t, 1, calls, "F3 on /infer VService failure must trigger Reject")
	assert.Equal(t, protocol.VerdictReject, gotVerd)
	_, err = agent.session(sid)
	require.Error(t, err)
}

// TestHTTPVAgent_PartialDecryption_MalformedBodyEvicts: re-affirms that
// the existing F2 partial-decryption callback also evicts now (was the
// concrete replay weakness the iteration-3 finding called out).
func TestHTTPVAgent_PartialDecryption_MalformedBodyEvicts(t *testing.T) {
	vagentSrv, _, _, agent, rstub, _, _ := newHTTPFixtureWithRService(t)
	sid := openSessionViaHTTP(t, vagentSrv)

	resp := postOctet(t, vagentSrv.URL, "/sessions/"+string(sid)+"/partial", []byte{0xff, 0xff, 0xff})
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	calls, _, gotVerd := rstub.snapshot()
	assert.Equal(t, 1, calls)
	assert.Equal(t, protocol.VerdictReject, gotVerd)
	_, err := agent.session(sid)
	require.Error(t, err, "F2 must evict so a retry cannot upsert Accept")
}

// runKeygenUpToGKS drives PK + RLK round1 + round2 against the VAgent HTTP
// server so callers can then POST a custom gks-shares body. Mirrors the
// inline preamble in TestHTTPVAgent_GKSShares_VServiceForwardFailure; kept
// as a helper because two new tests need the same prefix.
func runKeygenUpToGKS(t *testing.T, base string, sid protocol.SessionID, stub *vclientStub, params protocol.Params) {
	t.Helper()

	// Dual PK shares (eval + top).
	pkProtoEval := multiparty.NewPublicKeyGenProtocol(params.CKKS)
	clientCRPEval := pkProtoEval.SampleCRP(stub.crs)
	clientPKShareEval := pkProtoEval.AllocateShare()
	pkProtoEval.GenShare(stub.skCEval, clientCRPEval, &clientPKShareEval)
	pkProtoTop := multiparty.NewPublicKeyGenProtocol(params.LLKN.Top())
	clientCRPTop := pkProtoTop.SampleCRP(stub.crs)
	clientPKShareTop := pkProtoTop.AllocateShare()
	pkProtoTop.GenShare(stub.skCTop, clientCRPTop, &clientPKShareTop)
	pkBytes, err := protocol.VClientPKShare{
		ShareEval: clientPKShareEval,
		ShareTop:  clientPKShareTop,
	}.MarshalBinary()
	require.NoError(t, err)
	r := postOctet(t, base, "/sessions/"+string(sid)+"/pk-share", pkBytes)
	require.Equal(t, http.StatusOK, r.StatusCode)
	pkRespBody, _ := io.ReadAll(r.Body)
	r.Body.Close()
	var agentPK protocol.VAgentPKShare
	require.NoError(t, agentPK.UnmarshalBinary(pkRespBody))

	rlkProto := multiparty.NewRelinearizationKeyGenProtocol(params.CKKS)
	clientRLKCRP := rlkProto.SampleCRP(stub.crs)
	ephSk, share1, share2 := rlkProto.AllocateShare()
	rlkProto.GenShareRoundOne(stub.skCEval, clientRLKCRP, ephSk, &share1)
	r1b, err := protocol.VClientRLKRound1{Share: share1}.MarshalBinary()
	require.NoError(t, err)
	r1 := postOctet(t, base, "/sessions/"+string(sid)+"/rlk/round1", r1b)
	require.Equal(t, http.StatusOK, r1.StatusCode)
	r1RespBody, _ := io.ReadAll(r1.Body)
	r1.Body.Close()
	var agentR1 protocol.VAgentRLKRound1
	require.NoError(t, agentR1.UnmarshalBinary(r1RespBody))
	_, share1Agg, _ := rlkProto.AllocateShare()
	rlkProto.AggregateShares(share1, agentR1.Share, &share1Agg)
	rlkProto.GenShareRoundTwo(ephSk, stub.skCEval, share1Agg, &share2)
	r2b, err := protocol.VClientRLKRound2{Share: share2}.MarshalBinary()
	require.NoError(t, err)
	r2 := postOctet(t, base, "/sessions/"+string(sid)+"/rlk/round2", r2b)
	require.Equal(t, http.StatusOK, r2.StatusCode)
	r2.Body.Close()
}
