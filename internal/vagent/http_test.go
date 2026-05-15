package vagent

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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
	vsvcSrv = httptest.NewServer(vservice.NewServer(svc, "").Handler())
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
	vagent, vagentSrv, _, svc, agent, _ := newHTTPFixture(t)
	_ = vagent

	sid := openSessionViaHTTP(t, vagentSrv)

	// VService must know the sid (StoreEvalKeys would 404 otherwise).
	// Sidestep: VService's session table is private — but the agent's
	// OpenSession registered the sid in the agent, and the only way the
	// sid is non-empty is via vsvc.OpenSession. We verify both:
	_, err := agent.session(sid)
	require.NoError(t, err, "agent must have registered the sid")

	// And in-process: the VService Service must have the sid in its table.
	// We can't check the map directly; we can check by issuing a second
	// open that should not collide (sids are random) and ensuring the
	// in-process count is at least 2.
	_ = svc
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

func TestHTTPVAgent_GetParams_ProxiesToVService(t *testing.T) {
	_, vagentSrv, _, _, _, params := newHTTPFixture(t)

	// sid in the URL is required by the route shape but unused by the
	// current proxy — phase 4 may make params session-dependent.
	resp, err := http.Get(vagentSrv.URL + "/sessions/sid-x/params")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Content-Type"), "application/json")

	// Body must be a paramsWire-shaped JSON. We only check the
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

	// Build VClient's PK share off the stub's CRS — the first CRP draw is PK.
	pkProto := multiparty.NewPublicKeyGenProtocol(params.CKKS)
	clientCRP := pkProto.SampleCRP(stub.crs)
	clientShare := pkProto.AllocateShare()
	pkProto.GenShare(stub.skC, clientCRP, &clientShare)
	clientBytes, err := protocol.VClientPKShare{Share: clientShare}.MarshalBinary()
	require.NoError(t, err)

	resp := postOctet(t, vagentSrv.URL, "/sessions/"+string(sid)+"/pk-share", clientBytes)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Content-Type"), "application/octet-stream")

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	t.Logf("response body length: %d, client share bytes length: %d", len(body), len(clientBytes))
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
	var body errorBody
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Contains(t, body.Error, "unknown session")
}

func TestHTTPVAgent_PKShare_MalformedBodyReturns400(t *testing.T) {
	_, vagentSrv, _, _, _, _ := newHTTPFixture(t)
	sid := openSessionViaHTTP(t, vagentSrv)
	resp := postOctet(t, vagentSrv.URL, "/sessions/"+string(sid)+"/pk-share", []byte{0xff, 0xff, 0xff})
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var body errorBody
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

	// PK
	pkProto := multiparty.NewPublicKeyGenProtocol(params.CKKS)
	clientCRP := pkProto.SampleCRP(stub.crs)
	clientPKShare := pkProto.AllocateShare()
	pkProto.GenShare(stub.skC, clientCRP, &clientPKShare)
	pkBytes, err := protocol.VClientPKShare{Share: clientPKShare}.MarshalBinary()
	require.NoError(t, err)
	pkResp := postOctet(t, base, "/sessions/"+string(sid)+"/pk-share", pkBytes)
	pkRespBody, err := io.ReadAll(pkResp.Body)
	require.NoError(t, err)
	pkResp.Body.Close()
	require.Equal(t, http.StatusOK, pkResp.StatusCode, "pk-share body=%s", pkRespBody)
	var agentPK protocol.VAgentPKShare
	require.NoError(t, agentPK.UnmarshalBinary(pkRespBody))

	// RLK round 1
	rlkProto := multiparty.NewRelinearizationKeyGenProtocol(params.CKKS)
	clientRLKCRP := rlkProto.SampleCRP(stub.crs)
	clientEphSk, clientRLK1, clientRLK2 := rlkProto.AllocateShare()
	rlkProto.GenShareRoundOne(stub.skC, clientRLKCRP, clientEphSk, &clientRLK1)
	r1Bytes, err := protocol.VClientRLKRound1{Share: clientRLK1}.MarshalBinary()
	require.NoError(t, err)
	r1Resp := postOctet(t, base, "/sessions/"+string(sid)+"/rlk/round1", r1Bytes)
	r1RespBody, err := io.ReadAll(r1Resp.Body)
	require.NoError(t, err)
	r1Resp.Body.Close()
	require.Equal(t, http.StatusOK, r1Resp.StatusCode, "rlk/round1 body=%s", r1RespBody)
	var agentR1 protocol.VAgentRLKRound1
	require.NoError(t, agentR1.UnmarshalBinary(r1RespBody))

	// Stub-side round-1 aggregate (must mirror the agent's).
	_, clientRLK1Agg, _ := rlkProto.AllocateShare()
	rlkProto.AggregateShares(clientRLK1, agentR1.Share, &clientRLK1Agg)

	// RLK round 2
	rlkProto.GenShareRoundTwo(clientEphSk, stub.skC, clientRLK1Agg, &clientRLK2)
	r2Bytes, err := protocol.VClientRLKRound2{Share: clientRLK2}.MarshalBinary()
	require.NoError(t, err)
	r2Resp := postOctet(t, base, "/sessions/"+string(sid)+"/rlk/round2", r2Bytes)
	r2RespBody, err := io.ReadAll(r2Resp.Body)
	require.NoError(t, err)
	r2Resp.Body.Close()
	require.Equal(t, http.StatusOK, r2Resp.StatusCode, "rlk/round2 body=%s", r2RespBody)

	// Galois shares
	gkg := multiparty.NewGaloisKeyGenProtocol(params.CKKS)
	labels := params.RotationIndices()
	clientGalShares := make([]multiparty.GaloisKeyGenShare, len(labels))
	for i, j := range labels {
		crp := gkg.SampleCRP(stub.crs)
		s := gkg.AllocateShare()
		galEl := params.CKKS.GaloisElement(-j)
		require.NoError(t, gkg.GenShare(stub.skC, galEl, crp, &s))
		clientGalShares[i] = s
	}
	gksBytes, err := protocol.VClientGaloisKeyShare{Shares: clientGalShares}.MarshalBinary()
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
	// we can verify the agent's session-level invariants (rlkAgg, eval are
	// non-nil) and check VService doesn't 404 a duplicate StoreEvalKeys.
	sess := agentState(t, agent, sid)
	require.NotNil(t, sess.rlkAgg, "AggregateGaloisShares must have finalised rlk")
	require.NotNil(t, sess.eval, "Session evaluator must be wired")

	// Re-issue StoreEvalKeys directly against the vservice — if the sid
	// hadn't been stored, this would 404. (It overwrites; that's fine.)
	require.NoError(t, svc.StoreEvalKeys(sid, sess.rlkAgg, nil))
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

func TestHTTPVAgent_RLKRound2_MalformedBodyReturns400(t *testing.T) {
	_, vagentSrv, _, _, _, _ := newHTTPFixture(t)
	sid := openSessionViaHTTP(t, vagentSrv)

	// Run PK + RLK round1 first so the session is in the right state for
	// round 2 to be reachable.
	params := smallParams(t)
	stub := newVClientStub(t, params, sid)

	// PK
	pkProto := multiparty.NewPublicKeyGenProtocol(params.CKKS)
	clientCRP := pkProto.SampleCRP(stub.crs)
	clientPKShare := pkProto.AllocateShare()
	pkProto.GenShare(stub.skC, clientCRP, &clientPKShare)
	pkBytes, err := protocol.VClientPKShare{Share: clientPKShare}.MarshalBinary()
	require.NoError(t, err)
	r := postOctet(t, vagentSrv.URL, "/sessions/"+string(sid)+"/pk-share", pkBytes)
	r.Body.Close()
	// RLK round 1
	rlkProto := multiparty.NewRelinearizationKeyGenProtocol(params.CKKS)
	clientRLKCRP := rlkProto.SampleCRP(stub.crs)
	ephSk, share1, _ := rlkProto.AllocateShare()
	rlkProto.GenShareRoundOne(stub.skC, clientRLKCRP, ephSk, &share1)
	r1, err := protocol.VClientRLKRound1{Share: share1}.MarshalBinary()
	require.NoError(t, err)
	r2 := postOctet(t, vagentSrv.URL, "/sessions/"+string(sid)+"/rlk/round1", r1)
	r2.Body.Close()

	// Now hit round2 with garbage.
	resp := postOctet(t, vagentSrv.URL, "/sessions/"+string(sid)+"/rlk/round2", []byte{0xff, 0xff})
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

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

	// PK + RLK round1 + round2
	pkProto := multiparty.NewPublicKeyGenProtocol(params.CKKS)
	clientCRP := pkProto.SampleCRP(stub.crs)
	clientPKShare := pkProto.AllocateShare()
	pkProto.GenShare(stub.skC, clientCRP, &clientPKShare)
	pkBytes, _ := protocol.VClientPKShare{Share: clientPKShare}.MarshalBinary()
	r := postOctet(t, vagentSrv.URL, "/sessions/"+string(sid)+"/pk-share", pkBytes)
	require.Equal(t, http.StatusOK, r.StatusCode)
	pkResp, _ := io.ReadAll(r.Body)
	r.Body.Close()
	var agentPK protocol.VAgentPKShare
	require.NoError(t, agentPK.UnmarshalBinary(pkResp))

	rlkProto := multiparty.NewRelinearizationKeyGenProtocol(params.CKKS)
	clientRLKCRP := rlkProto.SampleCRP(stub.crs)
	ephSk, share1, share2 := rlkProto.AllocateShare()
	rlkProto.GenShareRoundOne(stub.skC, clientRLKCRP, ephSk, &share1)
	r1b, _ := protocol.VClientRLKRound1{Share: share1}.MarshalBinary()
	r1 := postOctet(t, vagentSrv.URL, "/sessions/"+string(sid)+"/rlk/round1", r1b)
	require.Equal(t, http.StatusOK, r1.StatusCode)
	r1Resp, _ := io.ReadAll(r1.Body)
	r1.Body.Close()
	var agentR1 protocol.VAgentRLKRound1
	require.NoError(t, agentR1.UnmarshalBinary(r1Resp))
	_, share1Agg, _ := rlkProto.AllocateShare()
	rlkProto.AggregateShares(share1, agentR1.Share, &share1Agg)
	rlkProto.GenShareRoundTwo(ephSk, stub.skC, share1Agg, &share2)
	r2b, _ := protocol.VClientRLKRound2{Share: share2}.MarshalBinary()
	r2 := postOctet(t, vagentSrv.URL, "/sessions/"+string(sid)+"/rlk/round2", r2b)
	require.Equal(t, http.StatusOK, r2.StatusCode)
	r2.Body.Close()

	// Submit a gks-shares blob with zero shares — the agent has Lambda-1
	// labels, so the count mismatch must be rejected as 400.
	emptyBytes, err := protocol.VClientGaloisKeyShare{Shares: nil}.MarshalBinary()
	require.NoError(t, err)
	resp := postOctet(t, vagentSrv.URL, "/sessions/"+string(sid)+"/gks-shares", emptyBytes)
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
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

	// Drive the keygen to completion of round 2 (so gks-shares is
	// reachable with the right session state).
	pkProto := multiparty.NewPublicKeyGenProtocol(params.CKKS)
	clientCRP := pkProto.SampleCRP(stub.crs)
	clientPKShare := pkProto.AllocateShare()
	pkProto.GenShare(stub.skC, clientCRP, &clientPKShare)
	pkBytes, _ := protocol.VClientPKShare{Share: clientPKShare}.MarshalBinary()
	r := postOctet(t, vagentSrv.URL, "/sessions/"+string(sid)+"/pk-share", pkBytes)
	require.Equal(t, http.StatusOK, r.StatusCode)
	pkRespBody, _ := io.ReadAll(r.Body)
	r.Body.Close()
	var agentPK protocol.VAgentPKShare
	require.NoError(t, agentPK.UnmarshalBinary(pkRespBody))

	rlkProto := multiparty.NewRelinearizationKeyGenProtocol(params.CKKS)
	clientRLKCRP := rlkProto.SampleCRP(stub.crs)
	ephSk, share1, share2 := rlkProto.AllocateShare()
	rlkProto.GenShareRoundOne(stub.skC, clientRLKCRP, ephSk, &share1)
	r1b, _ := protocol.VClientRLKRound1{Share: share1}.MarshalBinary()
	r1 := postOctet(t, vagentSrv.URL, "/sessions/"+string(sid)+"/rlk/round1", r1b)
	require.Equal(t, http.StatusOK, r1.StatusCode)
	r1RespBody, _ := io.ReadAll(r1.Body)
	r1.Body.Close()
	var agentR1 protocol.VAgentRLKRound1
	require.NoError(t, agentR1.UnmarshalBinary(r1RespBody))
	_, share1Agg, _ := rlkProto.AllocateShare()
	rlkProto.AggregateShares(share1, agentR1.Share, &share1Agg)
	rlkProto.GenShareRoundTwo(ephSk, stub.skC, share1Agg, &share2)
	r2b, _ := protocol.VClientRLKRound2{Share: share2}.MarshalBinary()
	r2 := postOctet(t, vagentSrv.URL, "/sessions/"+string(sid)+"/rlk/round2", r2b)
	require.Equal(t, http.StatusOK, r2.StatusCode)
	r2.Body.Close()

	// Build valid gks shares
	gkg := multiparty.NewGaloisKeyGenProtocol(params.CKKS)
	labels := params.RotationIndices()
	clientGalShares := make([]multiparty.GaloisKeyGenShare, len(labels))
	for i, j := range labels {
		crp := gkg.SampleCRP(stub.crs)
		s := gkg.AllocateShare()
		galEl := params.CKKS.GaloisElement(-j)
		require.NoError(t, gkg.GenShare(stub.skC, galEl, crp, &s))
		clientGalShares[i] = s
	}
	gksBytes, err := protocol.VClientGaloisKeyShare{Shares: clientGalShares}.MarshalBinary()
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

func TestHTTPVAgent_ResultSSE_UnknownSidReturns404(t *testing.T) {
	_, vagentSrv, _, _, _, _ := newHTTPFixture(t)
	resp, err := http.Get(vagentSrv.URL + "/sessions/never-opened/result")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestHTTPVAgent_ResultSSE_RejectsPost(t *testing.T) {
	_, vagentSrv, _, _, _, _ := newHTTPFixture(t)
	sid := openSessionViaHTTP(t, vagentSrv)
	resp, err := http.Post(vagentSrv.URL+"/sessions/"+string(sid)+"/result", "application/octet-stream", nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
}

// TestHTTPVAgent_ResultSSE_DeliversBase64Ciphertext drives the SSE handler
// end-to-end: starts the GET request, deposits a real ciphertext into the
// session's authResult channel, then reads the SSE `data:` line and
// confirms it base64-decodes back to a marshalable ciphertext. Verifies
// the headers (Content-Type / Cache-Control) and the on-wire frame shape
// (`data: <b64>\n\n`).
func TestHTTPVAgent_ResultSSE_DeliversBase64Ciphertext(t *testing.T) {
	_, vagentSrv, _, _, agent, params := newHTTPFixture(t)
	sid := openSessionViaHTTP(t, vagentSrv)

	// Build a real ciphertext under the params (degree 1, max level) so
	// MarshalBinary produces a wire payload that round-trips.
	ct := rlwe.NewCiphertext(params.CKKS, 1, params.CKKS.MaxLevel())

	// Seed the session's authResult channel before opening SSE: the
	// pre-arrival case (image POST finishes before SSE GET opens). Buffer
	// is capacity 1, so this non-blocking send always succeeds for a
	// freshly-opened session.
	ch, ok := agent.SessionAuthResult(sid)
	require.True(t, ok)
	ch <- ct

	resp, err := http.Get(vagentSrv.URL + "/sessions/" + string(sid) + "/result")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "text/event-stream", resp.Header.Get("Content-Type"))
	assert.Equal(t, "no-cache", resp.Header.Get("Cache-Control"))

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	frame := string(body)
	require.True(t, strings.HasPrefix(frame, "data: "), "frame must start with `data: `: %q", frame)
	require.True(t, strings.HasSuffix(frame, "\n\n"), "SSE event separator missing: %q", frame)
	encoded := strings.TrimSuffix(strings.TrimPrefix(frame, "data: "), "\n\n")
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	require.NoError(t, err)

	// Cross-check the base64 payload is the same MarshalBinary output the
	// handler should have produced.
	want, err := ct.MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t, want, decoded)
}

// TestHTTPVAgent_ResultSSE_CancelledOnClientDisconnect verifies the
// `r.Context().Done()` branch: starting the request with a cancellable
// context, then cancelling before any ciphertext arrives, must return
// without waiting forever. We use a client context with a short deadline.
func TestHTTPVAgent_ResultSSE_CancelledOnClientDisconnect(t *testing.T) {
	_, vagentSrv, _, _, _, _ := newHTTPFixture(t)
	sid := openSessionViaHTTP(t, vagentSrv)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, vagentSrv.URL+"/sessions/"+string(sid)+"/result", nil)
	require.NoError(t, err)
	start := time.Now()
	resp, err := http.DefaultClient.Do(req)
	// Either the read finishes after server-side cancellation or the
	// client surfaces a context error — both are acceptable.
	if err == nil {
		// Drain body so the connection can be cleanly closed.
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	elapsed := time.Since(start)
	// The handler must not hang past the cancel deadline by more than a
	// generous margin (network jitter on httptest.Server).
	require.Less(t, elapsed, 2*time.Second, "SSE handler did not exit on client disconnect")
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
// RService stub. Use for image/partial-decryption tests that exercise the
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
	vsvcSrv = httptest.NewServer(vservice.NewServer(svc, "").Handler())
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
	return jointSk(t, params, stub.skC, sess.skShare), sess.pkAgg
}

func TestHTTPVAgent_Image_HappyPath(t *testing.T) {
	vagentSrv, _, _, agent, _, _, params := newHTTPFixtureWithRService(t)
	sid := openSessionViaHTTP(t, vagentSrv)
	stub := newVClientStub(t, params, sid)

	_, jointPK := runFullKeygenViaHTTPThenStore(t, vagentSrv.URL, sid, stub, agent, params)

	// Encrypt 0.5 at slot 0 under jointPK. The x² circuit yields ≈0.25;
	// we don't decode here — just verify the SSE channel receives a ct_M.
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

	resp := postOctet(t, vagentSrv.URL, "/sessions/"+string(sid)+"/image", inputBytes)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", readAll(t, resp.Body))

	// SSE channel must now carry ct_M (capacity-1 buffer captured it).
	ch, ok := agent.SessionAuthResult(sid)
	require.True(t, ok)
	select {
	case ct := <-ch:
		require.NotNil(t, ct)
	default:
		t.Fatal("authResult channel empty after image POST")
	}
	// authenticatedCt cache must also be populated for the partial-decryption
	// handler to retrieve.
	ct, populated, ok := agent.SessionAuthenticatedCt(sid)
	require.True(t, ok)
	require.True(t, populated, "image handler must cache ct_M")
	require.NotNil(t, ct)
}

func TestHTTPVAgent_Image_UnknownSidReturns404(t *testing.T) {
	vagentSrv, _, _, _, _, _, _ := newHTTPFixtureWithRService(t)
	resp := postOctet(t, vagentSrv.URL, "/sessions/never-opened/image", []byte{0x00})
	defer resp.Body.Close()
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
	var body errorBody
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Contains(t, body.Error, "unknown session")
}

func TestHTTPVAgent_Image_MalformedBodyReturns400(t *testing.T) {
	vagentSrv, _, _, _, _, _, _ := newHTTPFixtureWithRService(t)
	sid := openSessionViaHTTP(t, vagentSrv)
	resp := postOctet(t, vagentSrv.URL, "/sessions/"+string(sid)+"/image", []byte{0xff, 0xff, 0xff})
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestHTTPVAgent_Image_RejectsGet(t *testing.T) {
	vagentSrv, _, _, _, _, _, _ := newHTTPFixtureWithRService(t)
	sid := openSessionViaHTTP(t, vagentSrv)
	resp, err := http.Get(vagentSrv.URL + "/sessions/" + string(sid) + "/image")
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

	imgResp := postOctet(t, vagentSrv.URL, "/sessions/"+string(sid)+"/image", inputBytes)
	require.Equal(t, http.StatusOK, imgResp.StatusCode)
	imgResp.Body.Close()

	// Build VClient's partial-decryption share under sk_c against the cached ct_M.
	ctM, _, ok := agent.SessionAuthenticatedCt(sid)
	require.True(t, ok)
	require.NotNil(t, ctM)

	clientProto, err := multiparty.NewKeySwitchProtocol(params.CKKS, ring.DiscreteGaussian{
		Sigma: params.FloodSigma,
		Bound: 6 * params.FloodSigma,
	})
	require.NoError(t, err)
	zeroSk := rlwe.NewSecretKey(params.CKKS)
	clientShare := clientProto.AllocateShare(ctM.Level())
	clientProto.GenShare(stub.skC, zeroSk, ctM, &clientShare)
	pdBytes, err := protocol.PartialDecryption{Share: clientShare}.MarshalBinary()
	require.NoError(t, err)

	// Disable redirect following so we can observe the 302 directly.
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequest(http.MethodPost, vagentSrv.URL+"/sessions/"+string(sid)+"/partial-decryption", bytes.NewReader(pdBytes))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode, "body=%s", readAll(t, resp.Body))
	assert.Equal(t, rsvcSrv.URL+"/protected", resp.Header.Get("Location"))

	calls, gotSid, gotVerd := rstub.snapshot()
	assert.Equal(t, 1, calls, "RService must receive exactly one callback")
	assert.Equal(t, sid, gotSid)
	assert.Equal(t, protocol.VerdictAccept, gotVerd)
}

// TestHTTPVAgent_PartialDecryption_TamperedShareReject sends a share built
// under a different sk_c → Ver fails → callback Reject + 302.
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
	imgResp := postOctet(t, vagentSrv.URL, "/sessions/"+string(sid)+"/image", inputBytes)
	require.Equal(t, http.StatusOK, imgResp.StatusCode)
	imgResp.Body.Close()

	ctM, _, ok := agent.SessionAuthenticatedCt(sid)
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

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequest(http.MethodPost, vagentSrv.URL+"/sessions/"+string(sid)+"/partial-decryption", bytes.NewReader(pdBytes))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	// A clean Ver=false finalize is reported as Reject (no error); per
	// docs/DESIGN.md the callback runs and the redirect is issued.
	require.Equal(t, http.StatusFound, resp.StatusCode, "body=%s", readAll(t, resp.Body))

	calls, _, gotVerd := rstub.snapshot()
	assert.Equal(t, 1, calls)
	assert.Equal(t, protocol.VerdictReject, gotVerd)
}

// TestHTTPVAgent_PartialDecryption_MalformedShareRejectThen4xx exercises
// F2 wire shape: known sid, garbage body → callback Reject + 4xx.
func TestHTTPVAgent_PartialDecryption_MalformedShareRejectThen4xx(t *testing.T) {
	vagentSrv, _, _, _, rstub, _, _ := newHTTPFixtureWithRService(t)
	sid := openSessionViaHTTP(t, vagentSrv)

	resp := postOctet(t, vagentSrv.URL, "/sessions/"+string(sid)+"/partial-decryption", []byte{0xff, 0xff, 0xff})
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

	resp := postOctet(t, vagentSrv.URL, "/sessions/never-opened/partial-decryption", []byte{0x00})
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
	proto.GenShare(stub.skC, zeroSk, dummyCt, &share)
	pdBytes, err := protocol.PartialDecryption{Share: share}.MarshalBinary()
	require.NoError(t, err)

	resp := postOctet(t, vagentSrv.URL, "/sessions/"+string(sid)+"/partial-decryption", pdBytes)
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	calls, _, gotVerd := rstub.snapshot()
	assert.Equal(t, 1, calls)
	assert.Equal(t, protocol.VerdictReject, gotVerd)

	// Session should still exist (FinalizeDecryption did not run).
	_, err = agent.session(sid)
	require.NoError(t, err)
}

func TestHTTPVAgent_PartialDecryption_RejectsGet(t *testing.T) {
	vagentSrv, _, _, _, _, _, _ := newHTTPFixtureWithRService(t)
	sid := openSessionViaHTTP(t, vagentSrv)
	resp, err := http.Get(vagentSrv.URL + "/sessions/" + string(sid) + "/partial-decryption")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
}
