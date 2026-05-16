package main

import (
	"testing"

	"github.com/butvinm/ppiav/internal/bench"
	"github.com/butvinm/ppiav/internal/vagent"
	"github.com/butvinm/ppiav/internal/vclient"
	"github.com/butvinm/ppiav/internal/vservice"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestKeygenShareSampleBytes drives the keygen handshake in-process at
// LogN=14 and asserts each share-emitting sub-step records a non-zero
// Sample.Bytes. The byte arithmetic uses the same `pkShareBytes` /
// `agentPKShareBytes` / `rlkShareBytes` / `galoisShareBytes` helpers as
// `runKeygen` itself — substituting `len(MarshalBinary())` for
// `BinarySize()` in production would break both call sites at once.
//
// The eight share sub-steps under test:
//   - keygen.pk.client_gen        (VClientPKShare: ShareEval + ShareTop)
//   - keygen.pk.agent_gen         (VAgentPKShare:  ShareEval + ShareTop)
//   - keygen.rlk-r1.client_gen    (RelinearizationKeyGenShare)
//   - keygen.rlk-r1.agent_gen     (RelinearizationKeyGenShare)
//   - keygen.rlk-r2.client_gen    (RelinearizationKeyGenShare)
//   - keygen.rlk-r2.agent_gen     (RelinearizationKeyGenShare)
//   - keygen.galois.client_gen    ([]GaloisKeyGenShare — summed)
//   - keygen.galois.agent_gen     ([]GaloisKeyGenShare — summed)
//
// Aggregation sub-steps (*.agent_agg / *.client_agg / *.service_store) are
// intentionally NOT covered — they don't produce a new share, so they stay
// on plain Measure (Bytes=0 by design) per the plan.
func TestKeygenShareSampleBytes(t *testing.T) {
	params := smallCLIParams(t)

	agent, err := vagent.New(params)
	require.NoError(t, err)
	svc := vservice.New(params)
	sid, err := svc.OpenSession()
	require.NoError(t, err)
	require.NoError(t, agent.OpenSession(sid))
	client, err := vclient.New(params, sid)
	require.NoError(t, err)

	// --- PK shares ---------------------------------------------------------
	pkClientSample, err := bench.MeasureWithSize("keygen.pk.client_gen", func() (uint64, error) {
		cs, e := client.GenPKShare()
		if e != nil {
			return 0, e
		}
		return pkShareBytes(cs), nil
	})
	require.NoError(t, err)
	assert.Greater(t, pkClientSample.Bytes, uint64(0), "keygen.pk.client_gen Sample.Bytes must be > 0")

	pkAgentSample, err := bench.MeasureWithSize("keygen.pk.agent_gen", func() (uint64, error) {
		as, e := agent.GenPKShare(sid)
		if e != nil {
			return 0, e
		}
		return agentPKShareBytes(as), nil
	})
	require.NoError(t, err)
	assert.Greater(t, pkAgentSample.Bytes, uint64(0), "keygen.pk.agent_gen Sample.Bytes must be > 0")

	// Aggregate so the round-1 protocol has a valid PK aggregate to lean on.
	cPK, err := client.GenPKShare()
	require.NoError(t, err)
	aPK, err := agent.GenPKShare(sid)
	require.NoError(t, err)
	require.NoError(t, agent.AggregatePK(sid, cPK))
	require.NoError(t, client.AggregatePK(aPK))

	// --- RLK round 1 -------------------------------------------------------
	cR1, err := client.GenRLKShareRound1()
	require.NoError(t, err)
	aR1, err := agent.GenRLKShareRound1(sid)
	require.NoError(t, err)
	rlkR1ClientSample, err := bench.MeasureWithSize("keygen.rlk-r1.client_gen", func() (uint64, error) {
		return rlkShareBytes(cR1), nil
	})
	require.NoError(t, err)
	assert.Greater(t, rlkR1ClientSample.Bytes, uint64(0), "keygen.rlk-r1.client_gen Sample.Bytes must be > 0")
	rlkR1AgentSample, err := bench.MeasureWithSize("keygen.rlk-r1.agent_gen", func() (uint64, error) {
		return rlkShareBytes(aR1), nil
	})
	require.NoError(t, err)
	assert.Greater(t, rlkR1AgentSample.Bytes, uint64(0), "keygen.rlk-r1.agent_gen Sample.Bytes must be > 0")

	require.NoError(t, agent.AggregateRLKRound1(sid, cR1))
	require.NoError(t, client.AggregateRLKRound1(aR1))

	// --- RLK round 2 -------------------------------------------------------
	cR2, err := client.GenRLKShareRound2()
	require.NoError(t, err)
	aR2, err := agent.GenRLKShareRound2(sid)
	require.NoError(t, err)
	rlkR2ClientSample, err := bench.MeasureWithSize("keygen.rlk-r2.client_gen", func() (uint64, error) {
		return rlkShareBytes(cR2), nil
	})
	require.NoError(t, err)
	assert.Greater(t, rlkR2ClientSample.Bytes, uint64(0), "keygen.rlk-r2.client_gen Sample.Bytes must be > 0")
	rlkR2AgentSample, err := bench.MeasureWithSize("keygen.rlk-r2.agent_gen", func() (uint64, error) {
		return rlkShareBytes(aR2), nil
	})
	require.NoError(t, err)
	assert.Greater(t, rlkR2AgentSample.Bytes, uint64(0), "keygen.rlk-r2.agent_gen Sample.Bytes must be > 0")

	// --- Galois master shares ---------------------------------------------
	cMaster, _, err := client.GenMasterShares()
	require.NoError(t, err)
	aMaster, _, err := agent.GenMasterShares(sid)
	require.NoError(t, err)
	galoisClientSample, err := bench.MeasureWithSize("keygen.galois.client_gen", func() (uint64, error) {
		return galoisShareBytes(cMaster), nil
	})
	require.NoError(t, err)
	assert.Greater(t, galoisClientSample.Bytes, uint64(0), "keygen.galois.client_gen Sample.Bytes must be > 0")
	galoisAgentSample, err := bench.MeasureWithSize("keygen.galois.agent_gen", func() (uint64, error) {
		return galoisShareBytes(aMaster), nil
	})
	require.NoError(t, err)
	assert.Greater(t, galoisAgentSample.Bytes, uint64(0), "keygen.galois.agent_gen Sample.Bytes must be > 0")
}
