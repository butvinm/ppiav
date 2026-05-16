package main

import (
	"testing"

	"github.com/butvinm/ppiav/internal/bench"
	"github.com/butvinm/ppiav/internal/vagent"
	"github.com/butvinm/ppiav/internal/vclient"
	"github.com/butvinm/ppiav/internal/vservice"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v6/multiparty"
)

// TestKeygenShareSampleBytes drives the same eight `bench.MeasureWithSize`
// closures keygen.go uses for the share-emitting sub-steps and asserts
// each Sample.Bytes is non-zero. Runs at LogN=14 (smallCLIParams) so it
// finishes within a few seconds on the dev box per CLAUDE.md's
// "no LogN=15 tests locally" rule.
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
		return uint64(cs.ShareEval.BinarySize() + cs.ShareTop.BinarySize()), nil
	})
	require.NoError(t, err)
	assert.Greater(t, pkClientSample.Bytes, uint64(0), "keygen.pk.client_gen Sample.Bytes must be > 0")

	pkAgentSample, err := bench.MeasureWithSize("keygen.pk.agent_gen", func() (uint64, error) {
		as, e := agent.GenPKShare(sid)
		if e != nil {
			return 0, e
		}
		return uint64(as.ShareEval.BinarySize() + as.ShareTop.BinarySize()), nil
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
	var clientR1 multiparty.RelinearizationKeyGenShare
	rlkR1ClientSample, err := bench.MeasureWithSize("keygen.rlk-r1.client_gen", func() (uint64, error) {
		cs, e := client.GenRLKShareRound1()
		if e != nil {
			return 0, e
		}
		clientR1 = cs
		return uint64(cs.BinarySize()), nil
	})
	require.NoError(t, err)
	assert.Greater(t, rlkR1ClientSample.Bytes, uint64(0), "keygen.rlk-r1.client_gen Sample.Bytes must be > 0")

	var agentR1 multiparty.RelinearizationKeyGenShare
	rlkR1AgentSample, err := bench.MeasureWithSize("keygen.rlk-r1.agent_gen", func() (uint64, error) {
		as, e := agent.GenRLKShareRound1(sid)
		if e != nil {
			return 0, e
		}
		agentR1 = as
		return uint64(as.BinarySize()), nil
	})
	require.NoError(t, err)
	assert.Greater(t, rlkR1AgentSample.Bytes, uint64(0), "keygen.rlk-r1.agent_gen Sample.Bytes must be > 0")

	require.NoError(t, agent.AggregateRLKRound1(sid, clientR1))
	require.NoError(t, client.AggregateRLKRound1(agentR1))

	// --- RLK round 2 -------------------------------------------------------
	rlkR2ClientSample, err := bench.MeasureWithSize("keygen.rlk-r2.client_gen", func() (uint64, error) {
		cs, e := client.GenRLKShareRound2()
		if e != nil {
			return 0, e
		}
		return uint64(cs.BinarySize()), nil
	})
	require.NoError(t, err)
	assert.Greater(t, rlkR2ClientSample.Bytes, uint64(0), "keygen.rlk-r2.client_gen Sample.Bytes must be > 0")

	rlkR2AgentSample, err := bench.MeasureWithSize("keygen.rlk-r2.agent_gen", func() (uint64, error) {
		as, e := agent.GenRLKShareRound2(sid)
		if e != nil {
			return 0, e
		}
		return uint64(as.BinarySize()), nil
	})
	require.NoError(t, err)
	assert.Greater(t, rlkR2AgentSample.Bytes, uint64(0), "keygen.rlk-r2.agent_gen Sample.Bytes must be > 0")

	// --- Galois master shares ---------------------------------------------
	galoisClientSample, err := bench.MeasureWithSize("keygen.galois.client_gen", func() (uint64, error) {
		cm, _, e := client.GenMasterShares()
		if e != nil {
			return 0, e
		}
		var total uint64
		for i := range cm {
			total += uint64(cm[i].BinarySize())
		}
		return total, nil
	})
	require.NoError(t, err)
	assert.Greater(t, galoisClientSample.Bytes, uint64(0), "keygen.galois.client_gen Sample.Bytes must be > 0")

	galoisAgentSample, err := bench.MeasureWithSize("keygen.galois.agent_gen", func() (uint64, error) {
		am, _, e := agent.GenMasterShares(sid)
		if e != nil {
			return 0, e
		}
		var total uint64
		for i := range am {
			total += uint64(am[i].BinarySize())
		}
		return total, nil
	})
	require.NoError(t, err)
	assert.Greater(t, galoisAgentSample.Bytes, uint64(0), "keygen.galois.agent_gen Sample.Bytes must be > 0")
}
