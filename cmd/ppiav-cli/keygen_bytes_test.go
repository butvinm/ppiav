package main

import (
	"testing"

	"github.com/butvinm/ppiav/internal/bench"
	"github.com/butvinm/ppiav/internal/protocol"
	"github.com/butvinm/ppiav/internal/vagent"
	"github.com/butvinm/ppiav/internal/vclient"
	"github.com/butvinm/ppiav/internal/vservice"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v6/multiparty"
)

// TestKeygenShareSampleBytes drives the keygen handshake in-process at LogN=14
// and asserts each share-emitting sub-step records Sample.Bytes > 0 via the
// same byte-size helpers production uses (substituting MarshalBinary for
// BinarySize would break both call sites at once).
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

	// PK shares: capture each share inside its MeasureWithSize closure so the
	// aggregation steps can reuse it without re-running GenPKShare.
	var cPK protocol.VClientPKShare
	pkClientSample, err := bench.MeasureWithSize("keygen.pk.client_gen", func() (uint64, error) {
		cs, e := client.GenPKShare()
		if e != nil {
			return 0, e
		}
		cPK = cs
		return pkShareBytes(cs), nil
	})
	require.NoError(t, err)
	assert.Greater(t, pkClientSample.Bytes, uint64(0), "keygen.pk.client_gen Sample.Bytes must be > 0")

	var aPK protocol.VAgentPKShare
	pkAgentSample, err := bench.MeasureWithSize("keygen.pk.agent_gen", func() (uint64, error) {
		as, e := agent.GenPKShare(sid)
		if e != nil {
			return 0, e
		}
		aPK = as
		return agentPKShareBytes(as), nil
	})
	require.NoError(t, err)
	assert.Greater(t, pkAgentSample.Bytes, uint64(0), "keygen.pk.agent_gen Sample.Bytes must be > 0")

	require.NoError(t, agent.AggregatePK(sid, cPK))
	require.NoError(t, client.AggregatePK(aPK))

	// RLK round 1.
	var cR1 multiparty.RelinearizationKeyGenShare
	rlkR1ClientSample, err := bench.MeasureWithSize("keygen.rlk-r1.client_gen", func() (uint64, error) {
		cs, e := client.GenRLKShareRound1()
		if e != nil {
			return 0, e
		}
		cR1 = cs
		return rlkShareBytes(cs), nil
	})
	require.NoError(t, err)
	assert.Greater(t, rlkR1ClientSample.Bytes, uint64(0), "keygen.rlk-r1.client_gen Sample.Bytes must be > 0")

	var aR1 multiparty.RelinearizationKeyGenShare
	rlkR1AgentSample, err := bench.MeasureWithSize("keygen.rlk-r1.agent_gen", func() (uint64, error) {
		as, e := agent.GenRLKShareRound1(sid)
		if e != nil {
			return 0, e
		}
		aR1 = as
		return rlkShareBytes(as), nil
	})
	require.NoError(t, err)
	assert.Greater(t, rlkR1AgentSample.Bytes, uint64(0), "keygen.rlk-r1.agent_gen Sample.Bytes must be > 0")

	require.NoError(t, agent.AggregateRLKRound1(sid, cR1))
	require.NoError(t, client.AggregateRLKRound1(aR1))

	// RLK round 2.
	rlkR2ClientSample, err := bench.MeasureWithSize("keygen.rlk-r2.client_gen", func() (uint64, error) {
		cs, e := client.GenRLKShareRound2()
		if e != nil {
			return 0, e
		}
		return rlkShareBytes(cs), nil
	})
	require.NoError(t, err)
	assert.Greater(t, rlkR2ClientSample.Bytes, uint64(0), "keygen.rlk-r2.client_gen Sample.Bytes must be > 0")
	rlkR2AgentSample, err := bench.MeasureWithSize("keygen.rlk-r2.agent_gen", func() (uint64, error) {
		as, e := agent.GenRLKShareRound2(sid)
		if e != nil {
			return 0, e
		}
		return rlkShareBytes(as), nil
	})
	require.NoError(t, err)
	assert.Greater(t, rlkR2AgentSample.Bytes, uint64(0), "keygen.rlk-r2.agent_gen Sample.Bytes must be > 0")

	// Galois master shares.
	galoisClientSample, err := bench.MeasureWithSize("keygen.galois.client_gen", func() (uint64, error) {
		cMaster, _, e := client.GenMasterShares()
		if e != nil {
			return 0, e
		}
		return galoisShareBytes(cMaster), nil
	})
	require.NoError(t, err)
	assert.Greater(t, galoisClientSample.Bytes, uint64(0), "keygen.galois.client_gen Sample.Bytes must be > 0")
	galoisAgentSample, err := bench.MeasureWithSize("keygen.galois.agent_gen", func() (uint64, error) {
		aMaster, _, e := agent.GenMasterShares(sid)
		if e != nil {
			return 0, e
		}
		return galoisShareBytes(aMaster), nil
	})
	require.NoError(t, err)
	assert.Greater(t, galoisAgentSample.Bytes, uint64(0), "keygen.galois.agent_gen Sample.Bytes must be > 0")
}
