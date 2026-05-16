package main

import (
	"flag"
	"fmt"

	"github.com/butvinm/ppiav/internal/bench"
	"github.com/butvinm/ppiav/internal/protocol"
	"github.com/butvinm/ppiav/internal/vagent"
	"github.com/butvinm/ppiav/internal/vclient"
	"github.com/butvinm/ppiav/internal/vservice"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
)

// runKeygen drives the bilateral collaborative keygen in-process and writes
// every per-session artifact (keys, sid, params, mac key) to <workdir>/.
// Per-round wall-time / RSS samples are appended to a single bench.Run named
// "keygen" with sub-step names keygen.open / keygen.pk / keygen.rlk-r1 /
// keygen.rlk-r2 / keygen.galois.
//
// The flow mirrors orchestrator.Setup but additionally captures
// pk_agg / sk_c / sk_a / rlk_agg / gks plus the agent's per-session
// authKey so the rest of the per-step CLIs can rebuild VClient / VAgent /
// VService via their respective NewWithState constructors.
func runKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	workdir := fs.String("workdir", "", "per-batch directory to hold keygen artifacts (required)")
	orionDir := fs.String("orion", "", "Orion compiled-model directory (empty => synthetic x² params)")
	outPath := fs.String("out", "", "timing JSON output path (default <workdir>/keygen.json)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *workdir == "" {
		return fmt.Errorf("keygen: --workdir is required")
	}

	// The synthetic-x² path (no --orion) uses Defaults() directly; the Orion
	// path (--orion <dir>) also starts at Defaults() so VAgent has a parameter
	// set to construct against before vservice.NewWithOrion produces the
	// authoritative manifest-derived params (see the rebuild below).
	params, err := protocol.Defaults()
	if err != nil {
		return fmt.Errorf("keygen: build default params: %w", err)
	}

	run := bench.NewRun("keygen", benchPhase)
	run.Metadata["workdir"] = *workdir
	if *orionDir != "" {
		run.Metadata["orion_dir"] = *orionDir
	}

	// Build the three peers up-front so they share the same params and the
	// VService session table is ready for the SID mint.
	agent, err := vagent.New(params)
	if err != nil {
		return fmt.Errorf("keygen: build VAgent: %w", err)
	}
	var svc *vservice.Service
	if *orionDir == "" {
		svc = vservice.New(params)
	} else {
		svc, err = vservice.NewWithOrion(params, *orionDir)
		if err != nil {
			return fmt.Errorf("keygen: build VService with Orion: %w", err)
		}
		// vservice.NewWithOrion may override CKKS / InputLevel / rotations;
		// rebuild the Agent under the service's authoritative params so all
		// three peers consume the same source of truth (mirrors
		// orchestrator.NewRunnerWithOrion).
		params = svc.Params()
		agent, err = vagent.New(params)
		if err != nil {
			return fmt.Errorf("keygen: rebuild VAgent under Orion params: %w", err)
		}
	}

	// keygen.open: VService mints sid, VAgent registers, VClient is built
	// against sid. Wrap the whole three-step open as one timed block — the
	// underlying calls are sub-millisecond and splitting them would just
	// add JSON noise.
	var (
		sid    protocol.SessionID
		client *vclient.Client
	)
	// Helper: time a single per-party call and append the sample. Returns
	// the inner function's error so the caller short-circuits cleanly.
	measureStep := func(name string, fn func() error) error {
		sample, mErr := bench.Measure(name, fn)
		run.Append(sample)
		return mErr
	}

	// keygen.open — per-party session-state writes (sub-millisecond each).
	if err := measureStep("keygen.open.service", func() error {
		s, e := svc.OpenSession()
		if e != nil {
			return fmt.Errorf("VService.OpenSession: %w", e)
		}
		sid = s
		return nil
	}); err != nil {
		_ = run.WriteJSON(stepOutPath(*outPath, *workdir, "keygen"))
		return fmt.Errorf("keygen: open.service: %w", err)
	}
	if err := measureStep("keygen.open.agent", func() error {
		return agent.OpenSession(sid)
	}); err != nil {
		_ = run.WriteJSON(stepOutPath(*outPath, *workdir, "keygen"))
		return fmt.Errorf("keygen: open.agent: %w", err)
	}
	if err := measureStep("keygen.open.client", func() error {
		c, e := vclient.New(params, sid)
		if e != nil {
			return e
		}
		client = c
		return nil
	}); err != nil {
		_ = run.WriteJSON(stepOutPath(*outPath, *workdir, "keygen"))
		return fmt.Errorf("keygen: open.client: %w", err)
	}

	// keygen.pk — Generate-on-client, generate-on-agent, aggregate-on-agent,
	// aggregate-on-client. Mirrors protocol.puml § "Генерация открытого ключа".
	{
		var clientShare, agentShare any
		if err := measureStep("keygen.pk.client_gen", func() error {
			cs, e := client.GenPKShare()
			clientShare = cs
			return e
		}); err != nil {
			_ = run.WriteJSON(stepOutPath(*outPath, *workdir, "keygen"))
			return fmt.Errorf("keygen: pk.client_gen: %w", err)
		}
		if err := measureStep("keygen.pk.agent_gen", func() error {
			as, e := agent.GenPKShare(sid)
			agentShare = as
			return e
		}); err != nil {
			_ = run.WriteJSON(stepOutPath(*outPath, *workdir, "keygen"))
			return fmt.Errorf("keygen: pk.agent_gen: %w", err)
		}
		if err := measureStep("keygen.pk.agent_agg", func() error {
			return agent.AggregatePK(sid, clientShare.(multiparty.PublicKeyGenShare))
		}); err != nil {
			_ = run.WriteJSON(stepOutPath(*outPath, *workdir, "keygen"))
			return fmt.Errorf("keygen: pk.agent_agg: %w", err)
		}
		if err := measureStep("keygen.pk.client_agg", func() error {
			return client.AggregatePK(agentShare.(multiparty.PublicKeyGenShare))
		}); err != nil {
			_ = run.WriteJSON(stepOutPath(*outPath, *workdir, "keygen"))
			return fmt.Errorf("keygen: pk.client_agg: %w", err)
		}
	}

	// keygen.rlk-r1 — same shape as pk: client_gen → agent_gen → agent_agg → client_agg.
	{
		var clientR1, agentR1 any
		if err := measureStep("keygen.rlk-r1.client_gen", func() error {
			cs, e := client.GenRLKShareRound1()
			clientR1 = cs
			return e
		}); err != nil {
			_ = run.WriteJSON(stepOutPath(*outPath, *workdir, "keygen"))
			return fmt.Errorf("keygen: rlk-r1.client_gen: %w", err)
		}
		if err := measureStep("keygen.rlk-r1.agent_gen", func() error {
			as, e := agent.GenRLKShareRound1(sid)
			agentR1 = as
			return e
		}); err != nil {
			_ = run.WriteJSON(stepOutPath(*outPath, *workdir, "keygen"))
			return fmt.Errorf("keygen: rlk-r1.agent_gen: %w", err)
		}
		if err := measureStep("keygen.rlk-r1.agent_agg", func() error {
			return agent.AggregateRLKRound1(sid, clientR1.(multiparty.RelinearizationKeyGenShare))
		}); err != nil {
			_ = run.WriteJSON(stepOutPath(*outPath, *workdir, "keygen"))
			return fmt.Errorf("keygen: rlk-r1.agent_agg: %w", err)
		}
		if err := measureStep("keygen.rlk-r1.client_agg", func() error {
			return client.AggregateRLKRound1(agentR1.(multiparty.RelinearizationKeyGenShare))
		}); err != nil {
			_ = run.WriteJSON(stepOutPath(*outPath, *workdir, "keygen"))
			return fmt.Errorf("keygen: rlk-r1.client_agg: %w", err)
		}
	}

	// keygen.rlk-r2 — final rlk lives on the agent; no client_agg.
	{
		var clientR2 any
		if err := measureStep("keygen.rlk-r2.client_gen", func() error {
			cs, e := client.GenRLKShareRound2()
			clientR2 = cs
			return e
		}); err != nil {
			_ = run.WriteJSON(stepOutPath(*outPath, *workdir, "keygen"))
			return fmt.Errorf("keygen: rlk-r2.client_gen: %w", err)
		}
		if err := measureStep("keygen.rlk-r2.agent_gen", func() error {
			_, e := agent.GenRLKShareRound2(sid)
			return e
		}); err != nil {
			_ = run.WriteJSON(stepOutPath(*outPath, *workdir, "keygen"))
			return fmt.Errorf("keygen: rlk-r2.agent_gen: %w", err)
		}
		if err := measureStep("keygen.rlk-r2.agent_agg", func() error {
			return agent.AggregateRLKRound2(sid, clientR2.(multiparty.RelinearizationKeyGenShare))
		}); err != nil {
			_ = run.WriteJSON(stepOutPath(*outPath, *workdir, "keygen"))
			return fmt.Errorf("keygen: rlk-r2.agent_agg: %w", err)
		}
	}

	// keygen.galois — VClient emits per-rotation shares, VAgent aggregates,
	// VService stores the finalized evaluator keys.
	var (
		rlk *rlwe.RelinearizationKey
		gks []*rlwe.GaloisKey
	)
	{
		var (
			clientGalShares any
			clientLabels    any
		)
		if err := measureStep("keygen.galois.client_gen", func() error {
			cs, cl, e := client.GenGaloisShares()
			clientGalShares = cs
			clientLabels = cl
			return e
		}); err != nil {
			_ = run.WriteJSON(stepOutPath(*outPath, *workdir, "keygen"))
			return fmt.Errorf("keygen: galois.client_gen: %w", err)
		}
		if err := measureStep("keygen.galois.agent_gen", func() error {
			_, _, e := agent.GenGaloisShares(sid)
			return e
		}); err != nil {
			_ = run.WriteJSON(stepOutPath(*outPath, *workdir, "keygen"))
			return fmt.Errorf("keygen: galois.agent_gen: %w", err)
		}
		if err := measureStep("keygen.galois.agent_agg", func() error {
			aggRlk, aggGks, e := agent.AggregateGaloisShares(
				sid,
				clientGalShares.([]multiparty.GaloisKeyGenShare),
				clientLabels.([]int),
			)
			if e != nil {
				return e
			}
			rlk = aggRlk
			gks = aggGks
			return nil
		}); err != nil {
			_ = run.WriteJSON(stepOutPath(*outPath, *workdir, "keygen"))
			return fmt.Errorf("keygen: galois.agent_agg: %w", err)
		}
		if err := measureStep("keygen.galois.service_store", func() error {
			return svc.StoreEvalKeys(sid, rlk, gks)
		}); err != nil {
			_ = run.WriteJSON(stepOutPath(*outPath, *workdir, "keygen"))
			return fmt.Errorf("keygen: galois.service_store: %w", err)
		}
	}

	// Snapshot per-peer state so we can write the artifacts. ExportState on
	// each peer is the bridge between the live in-process keygen and the
	// disk artifacts consumed by encrypt/infer/mac/partial-decrypt/finalize.
	clientState, err := client.ExportState()
	if err != nil {
		return fmt.Errorf("keygen: VClient.ExportState: %w", err)
	}
	agentState, err := agent.ExportState(sid)
	if err != nil {
		return fmt.Errorf("keygen: VAgent.ExportState: %w", err)
	}

	if err := writeKeygenArtifacts(*workdir, params, sid, clientState, agentState, rlk, gks); err != nil {
		return fmt.Errorf("keygen: write artifacts: %w", err)
	}

	if err := run.WriteJSON(stepOutPath(*outPath, *workdir, "keygen")); err != nil {
		return fmt.Errorf("keygen: write run JSON: %w", err)
	}
	return nil
}

// (buildKeygenParams + outPathOrDefault inlined: keygen now uses
// protocol.Defaults() directly and stepOutPath in main.go.)

// writeKeygenArtifacts persists every file the downstream subcommands
// load. Aggregated GLK is emitted twice (glk_master.bin + glk_full.bin)
// per docs/plans: identical bytes today, divergent after lattigo-hierkeys
// integration. The aggregator gets per-artifact byte sizes via
// os.Stat on these filenames — there is no need to record them in the
// bench JSON.
func writeKeygenArtifacts(
	workdir string,
	params protocol.Params,
	sid protocol.SessionID,
	clientState *vclient.ExportedState,
	agentState *vagent.ExportedState,
	rlk *rlwe.RelinearizationKey,
	gks []*rlwe.GaloisKey,
) error {
	if err := writeSID(workdir, sid); err != nil {
		return err
	}
	if err := writeParams(workdir, params); err != nil {
		return err
	}
	if err := writePublicKey(workdir, clientState.PkAgg); err != nil {
		return err
	}
	if err := writeSecretKey(workdir, artifactSKClient, clientState.SkShare); err != nil {
		return err
	}
	if err := writeSecretKey(workdir, artifactSKAgent, agentState.SkShare); err != nil {
		return err
	}
	if err := writeRelinearizationKey(workdir, rlk); err != nil {
		return err
	}
	if err := writeGaloisKeys(workdir, artifactGLKMaster, gks); err != nil {
		return err
	}
	if err := writeGaloisKeys(workdir, artifactGLKFull, gks); err != nil {
		return err
	}
	if err := writeMacKey(workdir, agentState.MacKey); err != nil {
		return err
	}
	return nil
}
