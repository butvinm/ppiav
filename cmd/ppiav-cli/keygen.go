package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	hierkeys "github.com/butvinm/lattigo-hierkeys"
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
// pkEval / pkTop / sk_c / sk_a / rlkAgg / gksAuth / gksMasterInfer plus the
// agent's per-session authKey so the rest of the per-step CLIs can rebuild
// VClient / VAgent / VService via their respective NewWithState constructors.
//
// `keygen.galois.{client_gen, agent_gen, agent_agg}` each cover BOTH atom
// sets (auth + infer) in a single combined sample — the dual-atom-set
// design keeps the two iterations inside one method call, and the bench
// harness compares the combined cost cross-phase. The `service_store`
// sample additionally records `derive_gks_infer_seconds` (the wall-clock
// time spent inside StoreEvalKeys running hierkeys.LevelExpansion +
// FinalizeKey on the InferAtoms → gks_infer derivation), surfaced via
// `Service.DeriveGksInferSeconds(sid)`.
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
	writeRunOnExit := func() { _ = run.WriteJSON(stepOutPath(*outPath, *workdir, "keygen")) }

	// keygen.open — per-party session-state writes (sub-millisecond each).
	if err := measureStep("keygen.open.service", func() error {
		s, e := svc.OpenSession()
		if e != nil {
			return fmt.Errorf("VService.OpenSession: %w", e)
		}
		sid = s
		return nil
	}); err != nil {
		writeRunOnExit()
		return fmt.Errorf("keygen: open.service: %w", err)
	}
	if err := measureStep("keygen.open.agent", func() error {
		return agent.OpenSession(sid)
	}); err != nil {
		writeRunOnExit()
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
		writeRunOnExit()
		return fmt.Errorf("keygen: open.client: %w", err)
	}

	// keygen.pk — dual-level (eval + top) handshake. Each share is a
	// protocol.VClientPKShare / VAgentPKShare carrying both
	// `ShareEval` and `ShareTop`. The aggregator wires both into the
	// collective pkEval and pkTop.
	{
		var (
			clientShare protocol.VClientPKShare
			agentShare  protocol.VAgentPKShare
		)
		if err := measureStep("keygen.pk.client_gen", func() error {
			cs, e := client.GenPKShare()
			clientShare = cs
			return e
		}); err != nil {
			writeRunOnExit()
			return fmt.Errorf("keygen: pk.client_gen: %w", err)
		}
		if err := measureStep("keygen.pk.agent_gen", func() error {
			as, e := agent.GenPKShare(sid)
			agentShare = as
			return e
		}); err != nil {
			writeRunOnExit()
			return fmt.Errorf("keygen: pk.agent_gen: %w", err)
		}
		if err := measureStep("keygen.pk.agent_agg", func() error {
			return agent.AggregatePK(sid, clientShare)
		}); err != nil {
			writeRunOnExit()
			return fmt.Errorf("keygen: pk.agent_agg: %w", err)
		}
		if err := measureStep("keygen.pk.client_agg", func() error {
			return client.AggregatePK(agentShare)
		}); err != nil {
			writeRunOnExit()
			return fmt.Errorf("keygen: pk.client_agg: %w", err)
		}
	}

	// keygen.rlk-r1 — same shape as pk: client_gen → agent_gen → agent_agg → client_agg.
	{
		var (
			clientR1 any
			agentR1  any
		)
		if err := measureStep("keygen.rlk-r1.client_gen", func() error {
			cs, e := client.GenRLKShareRound1()
			clientR1 = cs
			return e
		}); err != nil {
			writeRunOnExit()
			return fmt.Errorf("keygen: rlk-r1.client_gen: %w", err)
		}
		if err := measureStep("keygen.rlk-r1.agent_gen", func() error {
			as, e := agent.GenRLKShareRound1(sid)
			agentR1 = as
			return e
		}); err != nil {
			writeRunOnExit()
			return fmt.Errorf("keygen: rlk-r1.agent_gen: %w", err)
		}
		if err := measureStep("keygen.rlk-r1.agent_agg", func() error {
			return agent.AggregateRLKRound1(sid, clientR1.(multiparty.RelinearizationKeyGenShare))
		}); err != nil {
			writeRunOnExit()
			return fmt.Errorf("keygen: rlk-r1.agent_agg: %w", err)
		}
		if err := measureStep("keygen.rlk-r1.client_agg", func() error {
			return client.AggregateRLKRound1(agentR1.(multiparty.RelinearizationKeyGenShare))
		}); err != nil {
			writeRunOnExit()
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
			writeRunOnExit()
			return fmt.Errorf("keygen: rlk-r2.client_gen: %w", err)
		}
		if err := measureStep("keygen.rlk-r2.agent_gen", func() error {
			_, e := agent.GenRLKShareRound2(sid)
			return e
		}); err != nil {
			writeRunOnExit()
			return fmt.Errorf("keygen: rlk-r2.agent_gen: %w", err)
		}
		if err := measureStep("keygen.rlk-r2.agent_agg", func() error {
			return agent.AggregateRLKRound2(sid, clientR2.(multiparty.RelinearizationKeyGenShare))
		}); err != nil {
			writeRunOnExit()
			return fmt.Errorf("keygen: rlk-r2.agent_agg: %w", err)
		}
	}

	// keygen.galois — dual-atom-set handshake. VClient and VAgent each emit
	// auth+infer share lists in a single call; the aggregator finalises
	// `gksAuth` (eval-level raw GaloisKeys, kept inside the VAgent session)
	// and `gksMasterInfer` (top-level hierkeys.MasterKey bundle, forwarded
	// to VService alongside pkTop). VService runs the hierkeys derivation
	// inside StoreEvalKeys.
	var (
		rlk            *rlwe.RelinearizationKey
		pkTop          *rlwe.PublicKey
		gksMasterInfer map[int]*hierkeys.MasterKey
	)
	{
		var (
			clientAuthShares  any
			clientInferShares any
		)
		if err := measureStep("keygen.galois.client_gen", func() error {
			ca, ci, _, _, e := client.GenAuthAndInferShares()
			if e != nil {
				return e
			}
			clientAuthShares = ca
			clientInferShares = ci
			return nil
		}); err != nil {
			writeRunOnExit()
			return fmt.Errorf("keygen: galois.client_gen: %w", err)
		}
		if err := measureStep("keygen.galois.agent_gen", func() error {
			_, _, _, _, e := agent.GenAuthAndInferShares(sid)
			return e
		}); err != nil {
			writeRunOnExit()
			return fmt.Errorf("keygen: galois.agent_gen: %w", err)
		}
		if err := measureStep("keygen.galois.agent_agg", func() error {
			shares := protocol.VClientGaloisShares{
				AuthAtomShares:  clientAuthShares.([]multiparty.GaloisKeyGenShare),
				InferAtomShares: clientInferShares.([]multiparty.GaloisKeyGenShare),
			}
			aggRlk, aggPkTop, aggMasters, e := agent.AggregateGaloisShares(sid, shares)
			if e != nil {
				return e
			}
			rlk = aggRlk
			pkTop = aggPkTop
			gksMasterInfer = aggMasters
			return nil
		}); err != nil {
			writeRunOnExit()
			return fmt.Errorf("keygen: galois.agent_agg: %w", err)
		}
		// service_store covers VService running hierkeys.LevelExpansion +
		// FinalizeKey on every InferAtom — the dominant per-session cost
		// at LogN=16 (multi-minute sequential, tens of seconds concurrent).
		// The wall-clock time also lands in run.Metadata so the bench
		// driver can report sequential vs concurrent variants.
		if err := measureStep("keygen.galois.service_store", func() error {
			return svc.StoreEvalKeys(sid, rlk, pkTop, gksMasterInfer)
		}); err != nil {
			writeRunOnExit()
			return fmt.Errorf("keygen: galois.service_store: %w", err)
		}
		if d, ok := svc.DeriveGksInferSeconds(sid); ok {
			run.Metadata["derive_gks_infer_seconds"] = d
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
	svcState, err := svc.ExportState(sid)
	if err != nil {
		return fmt.Errorf("keygen: VService.ExportState: %w", err)
	}

	if err := writeKeygenArtifacts(*workdir, params, sid, clientState, agentState, svcState); err != nil {
		return fmt.Errorf("keygen: write artifacts: %w", err)
	}

	// Record on-disk sizes for the bench cross-phase wire-size comparison.
	// gks_auth.bin + gks_master_infer.bin together carry the agent-side
	// rotation-key payload; gks_infer.bin is a local cache of the derived
	// rotation set and not part of the wire payload.
	if size, e := fileSize(*workdir, artifactGKSAuth); e == nil {
		run.Metadata["gks_auth_bytes"] = size
	}
	if size, e := fileSize(*workdir, artifactGKSMasterInfer); e == nil {
		run.Metadata["gks_master_infer_bytes"] = size
	}

	if err := run.WriteJSON(stepOutPath(*outPath, *workdir, "keygen")); err != nil {
		return fmt.Errorf("keygen: write run JSON: %w", err)
	}
	return nil
}

// writeKeygenArtifacts persists every file the downstream subcommands
// load: `pk_eval.bin` + `pk_top.bin` + `gks_auth.bin` +
// `gks_master_infer.bin` + `gks_infer.bin`.
//
// `gks_auth.bin` is the auth-side raw multi-party Galois keys (eval level,
// negative galEls) — VAgent uses it directly to drive authchain.Evaluator.
// `gks_master_infer.bin` is the wire artifact (cross-phase size comparison).
// `gks_infer.bin` is VService's per-target Galois key set, derived once
// at keygen and cached because per-sample re-derivation is multi-minute
// at LogN=16.
func writeKeygenArtifacts(
	workdir string,
	params protocol.Params,
	sid protocol.SessionID,
	clientState *vclient.ExportedState,
	agentState *vagent.ExportedState,
	svcState *vservice.ExportedState,
) error {
	if err := writeSID(workdir, sid); err != nil {
		return err
	}
	if err := writeParams(workdir, params); err != nil {
		return err
	}
	// pk_eval — used by VClient.EncryptImage and by VAgent's Auth (encrypt
	// of the random v vector). Client state carries this as `PkAgg`.
	if err := writePublicKey(workdir, artifactPKEval, clientState.PkAgg); err != nil {
		return err
	}
	// pk_top — needed by VService to seed hierkeys.PubToRot during the
	// gks_infer derivation. The Agent state's PkTop is the source of
	// truth (mirrors the wire path: VAgent ships PKTop to VService).
	if err := writePublicKey(workdir, artifactPKTop, agentState.PkTop); err != nil {
		return err
	}
	if err := writeSecretKey(workdir, artifactSKClient, clientState.SkTop); err != nil {
		return err
	}
	if err := writeSecretKey(workdir, artifactSKAgent, agentState.SkTop); err != nil {
		return err
	}
	if err := writeRelinearizationKey(workdir, agentState.Rlk); err != nil {
		return err
	}
	// gks_auth — VAgent's auth atoms. Persisted because the CLI's
	// stage-process model has no in-memory channel between keygen and mac.
	if err := writeGaloisKeys(workdir, artifactGKSAuth, agentState.GksAuth); err != nil {
		return err
	}
	// gks_master_infer — VAgent's hierkeys MasterKey bundle (wire artifact).
	if err := writeMasterKeys(workdir, artifactGKSMasterInfer, agentState.GksMasterInfer); err != nil {
		return err
	}
	// gks_infer — VService's derived per-target Galois keys (eval level).
	if err := writeGaloisKeys(workdir, artifactGKSInfer, svcState.GksInfer); err != nil {
		return err
	}
	if err := writeMacKey(workdir, agentState.MacKey); err != nil {
		return err
	}
	return nil
}

// fileSize returns the byte size of <workdir>/<name>; not found → error.
// Used to record per-artifact sizes in the keygen.json metadata.
func fileSize(workdir, name string) (int64, error) {
	info, err := os.Stat(filepath.Join(workdir, name))
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}
