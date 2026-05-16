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
	openSample, err := bench.Measure("keygen.open", func() error {
		s, openErr := svc.OpenSession()
		if openErr != nil {
			return fmt.Errorf("VService.OpenSession: %w", openErr)
		}
		if openErr := agent.OpenSession(s); openErr != nil {
			return fmt.Errorf("VAgent.OpenSession: %w", openErr)
		}
		c, openErr := vclient.New(params, s)
		if openErr != nil {
			return fmt.Errorf("vclient.New: %w", openErr)
		}
		sid = s
		client = c
		return nil
	})
	run.Append(openSample)
	if err != nil {
		_ = run.WriteJSON(stepOutPath(*outPath, *workdir, "keygen"))
		return fmt.Errorf("keygen: open: %w", err)
	}

	// keygen.pk: bilateral PK share exchange + aggregation on both sides.
	pkSample, err := bench.Measure("keygen.pk", func() error {
		clientShare, perr := client.GenPKShare()
		if perr != nil {
			return fmt.Errorf("VClient.GenPKShare: %w", perr)
		}
		agentShare, perr := agent.GenPKShare(sid)
		if perr != nil {
			return fmt.Errorf("VAgent.GenPKShare: %w", perr)
		}
		if perr := client.AggregatePK(agentShare); perr != nil {
			return fmt.Errorf("VClient.AggregatePK: %w", perr)
		}
		if perr := agent.AggregatePK(sid, clientShare); perr != nil {
			return fmt.Errorf("VAgent.AggregatePK: %w", perr)
		}
		return nil
	})
	run.Append(pkSample)
	if err != nil {
		_ = run.WriteJSON(stepOutPath(*outPath, *workdir, "keygen"))
		return fmt.Errorf("keygen: pk: %w", err)
	}

	// keygen.rlk-r1.
	rlk1Sample, err := bench.Measure("keygen.rlk-r1", func() error {
		clientR1, perr := client.GenRLKShareRound1()
		if perr != nil {
			return fmt.Errorf("VClient.GenRLKShareRound1: %w", perr)
		}
		agentR1, perr := agent.GenRLKShareRound1(sid)
		if perr != nil {
			return fmt.Errorf("VAgent.GenRLKShareRound1: %w", perr)
		}
		if perr := client.AggregateRLKRound1(agentR1); perr != nil {
			return fmt.Errorf("VClient.AggregateRLKRound1: %w", perr)
		}
		if perr := agent.AggregateRLKRound1(sid, clientR1); perr != nil {
			return fmt.Errorf("VAgent.AggregateRLKRound1: %w", perr)
		}
		return nil
	})
	run.Append(rlk1Sample)
	if err != nil {
		_ = run.WriteJSON(stepOutPath(*outPath, *workdir, "keygen"))
		return fmt.Errorf("keygen: rlk-r1: %w", err)
	}

	// keygen.rlk-r2.
	rlk2Sample, err := bench.Measure("keygen.rlk-r2", func() error {
		clientR2, perr := client.GenRLKShareRound2()
		if perr != nil {
			return fmt.Errorf("VClient.GenRLKShareRound2: %w", perr)
		}
		if _, perr := agent.GenRLKShareRound2(sid); perr != nil {
			return fmt.Errorf("VAgent.GenRLKShareRound2: %w", perr)
		}
		if perr := agent.AggregateRLKRound2(sid, clientR2); perr != nil {
			return fmt.Errorf("VAgent.AggregateRLKRound2: %w", perr)
		}
		return nil
	})
	run.Append(rlk2Sample)
	if err != nil {
		_ = run.WriteJSON(stepOutPath(*outPath, *workdir, "keygen"))
		return fmt.Errorf("keygen: rlk-r2: %w", err)
	}

	// keygen.galois: VClient emits per-rotation shares, VAgent aggregates
	// them with its own shares to produce the rlk + gks pair the rest of
	// the pipeline needs.
	var (
		rlk *rlwe.RelinearizationKey
		gks []*rlwe.GaloisKey
	)
	galSample, err := bench.Measure("keygen.galois", func() error {
		clientGalShares, clientLabels, perr := client.GenGaloisShares()
		if perr != nil {
			return fmt.Errorf("VClient.GenGaloisShares: %w", perr)
		}
		if _, _, perr := agent.GenGaloisShares(sid); perr != nil {
			return fmt.Errorf("VAgent.GenGaloisShares: %w", perr)
		}
		aggRlk, aggGks, perr := agent.AggregateGaloisShares(sid, clientGalShares, clientLabels)
		if perr != nil {
			return fmt.Errorf("VAgent.AggregateGaloisShares: %w", perr)
		}
		if perr := svc.StoreEvalKeys(sid, aggRlk, aggGks); perr != nil {
			return fmt.Errorf("VService.StoreEvalKeys: %w", perr)
		}
		rlk = aggRlk
		gks = aggGks
		return nil
	})
	run.Append(galSample)
	if err != nil {
		_ = run.WriteJSON(stepOutPath(*outPath, *workdir, "keygen"))
		return fmt.Errorf("keygen: galois: %w", err)
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
