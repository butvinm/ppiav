package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/butvinm/ppiav/internal/bench"
	"github.com/butvinm/ppiav/internal/vagent"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

// runMAC loads the VAgent state written by `keygen`, derives the auth-atom
// keys locally, and runs `BuildAuthenticatedCt` on a saved result ciphertext.
func runMAC(args []string) error {
	fs := flag.NewFlagSet("mac", flag.ContinueOnError)
	workdir := fs.String("workdir", "", "per-batch keygen artifact directory (required)")
	inCt := fs.String("in-ct", "", "input result ciphertext path (required)")
	outCt := fs.String("out-ct", "", "output authenticated ciphertext path (required)")
	outPath := fs.String("out", "", "timing JSON output path (default <workdir>/mac.json)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *workdir == "" {
		return fmt.Errorf("mac: --workdir is required")
	}
	if *inCt == "" {
		return fmt.Errorf("mac: --in-ct is required")
	}
	if *outCt == "" {
		return fmt.Errorf("mac: --out-ct is required")
	}

	params, err := loadParams(*workdir)
	if err != nil {
		return fmt.Errorf("mac: load params: %w", err)
	}
	sid, err := readSID(*workdir)
	if err != nil {
		return fmt.Errorf("mac: load sid: %w", err)
	}
	skTop, err := readSecretKey(*workdir, artifactSKAgent)
	if err != nil {
		return fmt.Errorf("mac: load sk_a: %w", err)
	}
	macKey, err := readMacKey(*workdir)
	if err != nil {
		return fmt.Errorf("mac: load mac key: %w", err)
	}
	pkEval, err := readPublicKey(*workdir, artifactPKEval)
	if err != nil {
		return fmt.Errorf("mac: load pk_eval: %w", err)
	}
	pkTop, err := readPublicKey(*workdir, artifactPKTop)
	if err != nil {
		return fmt.Errorf("mac: load pk_top: %w", err)
	}
	rlk, err := readRelinearizationKey(*workdir)
	if err != nil {
		return fmt.Errorf("mac: load rlk: %w", err)
	}
	ct, err := readCiphertextPath(*inCt)
	if err != nil {
		return fmt.Errorf("mac: load in-ct: %w", err)
	}

	run := bench.NewRun("mac", benchPhase)
	run.Metadata["workdir"] = *workdir
	run.Metadata["in_ct"] = *inCt
	run.Metadata["out_ct"] = *outCt
	run.Metadata["sid"] = string(sid)
	writeRunOnExit := func() { _ = run.WriteJSON(stepOutPath(*outPath, *workdir, "mac")) }

	// mac.derive_auth_keys captures both the gks_master read I/O (the
	// dominant input by far at LogN=16) and NewWithState's hierkeys
	// LevelExpansion + FinalizeKey pass over the negative auth atoms.
	// Bytes carries the derived gks_auth bundle size — summed
	// BinarySize() across each *rlwe.GaloisKey in the slice.
	var (
		agent             *vagent.Agent
		readGksMasterSecs float64
	)
	deriveSample, err := bench.MeasureWithSize(sampleMacDeriveAuthKeys, func() (uint64, error) {
		readGksStart := time.Now()
		gksMaster, e := readMasterKeys(*workdir, artifactGKSMaster)
		if e != nil {
			return 0, fmt.Errorf("load gks_master: %w", e)
		}
		readGksMasterSecs = time.Since(readGksStart).Seconds()
		a, e := vagent.NewWithState(params, &vagent.ExportedState{
			SID:       sid,
			SkTop:     skTop,
			MacKey:    macKey,
			PkAgg:     pkEval,
			PkTop:     pkTop,
			Rlk:       rlk,
			GksMaster: gksMaster,
		})
		if e != nil {
			return 0, fmt.Errorf("build VAgent: %w", e)
		}
		agent = a
		gksAuth, ok := agent.GksAuth(sid)
		if !ok {
			return 0, fmt.Errorf("VAgent.GksAuth: no derived auth-atom keys for sid %q", sid)
		}
		var total uint64
		for _, gk := range gksAuth {
			if gk == nil {
				continue
			}
			total += uint64(gk.BinarySize())
		}
		return total, nil
	})
	run.Append(deriveSample)
	run.Metadata["read_gks_master_seconds"] = readGksMasterSecs
	if err != nil {
		writeRunOnExit()
		return fmt.Errorf("mac: derive_auth_keys: %w", err)
	}
	if d, ok := agent.DeriveGksAuthSeconds(sid); ok {
		run.Metadata["derive_gks_auth_seconds"] = d
	}

	var authCt *rlwe.Ciphertext
	computeSample, err := bench.MeasureWithSize(sampleMacComputeCt, func() (uint64, error) {
		c, macErr := agent.BuildAuthenticatedCt(sid, ct)
		if macErr != nil {
			return 0, fmt.Errorf("VAgent.BuildAuthenticatedCt: %w", macErr)
		}
		authCt = c
		return uint64(c.BinarySize()), nil
	})
	run.Append(computeSample)
	if err != nil {
		writeRunOnExit()
		return fmt.Errorf("mac: %w", err)
	}

	if dErr := dumpHeapIfRequested("mac"); dErr != nil {
		fmt.Fprintf(os.Stderr, "mac: memprofile: %v\n", dErr)
	}

	if err := writeCiphertextPath(*outCt, authCt); err != nil {
		writeRunOnExit()
		return fmt.Errorf("mac: write ciphertext: %w", err)
	}

	if err := run.WriteJSON(stepOutPath(*outPath, *workdir, "mac")); err != nil {
		return fmt.Errorf("mac: write run JSON: %w", err)
	}
	return nil
}
