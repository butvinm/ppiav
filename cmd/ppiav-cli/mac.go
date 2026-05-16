package main

import (
	"flag"
	"fmt"

	"github.com/butvinm/ppiav/internal/bench"
	"github.com/butvinm/ppiav/internal/vagent"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

// runMAC loads the VAgent state written by `keygen` and runs Stage 4a —
// `BuildAuthenticatedCt` — on a saved result ciphertext. The output
// authenticated ciphertext is written to --out-ct; a single-sample
// bench.Run named "mac" is written to --out (default <workdir>/mac.json).
//
// The VAgent state surface for Auth is wide: sk_a drives the per-session
// secret, mac_key carries (S, SeedF), and the encryptor + evaluator need
// pk_agg + rlk + glk_full respectively. All of these are persisted by
// keygen and reloaded here via NewWithState.
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
	skShare, err := readSecretKey(*workdir, artifactSKAgent)
	if err != nil {
		return fmt.Errorf("mac: load sk_a: %w", err)
	}
	macKey, err := readMacKey(*workdir)
	if err != nil {
		return fmt.Errorf("mac: load mac key: %w", err)
	}
	pkAgg, err := readPublicKey(*workdir)
	if err != nil {
		return fmt.Errorf("mac: load pk_agg: %w", err)
	}
	rlk, err := readRelinearizationKey(*workdir)
	if err != nil {
		return fmt.Errorf("mac: load rlk: %w", err)
	}
	gks, err := readGaloisKeys(*workdir, artifactGLKFull)
	if err != nil {
		return fmt.Errorf("mac: load glk_full: %w", err)
	}
	ct, err := readCiphertextPath(*inCt)
	if err != nil {
		return fmt.Errorf("mac: load in-ct: %w", err)
	}

	agent, err := vagent.NewWithState(params, &vagent.ExportedState{
		SID:     sid,
		SkShare: skShare,
		MacKey:  macKey,
		PkAgg:   pkAgg,
		Rlk:     rlk,
		Gks:     gks,
	})
	if err != nil {
		return fmt.Errorf("mac: build VAgent: %w", err)
	}

	run := bench.NewRun("mac", benchPhase)
	run.Metadata["workdir"] = *workdir
	run.Metadata["in_ct"] = *inCt
	run.Metadata["out_ct"] = *outCt
	run.Metadata["sid"] = string(sid)

	var authCt *rlwe.Ciphertext
	sample, err := bench.Measure("mac", func() error {
		c, macErr := agent.BuildAuthenticatedCt(sid, ct)
		if macErr != nil {
			return fmt.Errorf("VAgent.BuildAuthenticatedCt: %w", macErr)
		}
		authCt = c
		return nil
	})
	run.Append(sample)
	if err != nil {
		_ = run.WriteJSON(stepOutPath(*outPath, *workdir, "mac"))
		return fmt.Errorf("mac: %w", err)
	}

	if err := writeCiphertextPath(*outCt, authCt); err != nil {
		_ = run.WriteJSON(stepOutPath(*outPath, *workdir, "mac"))
		return fmt.Errorf("mac: write ciphertext: %w", err)
	}

	if err := run.WriteJSON(stepOutPath(*outPath, *workdir, "mac")); err != nil {
		return fmt.Errorf("mac: write run JSON: %w", err)
	}
	return nil
}

