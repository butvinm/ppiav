package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/butvinm/ppiav/internal/bench"
	"github.com/butvinm/ppiav/internal/vagent"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

// runMAC loads the VAgent state written by `keygen` and runs Stage 4a —
// `BuildAuthenticatedCt` — on a saved result ciphertext. The output
// authenticated ciphertext is written to --out-ct; a single-sample
// bench.Run named "mac" is written to --out (default <workdir>/mac.json).
//
// Reads from disk: pk_eval.bin (drives the authenticator-side encryptor),
// rlk.bin + gks_auth.bin (drive authchain.Evaluator), sk_a + mac_key
// (per-session secrets). gks_auth.bin is the largest input by far
// (~1.57 GB at LogN=16); the read time is recorded as
// `read_gks_auth_seconds` in mac.json metadata for the bench harness.
//
// `authchain_construct_seconds` captures the in-memory authchain build
// time (sub-millisecond — no derivation, just `rlwe.NewMemEvaluationKeySet`
// over the loaded keys); the field exists for parity with the original
// hier-eval-construct field in the plan draft.
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
	rlk, err := readRelinearizationKey(*workdir)
	if err != nil {
		return fmt.Errorf("mac: load rlk: %w", err)
	}
	// gks_auth.bin is the dominant I/O — record the wall-clock load time.
	readGksStart := time.Now()
	gksAuth, err := readGaloisKeys(*workdir, artifactGKSAuth)
	if err != nil {
		return fmt.Errorf("mac: load gks_auth: %w", err)
	}
	readGksAuthSecs := time.Since(readGksStart).Seconds()
	ct, err := readCiphertextPath(*inCt)
	if err != nil {
		return fmt.Errorf("mac: load in-ct: %w", err)
	}

	run := bench.NewRun("mac", benchPhase)
	run.Metadata["workdir"] = *workdir
	run.Metadata["in_ct"] = *inCt
	run.Metadata["out_ct"] = *outCt
	run.Metadata["sid"] = string(sid)
	run.Metadata["read_gks_auth_seconds"] = readGksAuthSecs

	// authchain construction happens inside NewWithState — time it as a
	// dedicated sample so the bench can report the hier-eval-construct
	// surrogate. Expected to be sub-millisecond at any LogN.
	constructStart := time.Now()
	agent, err := vagent.NewWithState(params, &vagent.ExportedState{
		SID:     sid,
		SkTop:   skTop,
		MacKey:  macKey,
		PkAgg:   pkEval,
		Rlk:     rlk,
		GksAuth: gksAuth,
	})
	if err != nil {
		return fmt.Errorf("mac: build VAgent: %w", err)
	}
	run.Metadata["authchain_construct_seconds"] = time.Since(constructStart).Seconds()

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
