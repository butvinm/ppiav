package main

import (
	"flag"
	"fmt"

	"github.com/butvinm/ppiav/internal/bench"
	"github.com/butvinm/ppiav/internal/vservice"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

// runInfer loads the VService state written by `keygen` and runs the
// session's inference circuit on a saved input ciphertext. The output
// ciphertext is written to --out-ct; a single-sample bench.Run named "infer"
// is written to --out (default <workdir>/infer.json).
//
// --orion <dir> must point at the Orion compiled-model directory used by
// keygen; vservice.NewWithState reloads model.orion from disk and overrides
// the CKKS / InputLevel / ExtraRotationIndices fields from the manifest. The
// params persisted to params.json are also Orion-derived (keygen runs
// vservice.NewWithOrion), so the loadParams + NewWithState merge is
// idempotent in the Orion path.
func runInfer(args []string) error {
	fs := flag.NewFlagSet("infer", flag.ContinueOnError)
	workdir := fs.String("workdir", "", "per-batch keygen artifact directory (required)")
	orionDir := fs.String("orion", "", "Orion compiled-model directory (required for Orion mode; empty => synthetic x²)")
	inCt := fs.String("in-ct", "", "input ciphertext path (required)")
	outCt := fs.String("out-ct", "", "output ciphertext path (required)")
	outPath := fs.String("out", "", "timing JSON output path (default <workdir>/infer.json)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *workdir == "" {
		return fmt.Errorf("infer: --workdir is required")
	}
	if *inCt == "" {
		return fmt.Errorf("infer: --in-ct is required")
	}
	if *outCt == "" {
		return fmt.Errorf("infer: --out-ct is required")
	}

	params, err := loadParams(*workdir)
	if err != nil {
		return fmt.Errorf("infer: load params: %w", err)
	}
	sid, err := readSID(*workdir)
	if err != nil {
		return fmt.Errorf("infer: load sid: %w", err)
	}
	rlk, err := readRelinearizationKey(*workdir)
	if err != nil {
		return fmt.Errorf("infer: load rlk: %w", err)
	}
	// VService consumes the full GLK set. After lattigo-hierkeys integration
	// glk_master will swap in, but until then glk_full.bin is the canonical
	// evaluator key set.
	gks, err := readGaloisKeys(*workdir, artifactGLKFull)
	if err != nil {
		return fmt.Errorf("infer: load glk_full: %w", err)
	}
	ct, err := readCiphertextPath(*inCt)
	if err != nil {
		return fmt.Errorf("infer: load in-ct: %w", err)
	}

	svc, err := vservice.NewWithState(params, *orionDir, &vservice.ExportedState{
		SID: sid,
		Rlk: rlk,
		Glk: gks,
	})
	if err != nil {
		return fmt.Errorf("infer: build VService: %w", err)
	}

	run := bench.NewRun("infer", benchPhase)
	run.Metadata["workdir"] = *workdir
	if *orionDir != "" {
		run.Metadata["orion_dir"] = *orionDir
	}
	run.Metadata["in_ct"] = *inCt
	run.Metadata["out_ct"] = *outCt
	run.Metadata["sid"] = string(sid)

	var outCipher *rlwe.Ciphertext
	sample, err := bench.Measure("infer", func() error {
		c, infErr := svc.Infer(sid, ct)
		if infErr != nil {
			return fmt.Errorf("VService.Infer: %w", infErr)
		}
		outCipher = c
		return nil
	})
	run.Append(sample)
	if err != nil {
		_ = run.WriteJSON(stepOutPath(*outPath, *workdir, "infer"))
		return fmt.Errorf("infer: %w", err)
	}

	if err := writeCiphertextPath(*outCt, outCipher); err != nil {
		_ = run.WriteJSON(stepOutPath(*outPath, *workdir, "infer"))
		return fmt.Errorf("infer: write ciphertext: %w", err)
	}

	if err := run.WriteJSON(stepOutPath(*outPath, *workdir, "infer")); err != nil {
		return fmt.Errorf("infer: write run JSON: %w", err)
	}
	return nil
}

