package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/butvinm/ppiav/internal/bench"
	"github.com/butvinm/ppiav/internal/vservice"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

// runInfer rebuilds the VService from the keygen artifacts in --workdir and
// runs the session's FHE inference circuit on the input ciphertext at
// --in-ct, writing the result ciphertext to --out-ct. --orion <dir> must
// point at the Orion compiled-model directory used by keygen.
//
// The work is split into four timed sub-steps so the bench can attribute
// the dominant costs separately: infer.load_keys (rlk + gks_infer +
// LoadModel LT-encoding), infer.load_input_ct, infer.exec (the circuit
// itself), and infer.serialize_result (whose Bytes carries the result
// ciphertext's BinarySize).
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

	run := bench.NewRun("infer", benchPhase)
	run.Metadata["workdir"] = *workdir
	if *orionDir != "" {
		run.Metadata["orion_dir"] = *orionDir
	}
	run.Metadata["in_ct"] = *inCt
	run.Metadata["out_ct"] = *outCt
	run.Metadata["sid"] = string(sid)
	writeRunOnExit := func() { _ = run.WriteJSON(stepOutPath(*outPath, *workdir, "infer")) }

	var svc *vservice.Service
	loadKeysSample, err := bench.Measure(sampleInferLoadKeys, func() error {
		rlk, e := readRelinearizationKey(*workdir)
		if e != nil {
			return fmt.Errorf("load rlk: %w", e)
		}
		// VService consumes the pre-derived expand-fully Galois key set.
		// Per-sample re-derivation is multi-minute at LogN=16, so keygen
		// caches it in gks_infer.bin and infer loads it directly.
		gks, e := readGaloisKeys(*workdir, artifactGKSInfer)
		if e != nil {
			return fmt.Errorf("load gks_infer: %w", e)
		}
		s, e := vservice.NewWithState(params, *orionDir, &vservice.ExportedState{
			SID:      sid,
			Rlk:      rlk,
			GksInfer: gks,
		})
		if e != nil {
			return fmt.Errorf("build VService: %w", e)
		}
		svc = s
		return nil
	})
	run.Append(loadKeysSample)
	if err != nil {
		writeRunOnExit()
		return fmt.Errorf("infer: load_keys: %w", err)
	}

	var ct *rlwe.Ciphertext
	loadInputSample, err := bench.Measure(sampleInferLoadInputCt, func() error {
		c, e := readCiphertextPath(*inCt)
		if e != nil {
			return fmt.Errorf("load in-ct: %w", e)
		}
		ct = c
		return nil
	})
	run.Append(loadInputSample)
	if err != nil {
		writeRunOnExit()
		return fmt.Errorf("infer: load_input_ct: %w", err)
	}

	var outCipher *rlwe.Ciphertext
	execSample, err := bench.Measure(sampleInferExec, func() error {
		c, infErr := svc.Infer(sid, ct)
		if infErr != nil {
			return fmt.Errorf("VService.Infer: %w", infErr)
		}
		outCipher = c
		return nil
	})
	run.Append(execSample)
	if err != nil {
		writeRunOnExit()
		return fmt.Errorf("infer: %w", err)
	}

	if dErr := dumpHeapIfRequested("infer"); dErr != nil {
		fmt.Fprintf(os.Stderr, "infer: memprofile: %v\n", dErr)
	}

	serializeSample, err := bench.MeasureWithSize(sampleInferSerializeResult, func() (uint64, error) {
		if e := writeCiphertextPath(*outCt, outCipher); e != nil {
			return 0, e
		}
		return uint64(outCipher.BinarySize()), nil
	})
	run.Append(serializeSample)
	if err != nil {
		writeRunOnExit()
		return fmt.Errorf("infer: write ciphertext: %w", err)
	}

	if err := run.WriteJSON(stepOutPath(*outPath, *workdir, "infer")); err != nil {
		return fmt.Errorf("infer: write run JSON: %w", err)
	}
	return nil
}

