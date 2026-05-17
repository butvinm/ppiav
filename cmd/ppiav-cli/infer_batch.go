package main

import (
	"flag"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/butvinm/ppiav/internal/bench"
	"github.com/butvinm/ppiav/internal/vservice"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

// runInferBatch loads VService state + Orion model once, then runs N
// inferences over the supplied image dirs. Orion 2.1.5's eager-encoded
// LinearTransformations make LoadModel ~265s at LogN=16 but per-call
// inference is fast — amortizing the load across a batch saves
// (N-1)*load_seconds. The load_keys sample lands in the first image dir's
// infer.json only (aggregator bucket reports n=1 with the real cost).
func runInferBatch(args []string) error {
	fs := flag.NewFlagSet("infer-batch", flag.ContinueOnError)
	workdir := fs.String("workdir", "", "per-batch keygen artifact directory (required)")
	orionDir := fs.String("orion", "", "Orion compiled-model directory (required for Orion mode; empty => synthetic x²)")
	imageDirsCSV := fs.String("image-dirs", "", "comma-separated per-image dirs; each must contain in-ct-name and will receive out-ct-name + out-name (required)")
	inCtName := fs.String("in-ct-name", "input_ct.bin", "input ciphertext filename inside each image dir")
	outCtName := fs.String("out-ct-name", "result_ct.bin", "output ciphertext filename inside each image dir")
	outJSONName := fs.String("out-name", "infer.json", "per-image timing JSON filename")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *workdir == "" {
		return fmt.Errorf("infer-batch: --workdir is required")
	}
	if *imageDirsCSV == "" {
		return fmt.Errorf("infer-batch: --image-dirs is required")
	}
	imageDirs := strings.Split(*imageDirsCSV, ",")
	for i, d := range imageDirs {
		imageDirs[i] = strings.TrimSpace(d)
		if imageDirs[i] == "" {
			return fmt.Errorf("infer-batch: empty entry in --image-dirs at position %d", i)
		}
	}

	params, err := loadParams(*workdir)
	if err != nil {
		return fmt.Errorf("infer-batch: load params: %w", err)
	}
	sid, err := readSID(*workdir)
	if err != nil {
		return fmt.Errorf("infer-batch: load sid: %w", err)
	}

	var svc *vservice.Service
	loadKeysSample, err := bench.Measure(sampleInferLoadKeys, func() error {
		rlk, e := readRelinearizationKey(*workdir)
		if e != nil {
			return fmt.Errorf("load rlk: %w", e)
		}
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
	if err != nil {
		return fmt.Errorf("infer-batch: load_keys: %w", err)
	}

	for i, imgDir := range imageDirs {
		run := bench.NewRun("infer", benchPhase)
		run.Metadata["workdir"] = *workdir
		if *orionDir != "" {
			run.Metadata["orion_dir"] = *orionDir
		}
		run.Metadata["image_dir"] = imgDir
		run.Metadata["sid"] = string(sid)
		if i == 0 {
			run.Append(loadKeysSample)
		} else {
			run.Metadata["load_keys_amortized_to"] = imageDirs[0]
		}

		inCtPath := filepath.Join(imgDir, *inCtName)
		outCtPath := filepath.Join(imgDir, *outCtName)
		outJSONPath := filepath.Join(imgDir, *outJSONName)
		writeRunOnExit := func() { _ = run.WriteJSON(outJSONPath) }

		var ct *rlwe.Ciphertext
		loadInputSample, err := bench.Measure(sampleInferLoadInputCt, func() error {
			c, e := readCiphertextPath(inCtPath)
			if e != nil {
				return fmt.Errorf("load in-ct: %w", e)
			}
			ct = c
			return nil
		})
		run.Append(loadInputSample)
		if err != nil {
			writeRunOnExit()
			return fmt.Errorf("infer-batch: %s load_input_ct: %w", imgDir, err)
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
			return fmt.Errorf("infer-batch: %s exec: %w", imgDir, err)
		}

		serializeSample, err := bench.Measure(sampleInferSerializeResult, func() error {
			return writeCiphertextPath(outCtPath, outCipher)
		})
		run.Append(serializeSample)
		if err != nil {
			writeRunOnExit()
			return fmt.Errorf("infer-batch: %s serialize_result: %w", imgDir, err)
		}

		if err := run.WriteJSON(outJSONPath); err != nil {
			return fmt.Errorf("infer-batch: write run JSON %s: %w", outJSONPath, err)
		}
	}
	return nil
}
