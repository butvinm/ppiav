package main

import (
	"flag"
	"fmt"

	"github.com/butvinm/ppiav/internal/bench"
	"github.com/butvinm/ppiav/internal/vclient"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

// runEncrypt loads the VClient state written by `keygen` and encrypts a
// preprocessed image under the aggregated session pk. The output ciphertext
// is written to --out-ct; a single-sample bench.Run named "encrypt" is
// written to --out (default <workdir>/encrypt.json).
//
// All of {sid, sk_c, pk_agg, params} are read from --workdir; the rebuilt
// Client is encrypt-ready (PartialDecrypt would also work, but the bench
// `partial-decrypt` subcommand owns that path).
func runEncrypt(args []string) error {
	fs := flag.NewFlagSet("encrypt", flag.ContinueOnError)
	workdir := fs.String("workdir", "", "per-batch keygen artifact directory (required)")
	imagePath := fs.String("image", "", "path to the 12288-float64 .bin image file (required)")
	outCt := fs.String("out-ct", "", "output ciphertext path (required)")
	outPath := fs.String("out", "", "timing JSON output path (default <workdir>/encrypt.json)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *workdir == "" {
		return fmt.Errorf("encrypt: --workdir is required")
	}
	if *outCt == "" {
		return fmt.Errorf("encrypt: --out-ct is required")
	}

	image, err := loadImage(*imagePath)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	params, err := loadParams(*workdir)
	if err != nil {
		return fmt.Errorf("encrypt: load params: %w", err)
	}
	sid, err := readSID(*workdir)
	if err != nil {
		return fmt.Errorf("encrypt: load sid: %w", err)
	}
	skTop, err := readSecretKey(*workdir, artifactSKClient)
	if err != nil {
		return fmt.Errorf("encrypt: load sk_c: %w", err)
	}
	pkEval, err := readPublicKey(*workdir, artifactPKEval)
	if err != nil {
		return fmt.Errorf("encrypt: load pk_eval: %w", err)
	}

	client, err := vclient.NewWithState(params, &vclient.ExportedState{
		SID:   sid,
		SkTop: skTop,
		PkAgg: pkEval,
	})
	if err != nil {
		return fmt.Errorf("encrypt: build VClient: %w", err)
	}

	run := bench.NewRun("encrypt", benchPhase)
	run.Metadata["workdir"] = *workdir
	run.Metadata["image"] = *imagePath
	run.Metadata["out_ct"] = *outCt
	run.Metadata["sid"] = string(sid)

	var ct *rlwe.Ciphertext
	sample, err := bench.Measure("encrypt", func() error {
		c, encErr := client.EncryptImage(image)
		if encErr != nil {
			return fmt.Errorf("VClient.EncryptImage: %w", encErr)
		}
		ct = c
		return nil
	})
	run.Append(sample)
	if err != nil {
		_ = run.WriteJSON(stepOutPath(*outPath, *workdir, "encrypt"))
		return fmt.Errorf("encrypt: %w", err)
	}

	if err := writeCiphertextPath(*outCt, ct); err != nil {
		_ = run.WriteJSON(stepOutPath(*outPath, *workdir, "encrypt"))
		return fmt.Errorf("encrypt: write ciphertext: %w", err)
	}

	if err := run.WriteJSON(stepOutPath(*outPath, *workdir, "encrypt")); err != nil {
		return fmt.Errorf("encrypt: write run JSON: %w", err)
	}
	return nil
}

