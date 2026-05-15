package main

import (
	"flag"
	"fmt"

	"github.com/butvinm/ppiav/internal/bench"
	"github.com/butvinm/ppiav/internal/orchestrator"
	"github.com/butvinm/ppiav/internal/protocol"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

// runE2E executes the full §3 protocol `--n` times against a fresh sid per
// iteration. Each iteration wraps the four protocol stages (Open, Setup,
// Infer, Verify) in `bench.Measure` and appends labelled samples to a single
// `bench.Run`. The Run's metadata records the total iteration count and the
// final verdict counts so the Python bench/ tooling has an at-a-glance
// summary.
//
// Rationale for one Run per invocation (not one per stage): the Python
// post-processing reads `*.json` from a directory and groups samples by
// `Name`. A single multi-stage Run lets us emit a single file per `e2e` run
// while still letting the table/plot scripts slice by stage.
func runE2E(argv []string) error {
	fs := flag.NewFlagSet("e2e", flag.ContinueOnError)
	n := fs.Int("n", 1, "measured iteration count")
	out := fs.String("out", "", "output JSON path (default results/phaseN/e2e.json)")
	imagePath := fs.String("image", "", "path to a 12288-float64 .bin image (required)")
	orionDir := fs.String("orion", "", "directory holding a compiled Orion model.orion (Phase 2)")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *n <= 0 {
		return fmt.Errorf("e2e: --n must be > 0, got %d", *n)
	}
	if *out == "" {
		*out = defaultOutPathFor("e2e", *orionDir)
	}

	image, err := loadImage(*imagePath)
	if err != nil {
		return fmt.Errorf("e2e: %w", err)
	}

	params, err := protocol.Defaults()
	if err != nil {
		return fmt.Errorf("e2e: build params: %w", err)
	}

	phaseTag := "phase1"
	if *orionDir != "" {
		phaseTag = "phase2"
	}
	run := bench.NewRun("e2e", phaseTag)
	run.Metadata["n"] = *n
	run.Metadata["image"] = *imagePath
	if *orionDir != "" {
		run.Metadata["orion"] = *orionDir
	}
	var accepts, rejects, unknowns int

	for iter := 0; iter < *n; iter++ {
		var r *orchestrator.Runner
		var err error
		if *orionDir != "" {
			r, err = orchestrator.NewRunnerWithOrion(params, *orionDir)
		} else {
			r, err = orchestrator.NewRunner(params)
		}
		if err != nil {
			return fmt.Errorf("e2e iter %d: new runner: %w", iter, err)
		}

		var resultCt *rlwe.Ciphertext
		var verdict protocol.Verdict

		openSample, err := bench.Measure("open", func() error {
			_, e := r.Open()
			return e
		})
		openSample.Iter = iter
		run.Append(openSample)
		if err != nil {
			return fmt.Errorf("e2e iter %d: Open: %w", iter, err)
		}

		setupSample, err := bench.Measure("setup", func() error {
			return r.Setup()
		})
		setupSample.Iter = iter
		run.Append(setupSample)
		if err != nil {
			return fmt.Errorf("e2e iter %d: Setup: %w", iter, err)
		}

		inferSample, err := bench.Measure("infer", func() error {
			ct, e := r.Infer(image)
			if e != nil {
				return e
			}
			resultCt = ct
			return nil
		})
		inferSample.Iter = iter
		run.Append(inferSample)
		if err != nil {
			return fmt.Errorf("e2e iter %d: Infer: %w", iter, err)
		}

		verifySample, err := bench.Measure("verify", func() error {
			v, e := r.Verify(resultCt)
			if e != nil {
				return e
			}
			verdict = v
			return nil
		})
		verifySample.Iter = iter
		run.Append(verifySample)
		if err != nil {
			return fmt.Errorf("e2e iter %d: Verify: %w", iter, err)
		}

		switch verdict {
		case protocol.VerdictAccept:
			accepts++
		case protocol.VerdictReject:
			rejects++
		default:
			unknowns++
		}
		fmt.Printf("e2e iter %d/%d sid=%s verdict=%s\n", iter+1, *n, r.SessionID(), verdict)
	}

	run.Metadata["accepts"] = accepts
	run.Metadata["rejects"] = rejects
	run.Metadata["unknowns"] = unknowns

	if err := run.WriteJSON(*out); err != nil {
		return fmt.Errorf("e2e: write %s: %w", *out, err)
	}
	fmt.Printf("e2e: wrote %s (n=%d, accept=%d reject=%d unknown=%d)\n", *out, *n, accepts, rejects, unknowns)
	return nil
}
