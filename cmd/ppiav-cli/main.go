// Command ppiav-cli is the Phase-1 driver for the in-process protocol. It
// exposes the full §3 end-to-end flow (`e2e`) and per-step subcommands that
// isolate individual operations for benchmarking. Each invocation writes a
// `bench.Run` JSON to disk under `results/phase1/<step>.json` by default.
//
// Dispatch uses stdlib `flag` — no cobra — to keep dependencies tight.
// Subcommands:
//
//	e2e             — full §3 protocol per iteration (Open+Setup+Infer+Verify)
//	keygen          — Stage 2 only (fresh sid per iteration)
//	encrypt-image   — VClient.EncryptImage hot loop after one Open+Setup
//	infer           — VService.Infer hot loop on a fixed inputCt
//	mac             — VAgent.BuildAuthenticatedCt hot loop on a fixed resultCt
//	decrypt-result  — VClient.PartialDecrypt + key-switch + decode hot loop
//	verify-mac      — authenticator.Ver hot loop on a fixed plaintext
//
// See docs/DESIGN.md §`Protocol` for the stage definitions and
// docs/plans/20260514-phase-1-2-multiparty-ckks-and-c3ae.md §Task 9 for
// the bench-shape requirements.
package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/butvinm/ppiav/internal/vclient"
)

// usage prints the top-level help and exits with status 2 (flag convention).
func usage() {
	fmt.Fprintf(os.Stderr, `ppiav-cli — Phase-1 protocol driver.

Usage:
  ppiav-cli <subcommand> [flags]

Subcommands:
  e2e             run the full §3 protocol per iteration
  keygen          run Stage 2 (collaborative keygen) only, fresh sid per iter
  encrypt-image   benchmark VClient.EncryptImage on a fixed setup
  infer           benchmark VService.Infer on a fixed inputCt
  mac             benchmark VAgent.BuildAuthenticatedCt on a fixed resultCt
  decrypt-result  benchmark VClient.PartialDecrypt + final key-switch
  verify-mac      benchmark authenticator.Ver on a fixed plaintext

Common flags:
  --n int          measured iteration count (default 1)
  --out string     output JSON path (default results/phaseN/<step>.json)
  --image string   path to a 12288-float64 .bin file
                   (required for: e2e, encrypt-image)
  --orion string   directory containing a compiled Orion model.orion
                   (Phase 2; when set, output defaults shift to results/phase2/)

Examples:
  ppiav-cli e2e --orion ./models/out/logn15 --image ./models/out/inputs/sample_0.bin --n 5
`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	sub := os.Args[1]
	args := os.Args[2:]

	// --help / -h at the top level.
	if sub == "-h" || sub == "--help" || sub == "help" {
		usage()
		return
	}

	var err error
	switch sub {
	case "e2e":
		err = runE2E(args)
	case "keygen":
		err = runKeygen(args)
	case "encrypt-image":
		err = runEncryptImage(args)
	case "infer":
		err = runInfer(args)
	case "mac":
		err = runMAC(args)
	case "decrypt-result":
		err = runDecryptResult(args)
	case "verify-mac":
		err = runVerifyMAC(args)
	default:
		fmt.Fprintf(os.Stderr, "ppiav-cli: unknown subcommand %q\n\n", sub)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "ppiav-cli: %v\n", err)
		os.Exit(1)
	}
}

// defaultOutPath builds `results/phase1/<step>.json` when --out is empty.
func defaultOutPath(step string) string {
	return filepath.Join("results", "phase1", step+".json")
}

// defaultOutPathFor builds `results/phase{1,2}/<step>.json` depending on
// whether `--orion` was supplied. Centralising the phase tag keeps the
// per-step subcommands in lockstep with `e2e`.
func defaultOutPathFor(step, orionDir string) string {
	if orionDir != "" {
		return filepath.Join("results", "phase2", step+".json")
	}
	return filepath.Join("results", "phase1", step+".json")
}

// loadImage reads a 12288-little-endian-float64 .bin file and returns the
// slice. Hard-fails on size mismatch — no silent padding (mirrors
// internal/vclient.EncryptImage's contract).
func loadImage(path string) ([]float64, error) {
	if path == "" {
		return nil, fmt.Errorf("--image is required (path to a %d-float64 .bin file)", vclient.ImageLen)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open image %s: %w", path, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat image %s: %w", path, err)
	}
	const wantBytes = vclient.ImageLen * 8
	if info.Size() != wantBytes {
		return nil, fmt.Errorf("image %s: size %d bytes, expected %d (%d float64)", path, info.Size(), wantBytes, vclient.ImageLen)
	}

	out := make([]float64, vclient.ImageLen)
	if err := binary.Read(f, binary.LittleEndian, out); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return nil, fmt.Errorf("image %s: truncated read", path)
		}
		return nil, fmt.Errorf("decode image %s: %w", path, err)
	}
	return out, nil
}
