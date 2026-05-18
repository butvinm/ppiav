// Command ppiav-cli is the per-stage CLI for the ppiav verification protocol.
// Each subcommand performs exactly one cryptographic operation: it loads its
// inputs from disk (session keys, ciphertexts, shares), runs the operation,
// and writes its outputs back to disk as a wire artifact plus a timing JSON.
// Chaining the subcommands across a batch of images is delegated to the
// Python eval driver in bench/, which orchestrates a stratified UTKFace run
// with a single shared keygen and aggregates the JSONs into summary tables
// and plots.
//
// Splitting the protocol into independent processes (vs. a single in-process
// orchestrator) gives each stage a clean RSS baseline for memory profiling
// and lets the bench driver measure per-stage wall-time + peak resident set
// without cross-contamination.
//
// Dispatch uses stdlib `flag` — no cobra — to keep dependencies tight.
// Subcommands:
//
//	keygen           — multi-party collaborative keygen between VClient and
//	                   VAgent; writes the session keys, SID, and CKKS params
//	                   into <workdir>
//	encrypt          — VClient encrypts a preprocessed image under the
//	                   aggregated session pk; writes input_ct
//	infer            — VService runs the Orion-compiled FHE inference circuit
//	                   on input_ct; writes result_ct
//	infer-batch      — same as `infer` but over N image directories, sharing
//	                   one VService LoadModel (avoids re-encoding the model's
//	                   linear transforms per image)
//	mac              — VAgent derives the auth-atom keys and produces the
//	                   MPD-Auth authenticated ciphertext from result_ct;
//	                   writes auth_ct
//	partial-decrypt  — VClient emits its smudged KeySwitchShare over auth_ct;
//	                   writes client_share
//	finalize         — VAgent joins its own share with client_share, runs the
//	                   final decryption + auth check, and decodes the
//	                   broadcast logit into a verdict; writes decoded.json
//
// All subcommands share a `--workdir <dir>` flag pointing at the per-session
// directory containing the keygen artifacts. Each subcommand also takes an
// explicit `--out <path>` for its timing JSON (default
// `<workdir>/<subcommand>.json`).
package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/butvinm/ppiav/internal/vclient"
)

// benchPhase tags every bench.Run JSON emitted by the per-step subcommands.
// The bench loader/aggregator key off it for table grouping; the synthetic
// `x²` (--orion="") path uses the same tag (it just swaps the inference
// circuit).
//
// TODO: per memory `feedback_readme_user_facing.md` (2026-05-16 extension),
// "phase" should not appear in user-facing strings. The value here is
// pinned to keep wire compatibility with bench/bench/load.py's required
// `phase` field and existing on-disk results. Renaming it (e.g. to
// "ppiav") requires a coordinated change in the Python loader; deferred
// as ppiav-side ABI debt until that coordinated change lands.
const benchPhase = "phase2"

// usage prints the top-level help and exits with status 2 (flag convention).
func usage() {
	fmt.Fprintf(os.Stderr, `ppiav-cli — per-stage CLI for the ppiav verification protocol.

Each subcommand runs one cryptographic operation, reading its inputs from
<workdir> and writing its outputs (wire artifact + timing JSON) back to
disk. The Python eval driver in bench/ chains the subcommands across an
image batch with a single shared keygen.

Usage:
  ppiav-cli <subcommand> [flags]

Subcommands:
  keygen           multi-party keygen between VClient and VAgent;
                   writes session keys, SID, and CKKS params
  encrypt          VClient encrypts an image under the session pk;
                   writes input_ct
  infer            VService runs the FHE inference circuit on input_ct;
                   writes result_ct
  infer-batch      same as infer over N image dirs, sharing one LoadModel
  mac              VAgent emits the MPD-Auth authenticated ciphertext from
                   result_ct; writes auth_ct
  partial-decrypt  VClient returns its smudged KeySwitchShare for auth_ct;
                   writes client_share
  finalize         VAgent joins the shares, runs final decryption + auth
                   check, decodes the verdict; writes decoded.json

Shared flags:
  --workdir string  per-session directory holding keygen artifacts (required)
  --out string      timing JSON output path (default <workdir>/<subcommand>.json)

Per-subcommand flags: see "ppiav-cli <subcommand> -h".
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
	case "keygen":
		err = runKeygen(args)
	case "encrypt":
		err = runEncrypt(args)
	case "infer":
		err = runInfer(args)
	case "infer-batch":
		err = runInferBatch(args)
	case "mac":
		err = runMAC(args)
	case "partial-decrypt":
		err = runPartialDecrypt(args)
	case "finalize":
		err = runFinalize(args)
	default:
		fmt.Fprintf(os.Stderr, "ppiav-cli: unknown subcommand %q\n\n", sub)
		usage()
		os.Exit(2)
	}
	if err != nil {
		// `-h` / `--help` on a subcommand surfaces as flag.ErrHelp from
		// flag.NewFlagSet's Parse; treat it as success so `ppiav-cli foo -h`
		// exits 0 like every well-behaved CLI.
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintf(os.Stderr, "ppiav-cli: %v\n", err)
		os.Exit(1)
	}
}

// defaultOutPath builds `<workdir>/<step>.json` when --out is empty.
func defaultOutPath(workdir, step string) string {
	return filepath.Join(workdir, step+".json")
}

// stepOutPath returns the explicit --out path when non-empty, else the
// canonical `<workdir>/<step>.json` location used by the bench Python
// driver. Shared by every subcommand to keep the default-path convention
// in one place.
func stepOutPath(outPath, workdir, step string) string {
	if outPath != "" {
		return outPath
	}
	return defaultOutPath(workdir, step)
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

