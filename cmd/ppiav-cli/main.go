// Command ppiav-cli is the per-step driver for the §3 protocol. Each
// subcommand runs a single cryptographic operation, loading its inputs from
// disk and writing its outputs (artifact + timing JSON) back to disk. The
// Python eval driver in bench/ chains these subprocesses across a batch of
// images to produce the aggregated benchmark and accuracy numbers.
//
// Dispatch uses stdlib `flag` — no cobra — to keep dependencies tight.
// Subcommands:
//
//	keygen           — bilateral collaborative keygen; writes keys + sid + params
//	encrypt          — VClient.EncryptImage; reads --image, writes input_ct
//	infer            — VService.Infer; reads input_ct, writes result_ct
//	mac              — VAgent.BuildAuthenticatedCt; reads result_ct, writes auth_ct
//	partial-decrypt  — VClient.PartialDecrypt; reads auth_ct, writes client_share
//	finalize         — VAgent.FinalizeDecryptionVerbose; reads auth_ct + share, writes decoded.json
//
// All subcommands share a `--workdir <dir>` flag pointing at the per-batch
// directory containing the keygen artifacts. Each subcommand also takes an
// explicit `--out <path>` for its timing JSON (default `<workdir>/<step>.json`).
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
	fmt.Fprintf(os.Stderr, `ppiav-cli — per-step §3 protocol driver.

Usage:
  ppiav-cli <subcommand> [flags]

Subcommands:
  keygen           bilateral collaborative keygen; writes keys + sid + params
  encrypt          VClient.EncryptImage on a fresh image
  infer            VService.Infer on a saved input ciphertext
  mac              VAgent.BuildAuthenticatedCt on a saved result ciphertext
  partial-decrypt  VClient.PartialDecrypt on a saved auth ciphertext
  finalize         VAgent.FinalizeDecryptionVerbose on a saved auth ct + share

Shared flags:
  --workdir string  per-batch directory holding keygen artifacts (required)
  --out string      timing JSON output path (default <workdir>/<step>.json)

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
		fmt.Fprintf(os.Stderr, "ppiav-cli: %v\n", err)
		os.Exit(1)
	}
}

// defaultOutPath builds `<workdir>/<step>.json` when --out is empty.
func defaultOutPath(workdir, step string) string {
	return filepath.Join(workdir, step+".json")
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

// Stub handlers for subcommands not yet implemented. Each returns
// "unimplemented" so `go build ./...` succeeds with the dispatch in place.

func runInfer(args []string) error    { return fmt.Errorf("infer: unimplemented") }
func runMAC(args []string) error      { return fmt.Errorf("mac: unimplemented") }
func runFinalize(args []string) error { return fmt.Errorf("finalize: unimplemented") }
