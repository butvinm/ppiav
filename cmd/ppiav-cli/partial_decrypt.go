package main

import (
	"flag"
	"fmt"

	"github.com/butvinm/ppiav/internal/bench"
	"github.com/butvinm/ppiav/internal/vclient"
	"github.com/tuneinsight/lattigo/v6/multiparty"
)

// runPartialDecrypt loads the VClient state and emits the smudged
// KeySwitchShare (sk_c → 0) over a saved authenticated ciphertext. The
// output share is written to --out-share; a single-sample bench.Run named
// "partial-decrypt" is written to --out (default <workdir>/partial-decrypt.json).
//
// pk_agg is not required for partial decryption: NewWithState wires only the
// SkShare-driven path when PkAgg is nil. Loading pk_agg anyway would be a
// no-op on the hot path; skipping it keeps the I/O scope minimal.
func runPartialDecrypt(args []string) error {
	fs := flag.NewFlagSet("partial-decrypt", flag.ContinueOnError)
	workdir := fs.String("workdir", "", "per-batch keygen artifact directory (required)")
	inCt := fs.String("in-ct", "", "input authenticated ciphertext path (required)")
	outShare := fs.String("out-share", "", "output KeySwitchShare path (required)")
	outPath := fs.String("out", "", "timing JSON output path (default <workdir>/partial-decrypt.json)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *workdir == "" {
		return fmt.Errorf("partial-decrypt: --workdir is required")
	}
	if *inCt == "" {
		return fmt.Errorf("partial-decrypt: --in-ct is required")
	}
	if *outShare == "" {
		return fmt.Errorf("partial-decrypt: --out-share is required")
	}

	params, err := loadParams(*workdir)
	if err != nil {
		return fmt.Errorf("partial-decrypt: load params: %w", err)
	}
	sid, err := readSID(*workdir)
	if err != nil {
		return fmt.Errorf("partial-decrypt: load sid: %w", err)
	}
	skTop, err := readSecretKey(*workdir, artifactSKClient)
	if err != nil {
		return fmt.Errorf("partial-decrypt: load sk_c: %w", err)
	}
	ct, err := readCiphertextPath(*inCt)
	if err != nil {
		return fmt.Errorf("partial-decrypt: load in-ct: %w", err)
	}

	client, err := vclient.NewWithState(params, &vclient.ExportedState{
		SID:   sid,
		SkTop: skTop,
		// PkAgg intentionally omitted — partial decryption uses sk_c only.
	})
	if err != nil {
		return fmt.Errorf("partial-decrypt: build VClient: %w", err)
	}

	run := bench.NewRun("partial-decrypt", benchPhase)
	run.Metadata["workdir"] = *workdir
	run.Metadata["in_ct"] = *inCt
	run.Metadata["out_share"] = *outShare
	run.Metadata["sid"] = string(sid)

	var share multiparty.KeySwitchShare
	sample, err := bench.MeasureWithSize("partial-decrypt", func() (uint64, error) {
		s, pdErr := client.PartialDecrypt(ct)
		if pdErr != nil {
			return 0, fmt.Errorf("VClient.PartialDecrypt: %w", pdErr)
		}
		share = s
		return uint64(s.BinarySize()), nil
	})
	run.Append(sample)
	if err != nil {
		_ = run.WriteJSON(stepOutPath(*outPath, *workdir, "partial-decrypt"))
		return fmt.Errorf("partial-decrypt: %w", err)
	}

	if err := writeKeySwitchShare(*outShare, share); err != nil {
		_ = run.WriteJSON(stepOutPath(*outPath, *workdir, "partial-decrypt"))
		return fmt.Errorf("partial-decrypt: write share: %w", err)
	}

	if err := run.WriteJSON(stepOutPath(*outPath, *workdir, "partial-decrypt")); err != nil {
		return fmt.Errorf("partial-decrypt: write run JSON: %w", err)
	}
	return nil
}

