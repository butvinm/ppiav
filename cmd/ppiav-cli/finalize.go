package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math"

	"github.com/butvinm/ppiav/internal/bench"
	"github.com/butvinm/ppiav/internal/protocol"
	"github.com/butvinm/ppiav/internal/vagent"
)

// decodedOutput is the on-disk shape of <img_dir>/decoded.json, consumed by
// the Python aggregator to compute protocol FPR/FNR and the noise
// distribution. ref_logit is the cleartext PyTorch FHE-quad reference the
// eval driver passes via --ref-logit (per-image, from eval_inputs.json);
// noise_per_slot is computed at non-S slots only since those carry the
// broadcast logit m (the S slots carry the deterministic v[i]/Δ values).
//
// log2_scale and log2_flood_sigma let the Python aggregator reconstruct the
// canonical-embedding noise norm ||e||_canon = Δ · max|noise_per_slot| (in
// log2 terms) and compare against σ_flood to surface the Li–Micciancio
// statistical-security headroom in bits.
type decodedOutput struct {
	Verdict        string    `json:"verdict"`
	RefLogit       float64   `json:"ref_logit"`
	SlotsInS       []int     `json:"slots_in_s"`
	NoisePerSlot   []float64 `json:"noise_per_slot"`
	Log2Scale      float64   `json:"log2_scale"`
	Log2FloodSigma float64   `json:"log2_flood_sigma"`
}

// runFinalize rebuilds the VAgent from --workdir and combines the VClient's
// KeySwitchShare (--in-share) with the authenticated ciphertext (--in-ct)
// to run the final joint decryption and MPD-Auth check. The decoded
// verdict + per-slot noise vector are written to --out-decoded; the
// timing JSON splits the work into finalize.final_decrypt (the joint
// decrypt + auth check) and finalize.verdict_compute (slot bookkeeping +
// verdict packing).
func runFinalize(args []string) error {
	fs := flag.NewFlagSet("finalize", flag.ContinueOnError)
	workdir := fs.String("workdir", "", "per-batch keygen artifact directory (required)")
	inCt := fs.String("in-ct", "", "input authenticated ciphertext path (required)")
	inShare := fs.String("in-share", "", "input VClient KeySwitchShare path (required)")
	refLogit := fs.Float64("ref-logit", 0, "cleartext reference logit for noise computation")
	outDecoded := fs.String("out-decoded", "", "output decoded.json path (required)")
	outPath := fs.String("out", "", "timing JSON output path (default <workdir>/finalize.json)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *workdir == "" {
		return fmt.Errorf("finalize: --workdir is required")
	}
	if *inCt == "" {
		return fmt.Errorf("finalize: --in-ct is required")
	}
	if *inShare == "" {
		return fmt.Errorf("finalize: --in-share is required")
	}
	if *outDecoded == "" {
		return fmt.Errorf("finalize: --out-decoded is required")
	}

	params, err := loadParams(*workdir)
	if err != nil {
		return fmt.Errorf("finalize: load params: %w", err)
	}
	sid, err := readSID(*workdir)
	if err != nil {
		return fmt.Errorf("finalize: load sid: %w", err)
	}
	skTop, err := readSecretKey(*workdir, artifactSKAgent)
	if err != nil {
		return fmt.Errorf("finalize: load sk_a: %w", err)
	}
	macKey, err := readMacKey(*workdir)
	if err != nil {
		return fmt.Errorf("finalize: load mac key: %w", err)
	}
	ct, err := readCiphertextPath(*inCt)
	if err != nil {
		return fmt.Errorf("finalize: load in-ct: %w", err)
	}
	share, err := readKeySwitchShare(*inShare)
	if err != nil {
		return fmt.Errorf("finalize: load in-share: %w", err)
	}

	// FinalizeDecryption needs only sk_a + mac_key; PkAgg/Rlk/GksAuth are
	// unused on the decrypt path. Leave them nil to keep the loaded
	// surface minimal.
	agent, err := vagent.NewWithState(params, &vagent.ExportedState{
		SID:    sid,
		SkTop:  skTop,
		MacKey: macKey,
	})
	if err != nil {
		return fmt.Errorf("finalize: build VAgent: %w", err)
	}

	run := bench.NewRun("finalize", benchPhase)
	run.Metadata["workdir"] = *workdir
	run.Metadata["in_ct"] = *inCt
	run.Metadata["in_share"] = *inShare
	run.Metadata["out_decoded"] = *outDecoded
	run.Metadata["sid"] = string(sid)
	run.Metadata["ref_logit"] = *refLogit

	writeRunOnExit := func() { _ = run.WriteJSON(stepOutPath(*outPath, *workdir, "finalize")) }

	var (
		verdict protocol.Verdict
		slots   []float64
	)
	decryptSample, err := bench.Measure(sampleFinalizeFinalDecrypt, func() error {
		v, s, finErr := agent.FinalizeDecryptionVerbose(sid, ct, share)
		if finErr != nil {
			return fmt.Errorf("VAgent.FinalizeDecryptionVerbose: %w", finErr)
		}
		verdict = v
		slots = s
		return nil
	})
	run.Append(decryptSample)
	if err != nil {
		writeRunOnExit()
		return fmt.Errorf("finalize: %w", err)
	}

	var decoded decodedOutput
	verdictSample, err := bench.Measure(sampleFinalizeVerdictCompute, func() error {
		d, e := buildDecodedOutput(*refLogit, params.Authenticator.Lambda, macKey.S, slots, verdict, ct.Scale.Log2(), math.Log2(params.FloodSigma))
		if e != nil {
			return e
		}
		decoded = d
		return nil
	})
	run.Append(verdictSample)
	if err != nil {
		writeRunOnExit()
		return fmt.Errorf("finalize: %w", err)
	}

	if err := writeDecodedJSON(*outDecoded, decoded); err != nil {
		writeRunOnExit()
		return fmt.Errorf("finalize: write decoded.json: %w", err)
	}

	if err := run.WriteJSON(stepOutPath(*outPath, *workdir, "finalize")); err != nil {
		return fmt.Errorf("finalize: write run JSON: %w", err)
	}
	return nil
}

// buildDecodedOutput shapes the decoded.json payload. Non-S slots (i ∈
// [0, Lambda) \ S) carry the broadcast logit m; their noise relative to
// ref_logit is what the aggregator histograms. S slots carry the
// deterministic v[i]/Δ checksum and are reported separately as slots_in_s
// for debugging (no noise computation — the v[i] values are not centered
// around ref_logit, so subtracting would be meaningless).
//
// Returns an error if `slots` is shorter than `lambda` — defensive against
// future weakening of the FinalizeDecryptionVerbose contract. Today
// FinalizeDecryptionVerbose always returns a MaxSlots-sized vector on
// success and MaxSlots is much greater than Lambda, so this only ever fires
// on a contract regression.
func buildDecodedOutput(refLogit float64, lambda int, s []int, slots []float64, verdict protocol.Verdict, log2Scale, log2FloodSigma float64) (decodedOutput, error) {
	if len(slots) < lambda {
		return decodedOutput{}, fmt.Errorf("finalize: slots length %d < lambda %d (FinalizeDecryptionVerbose contract violated)", len(slots), lambda)
	}
	inS := make(map[int]bool, len(s))
	for _, i := range s {
		inS[i] = true
	}
	slotsInS := make([]int, 0, len(s))
	noisePerSlot := make([]float64, 0, lambda-len(s))
	for i := 0; i < lambda; i++ {
		if inS[i] {
			slotsInS = append(slotsInS, i)
			continue
		}
		noisePerSlot = append(noisePerSlot, slots[i]-refLogit)
	}
	return decodedOutput{
		Verdict:        verdict.String(),
		RefLogit:       refLogit,
		SlotsInS:       slotsInS,
		NoisePerSlot:   noisePerSlot,
		Log2Scale:      log2Scale,
		Log2FloodSigma: log2FloodSigma,
	}, nil
}

// writeDecodedJSON serialises the decoded payload to path atomically via
// writeBytesPath — the workdir/per-image directory is created if absent.
func writeDecodedJSON(path string, decoded decodedOutput) error {
	data, err := json.MarshalIndent(decoded, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal decoded.json: %w", err)
	}
	return writeBytesPath(path, data)
}

