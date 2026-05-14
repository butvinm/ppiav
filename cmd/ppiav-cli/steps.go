package main

import (
	"crypto/rand"
	"flag"
	"fmt"

	"github.com/butvinm/ppiav/internal/authenticator"
	"github.com/butvinm/ppiav/internal/bench"
	"github.com/butvinm/ppiav/internal/orchestrator"
	"github.com/butvinm/ppiav/internal/protocol"
	"github.com/butvinm/ppiav/internal/rservice"
	"github.com/butvinm/ppiav/internal/vagent"
	"github.com/butvinm/ppiav/internal/vclient"
	"github.com/butvinm/ppiav/internal/vservice"
)

// stepCommonFlags is the flag set shared by all per-step subcommands.
type stepCommonFlags struct {
	n   *int
	out *string
}

func registerCommonFlags(fs *flag.FlagSet, defaultOut string) stepCommonFlags {
	return stepCommonFlags{
		n:   fs.Int("n", 1, "measured iteration count"),
		out: fs.String("out", "", "output JSON path (default "+defaultOut+")"),
	}
}

// resolveOut returns the explicit --out value if set, or defaultOut otherwise.
func (f stepCommonFlags) resolveOut(defaultOut string) string {
	if *f.out != "" {
		return *f.out
	}
	return defaultOut
}

// runKeygen drives only Stage 2 (collaborative keygen) with a FRESH sid per
// iteration. Each iteration runs Open + Setup against new VClient/VAgent
// state, so the bench captures the full collaborative-keygen cost.
func runKeygen(argv []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	common := registerCommonFlags(fs, defaultOutPath("keygen"))
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *common.n <= 0 {
		return fmt.Errorf("keygen: --n must be > 0")
	}
	out := common.resolveOut(defaultOutPath("keygen"))

	params, err := protocol.Defaults()
	if err != nil {
		return fmt.Errorf("keygen: build params: %w", err)
	}

	run := bench.NewRun("keygen", "phase1")
	run.Metadata["n"] = *common.n

	for iter := 0; iter < *common.n; iter++ {
		r, err := orchestrator.NewRunner(params)
		if err != nil {
			return fmt.Errorf("keygen iter %d: new runner: %w", iter, err)
		}

		openSample, err := bench.Measure("open", func() error {
			_, e := r.Open()
			return e
		})
		openSample.Iter = iter
		run.Append(openSample)
		if err != nil {
			return fmt.Errorf("keygen iter %d: Open: %w", iter, err)
		}

		setupSample, err := bench.Measure("setup", func() error {
			return r.Setup()
		})
		setupSample.Iter = iter
		run.Append(setupSample)
		if err != nil {
			return fmt.Errorf("keygen iter %d: Setup: %w", iter, err)
		}
		fmt.Printf("keygen iter %d/%d sid=%s\n", iter+1, *common.n, r.SessionID())
	}

	if err := run.WriteJSON(out); err != nil {
		return fmt.Errorf("keygen: write %s: %w", out, err)
	}
	fmt.Printf("keygen: wrote %s (n=%d)\n", out, *common.n)
	return nil
}

// stepSession bundles the four collaborators after a one-time Open+Setup.
// Per-step subcommands then bypass the Runner and call the underlying
// packages directly in their hot loop — the bench measures one isolated
// operation per iteration, not a full Runner stage.
type stepSession struct {
	params  protocol.Params
	sid     protocol.SessionID
	vclient *vclient.Client
	vagent  *vagent.Agent
	vsvc    *vservice.Service
	rsvc    *rservice.Service
}

// buildStepSession does the Stage-1+2 setup once: opens a sid, drives the
// PK / RLK / Galois handshake symmetrically across VClient and VAgent, and
// hands the aggregated rlk+gks to VService. The returned stepSession is
// ready for image encryption, inference, Auth, and joint decryption.
func buildStepSession(params protocol.Params) (*stepSession, error) {
	vsvc := vservice.New(params)
	agent, err := vagent.New(params)
	if err != nil {
		return nil, fmt.Errorf("build VAgent: %w", err)
	}
	rsvc := rservice.New()

	sid, err := vsvc.OpenSession()
	if err != nil {
		return nil, fmt.Errorf("OpenSession: %w", err)
	}
	if err := agent.OpenSession(sid); err != nil {
		return nil, fmt.Errorf("VAgent.OpenSession: %w", err)
	}
	client, err := vclient.New(params, sid)
	if err != nil {
		return nil, fmt.Errorf("VClient.New: %w", err)
	}

	// PK handshake.
	cpkShare, err := client.GenPKShare()
	if err != nil {
		return nil, fmt.Errorf("VClient.GenPKShare: %w", err)
	}
	apkShare, err := agent.GenPKShare(sid)
	if err != nil {
		return nil, fmt.Errorf("VAgent.GenPKShare: %w", err)
	}
	if err := client.AggregatePK(apkShare); err != nil {
		return nil, fmt.Errorf("VClient.AggregatePK: %w", err)
	}
	if err := agent.AggregatePK(sid, cpkShare); err != nil {
		return nil, fmt.Errorf("VAgent.AggregatePK: %w", err)
	}

	// RLK round 1.
	crlk1, err := client.GenRLKShareRound1()
	if err != nil {
		return nil, fmt.Errorf("VClient.GenRLKShareRound1: %w", err)
	}
	arlk1, err := agent.GenRLKShareRound1(sid)
	if err != nil {
		return nil, fmt.Errorf("VAgent.GenRLKShareRound1: %w", err)
	}
	if err := client.AggregateRLKRound1(arlk1); err != nil {
		return nil, fmt.Errorf("VClient.AggregateRLKRound1: %w", err)
	}
	if err := agent.AggregateRLKRound1(sid, crlk1); err != nil {
		return nil, fmt.Errorf("VAgent.AggregateRLKRound1: %w", err)
	}

	// RLK round 2.
	crlk2, err := client.GenRLKShareRound2()
	if err != nil {
		return nil, fmt.Errorf("VClient.GenRLKShareRound2: %w", err)
	}
	if _, err := agent.GenRLKShareRound2(sid); err != nil {
		return nil, fmt.Errorf("VAgent.GenRLKShareRound2: %w", err)
	}
	if err := agent.AggregateRLKRound2(sid, crlk2); err != nil {
		return nil, fmt.Errorf("VAgent.AggregateRLKRound2: %w", err)
	}

	// Galois handshake.
	cgal, clabels, err := client.GenGaloisShares()
	if err != nil {
		return nil, fmt.Errorf("VClient.GenGaloisShares: %w", err)
	}
	if _, _, err := agent.GenGaloisShares(sid); err != nil {
		return nil, fmt.Errorf("VAgent.GenGaloisShares: %w", err)
	}
	rlk, gks, err := agent.AggregateGaloisShares(sid, cgal, clabels)
	if err != nil {
		return nil, fmt.Errorf("VAgent.AggregateGaloisShares: %w", err)
	}
	if err := vsvc.StoreEvalKeys(sid, rlk, gks); err != nil {
		return nil, fmt.Errorf("VService.StoreEvalKeys: %w", err)
	}

	return &stepSession{
		params:  params,
		sid:     sid,
		vclient: client,
		vagent:  agent,
		vsvc:    vsvc,
		rsvc:    rsvc,
	}, nil
}

// stepImage returns a synthetic image with slot 0 set to a fixed positive
// constant, the rest zero. Used by per-step subcommands that don't take an
// --image flag — what matters there is the protocol mechanics, not the
// preprocessing pipeline.
func stepImage() []float64 {
	img := make([]float64, imageFloats)
	img[0] = 0.5
	return img
}

// runEncryptImage reuses a single Open+Setup, then calls VClient.EncryptImage
// `--n` times on the same image.
func runEncryptImage(argv []string) error {
	fs := flag.NewFlagSet("encrypt-image", flag.ContinueOnError)
	common := registerCommonFlags(fs, defaultOutPath("encrypt-image"))
	imagePath := fs.String("image", "", "path to a 12288-float64 .bin image (required)")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *common.n <= 0 {
		return fmt.Errorf("encrypt-image: --n must be > 0")
	}
	out := common.resolveOut(defaultOutPath("encrypt-image"))

	image, err := loadImage(*imagePath)
	if err != nil {
		return fmt.Errorf("encrypt-image: %w", err)
	}

	params, err := protocol.Defaults()
	if err != nil {
		return fmt.Errorf("encrypt-image: build params: %w", err)
	}
	sess, err := buildStepSession(params)
	if err != nil {
		return fmt.Errorf("encrypt-image: setup: %w", err)
	}

	run := bench.NewRun("encrypt-image", "phase1")
	run.Metadata["n"] = *common.n
	run.Metadata["image"] = *imagePath

	samples, err := bench.Repeat(*common.n, "encrypt-image", func() error {
		_, e := sess.vclient.EncryptImage(image)
		return e
	})
	run.Append(samples...)
	if err != nil {
		return fmt.Errorf("encrypt-image: %w", err)
	}

	if err := run.WriteJSON(out); err != nil {
		return fmt.Errorf("encrypt-image: write %s: %w", out, err)
	}
	fmt.Printf("encrypt-image: wrote %s (n=%d)\n", out, *common.n)
	return nil
}

// runInfer reuses a single Open+Setup+EncryptImage, then calls VService.Infer
// `--n` times on the same inputCt.
func runInfer(argv []string) error {
	fs := flag.NewFlagSet("infer", flag.ContinueOnError)
	common := registerCommonFlags(fs, defaultOutPath("infer"))
	imagePath := fs.String("image", "", "path to a 12288-float64 .bin image (optional; defaults to synthetic)")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *common.n <= 0 {
		return fmt.Errorf("infer: --n must be > 0")
	}
	out := common.resolveOut(defaultOutPath("infer"))

	var image []float64
	if *imagePath != "" {
		img, err := loadImage(*imagePath)
		if err != nil {
			return fmt.Errorf("infer: %w", err)
		}
		image = img
	} else {
		image = stepImage()
	}

	params, err := protocol.Defaults()
	if err != nil {
		return fmt.Errorf("infer: build params: %w", err)
	}
	sess, err := buildStepSession(params)
	if err != nil {
		return fmt.Errorf("infer: setup: %w", err)
	}
	inputCt, err := sess.vclient.EncryptImage(image)
	if err != nil {
		return fmt.Errorf("infer: EncryptImage: %w", err)
	}

	run := bench.NewRun("infer", "phase1")
	run.Metadata["n"] = *common.n

	samples, err := bench.Repeat(*common.n, "infer", func() error {
		_, e := sess.vsvc.Infer(sess.sid, inputCt)
		return e
	})
	run.Append(samples...)
	if err != nil {
		return fmt.Errorf("infer: %w", err)
	}

	if err := run.WriteJSON(out); err != nil {
		return fmt.Errorf("infer: write %s: %w", out, err)
	}
	fmt.Printf("infer: wrote %s (n=%d)\n", out, *common.n)
	return nil
}

// runMAC reuses prior setup + one Infer result, then calls
// VAgent.BuildAuthenticatedCt `--n` times on the same resultCt.
func runMAC(argv []string) error {
	fs := flag.NewFlagSet("mac", flag.ContinueOnError)
	common := registerCommonFlags(fs, defaultOutPath("mac"))
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *common.n <= 0 {
		return fmt.Errorf("mac: --n must be > 0")
	}
	out := common.resolveOut(defaultOutPath("mac"))

	params, err := protocol.Defaults()
	if err != nil {
		return fmt.Errorf("mac: build params: %w", err)
	}
	sess, err := buildStepSession(params)
	if err != nil {
		return fmt.Errorf("mac: setup: %w", err)
	}
	inputCt, err := sess.vclient.EncryptImage(stepImage())
	if err != nil {
		return fmt.Errorf("mac: EncryptImage: %w", err)
	}
	resultCt, err := sess.vsvc.Infer(sess.sid, inputCt)
	if err != nil {
		return fmt.Errorf("mac: Infer: %w", err)
	}

	run := bench.NewRun("mac", "phase1")
	run.Metadata["n"] = *common.n

	samples, err := bench.Repeat(*common.n, "mac", func() error {
		_, e := sess.vagent.BuildAuthenticatedCt(sess.sid, resultCt)
		return e
	})
	run.Append(samples...)
	if err != nil {
		return fmt.Errorf("mac: %w", err)
	}

	if err := run.WriteJSON(out); err != nil {
		return fmt.Errorf("mac: write %s: %w", out, err)
	}
	fmt.Printf("mac: wrote %s (n=%d)\n", out, *common.n)
	return nil
}

// runDecryptResult benchmarks the joint-decryption path: VClient.PartialDecrypt
// + VAgent.FinalizeDecryption. Each iteration runs the full inner protocol
// stage. Because FinalizeDecryption is single-use (it evicts the session on
// completion), iteration i ≥ 1 rebuilds a fresh per-iter session OUTSIDE
// the measured block — the bench captures only the partial-decrypt + agent
// key-switch + decrypt + Ver cost, not the keygen + Auth setup cost.
func runDecryptResult(argv []string) error {
	fs := flag.NewFlagSet("decrypt-result", flag.ContinueOnError)
	common := registerCommonFlags(fs, defaultOutPath("decrypt-result"))
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *common.n <= 0 {
		return fmt.Errorf("decrypt-result: --n must be > 0")
	}
	out := common.resolveOut(defaultOutPath("decrypt-result"))

	params, err := protocol.Defaults()
	if err != nil {
		return fmt.Errorf("decrypt-result: build params: %w", err)
	}

	run := bench.NewRun("decrypt-result", "phase1")
	run.Metadata["n"] = *common.n

	for iter := 0; iter < *common.n; iter++ {
		// Outside the measured block: build a fresh authenticated ciphertext
		// for this iteration. FinalizeDecryption is single-use (drops the
		// session) so we cannot reuse a single authCt across iterations.
		sess, err := buildStepSession(params)
		if err != nil {
			return fmt.Errorf("decrypt-result iter %d: setup: %w", iter, err)
		}
		inputCt, err := sess.vclient.EncryptImage(stepImage())
		if err != nil {
			return fmt.Errorf("decrypt-result iter %d: EncryptImage: %w", iter, err)
		}
		resultCt, err := sess.vsvc.Infer(sess.sid, inputCt)
		if err != nil {
			return fmt.Errorf("decrypt-result iter %d: Infer: %w", iter, err)
		}
		authCt, err := sess.vagent.BuildAuthenticatedCt(sess.sid, resultCt)
		if err != nil {
			return fmt.Errorf("decrypt-result iter %d: BuildAuthenticatedCt: %w", iter, err)
		}

		sample, err := bench.Measure("decrypt-result", func() error {
			clientShare, e := sess.vclient.PartialDecrypt(authCt)
			if e != nil {
				return e
			}
			_, e = sess.vagent.FinalizeDecryption(sess.sid, authCt, clientShare)
			return e
		})
		sample.Iter = iter
		run.Append(sample)
		if err != nil {
			return fmt.Errorf("decrypt-result iter %d: %w", iter, err)
		}
	}

	if err := run.WriteJSON(out); err != nil {
		return fmt.Errorf("decrypt-result: write %s: %w", out, err)
	}
	fmt.Printf("decrypt-result: wrote %s (n=%d)\n", out, *common.n)
	return nil
}

// runVerifyMAC isolates the `authenticator.Ver` step. It mints an
// authenticator + key, fabricates the slot vector that honest joint
// decryption would produce (using `Authenticator.VRawValues`), and then
// runs Ver `--n` times. Each iteration is a pure CPU step — no FHE.
func runVerifyMAC(argv []string) error {
	fs := flag.NewFlagSet("verify-mac", flag.ContinueOnError)
	common := registerCommonFlags(fs, defaultOutPath("verify-mac"))
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *common.n <= 0 {
		return fmt.Errorf("verify-mac: --n must be > 0")
	}
	out := common.resolveOut(defaultOutPath("verify-mac"))

	params, err := protocol.Defaults()
	if err != nil {
		return fmt.Errorf("verify-mac: build params: %w", err)
	}
	auth, err := authenticator.New(params.Authenticator, params.CKKS)
	if err != nil {
		return fmt.Errorf("verify-mac: build authenticator: %w", err)
	}
	key, err := authenticator.KeyGen(params.Authenticator, rand.Reader)
	if err != nil {
		return fmt.Errorf("verify-mac: KeyGen: %w", err)
	}

	vRaw, err := auth.VRawValues(key)
	if err != nil {
		return fmt.Errorf("verify-mac: VRawValues: %w", err)
	}

	delta := params.CKKS.DefaultScale().Float64()
	lambda := params.Authenticator.Lambda

	inS := make(map[int]bool, len(key.S))
	for _, i := range key.S {
		inS[i] = true
	}

	// Build the plaintext vector Ver expects: S slots carry v[i]/Δ, the
	// rest carry the message m. m=0.5 is arbitrary; Ver accepts any value
	// as long as the pairwise-equality check holds across non-S slots.
	const m = 0.5
	plaintext := make([]float64, params.CKKS.MaxSlots())
	for i := 0; i < lambda; i++ {
		if inS[i] {
			plaintext[i] = vRaw[i] / delta
		} else {
			plaintext[i] = m
		}
	}

	run := bench.NewRun("verify-mac", "phase1")
	run.Metadata["n"] = *common.n

	samples, err := bench.Repeat(*common.n, "verify-mac", func() error {
		_, ok := auth.Ver(key, plaintext)
		if !ok {
			return fmt.Errorf("Ver rejected honest plaintext (bench fixture bug)")
		}
		return nil
	})
	run.Append(samples...)
	if err != nil {
		return fmt.Errorf("verify-mac: %w", err)
	}

	if err := run.WriteJSON(out); err != nil {
		return fmt.Errorf("verify-mac: write %s: %w", out, err)
	}
	fmt.Printf("verify-mac: wrote %s (n=%d)\n", out, *common.n)
	return nil
}
