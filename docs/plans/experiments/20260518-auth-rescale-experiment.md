# Experiment: rescale in Auth instead of reserving a level

**Date:** 2026-05-18
**Status:** Negative result — reverted from main branch
**Branch state at experiment:** working tree (not committed)

## Question

The protocol's MPD-Auth/Auth uses `MulNew(resultCt, one_hot)` without a
following `Rescale`. This inflates the output scale from Δ=2^40 to Δ=2^80
(level stays at 1, requires `--reserve-output-levels 1` at Orion
compilation). The inflated Δ contributes ~40 bits to `log2(||e||_canon)`
when computing the Li–Micciancio security headroom — the baseline
measurement found margin = log2(σ_flood) − log2(Δ·max|noise|) ≈ −57 bits
at LogN=16 with σ_flood = 2^16.

Hypothesis: rescaling after the final `AddNew` in Auth would drop both Δ
and ||e||\_canon by exactly `Q[level] ≈ 2^40`, recovering 40 bits of σ
headroom without changing the protocol's information-theoretic content.

## What changed

```go
// internal/authenticator/authenticator.go

// Bound v_raw to (-q_0/16, q_0/16) instead of (-q_0/2, q_0/2) so the
// post-rescale coefficient fits in q_0 with headroom. Drops per-S-slot
// MAC entropy from ~54 to ~51 bits (irrelevant for this protocol).
- q0Half := new(big.Int).Rsh(q0, 1)
+ q0Half := new(big.Int).Rsh(q0, 4)

// After Step 6 (ct_M = ct_m^Rep + ct_v), rescale the final ciphertext:
+ if err = eval.Rescale(ctMReturn, ctMReturn); err != nil {
+     return nil, fmt.Errorf("authenticator: rescale final ct_M: %w", err)
+ }

// internal/authenticator/config.go — bump Ver tolerance to absorb the
// new slot-space noise floor from σ_flood after the smaller post-rescale Δ.
- Epsilon: math.Exp2(20),
+ Epsilon: math.Exp2(28),
```

Test files (`_test.go`) updated to match the new constants — same `Exp2`
and `Rsh` values everywhere they appeared hardcoded.

## Results

### 10-sample run (`results/20260518T152211Z/`)

| metric                 | baseline (reserve) | experiment (rescale) |       Δ |
| ---------------------- | -----------------: | -------------------: | ------: |
| log₂(Δ) at decode      |                 80 |                   40 | **−40** |
| log₂(\|\|e\|\|\_canon) |               73.3 |                 33.3 | **−40** |
| log₂(σ_flood)          |                 16 |                   16 |       0 |
| Li–Micciancio margin   |     **−57.3 bits** |       **−17.3 bits** | **+40** |

Exactly the predicted +40 bits of margin recovery. Verdicts: 10/10 matched
the plaintext reference. No MAC failures.

### 30-sample run (`results/20260518T160803Z/`)

Mean margin held at −17.3 bits across 30 images. **But:** image 8 showed
log₂(\|\|e\|\|\_canon) = 55 (the rest were ~33), and the FHE classifier
produced 1 false negative that the plaintext reference did not — accuracy
dropped from 0.833 (plain) to 0.800 (FHE), vs the baseline run where FHE
matched plain exactly on 10 samples.

The noise-per-slot histogram is bimodal: most slots have residual <1 in
slot space (good), but img_8's slots are saturated around `±q_0/(2·Δ)`
= ±32768 — the canonical wraparound signature.

## Conclusion

The reserve-vs-rescale choice is **not just a security-headroom
trade-off**. The baseline design's inflated Δ also provides a 40-bit
correctness margin against tail-of-distribution evaluation noise. The
rescale design moves the typical-case noise comfortably under Δ, but
tail samples (~3% of the batch) exceed q at level 0 and decode to
garbage, flipping verdicts non-deterministically.

The original author's design is correct on both axes — security headroom
is unrecoverable at this circuit depth either way, and giving up the
correctness reserve to chase the security gain produces verdict failures.
Closing the −17.3 bit gap further would require either a deeper Q chain
(more RAM), bootstrapping (much larger architectural change), or a
threat-model retreat (e.g., only the verdict bit is published, not the
full plaintext).

## What stays on main

The instrumentation that _measures_ the headroom — `log2_scale` and
`log2_flood_sigma` in `decoded.json`, and the `_security_headroom_rows /
_security_headroom_md` helpers in `bench/bench/eval.py` — is kept. The
Auth-rescale code change is reverted.

## Full diff archived in this file

See `git log --all -- internal/authenticator/authenticator.go` and the
diff snippet above. The 310-line full working diff was saved at
`/tmp/auth-rescale.diff` at experiment time but is not committed.
