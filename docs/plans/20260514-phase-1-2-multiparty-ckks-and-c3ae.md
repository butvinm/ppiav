# Phase 1+2: multi-party CKKS scaffolding and Orion-compiled C3AE

## Overview

Bring the ppiav prototype from empty scaffolding to a working end-to-end demonstrator covering DESIGN.md Phases 1 and 2.

- **Phase 1** delivers the multi-party CKKS protocol — collaborative keygen (pk + two-round rlk + per-rotation Galois keys), the MPD-Auth construction (`Auth` and `Ver`), and joint decryption — running in-process inside a single `ppiav-cli` binary against a synthetic `x²` inference circuit. The rotation-bearing `Auth` step exercises Galois keys from day one even though `x²` itself uses none. A pure-Go `internal/bench` harness emits per-stage JSON samples that a small Python project under `bench/` post-processes into Markdown tables and PNG plots.
- **Phase 2** replaces the synthetic `x²` circuit with an Orion-compiled C3AE inference, sourcing CKKS params from the Orion manifest. A new `models/` Python uv project handles training + Orion compilation and produces both the compiled circuit consumed by `internal/vservice` and pre-prepared `.bin` test inputs consumed by `internal/vclient`. The protocol shape stays identical to Phase 1; only the inference op and the params source change.

Phases 3 (HTTP transport + browser SPAs) and 4 (lattigo-hierkeys) are explicitly out of scope.

## Context (from discovery)

- Repo state: empty scaffolding — `go.mod` (`github.com/butvinm/ppiav`, Lattigo v6.2.0), `docs/DESIGN.md`, `CLAUDE.md`, `README.md`, an empty `results/.gitkeep`. No Go sources, no Python project, no `cmd/`, `internal/`, `bench/`, `models/`, or `web/` directories.
- README quick-start commands are forward-looking — they reference paths that don't exist yet. They become the implicit acceptance check for this plan.
- DESIGN.md is the single source of truth and is unusually concrete: package signatures, parameter values, CRS construction, level budget, Auth/Ver pseudocode, image preprocessing contract, and CRP draw order are all spelled out. Tasks below cite the relevant `§` in inline comments rather than restating algorithms.
- Reference repos (read-only, do **not** copy): Orion at `~/Dev/orion/` (especially `examples/c3ae-demo/`), Lattigo at `~/Dev/3rd-party/lattigo/`, thesis at `~/Dev/ITMO/thesis/`.
- Lattigo v6.2.0 made all per-structure methods concurrency-safe; `ShallowCopy()` is gone. Don't introduce per-goroutine clones.

## Development Approach

- **testing approach**: Regular — write Go code, then unit tests in the same file's `*_test.go`, in the same task. The design specifies algorithms precisely enough that strict test-first adds friction without buying coverage; in return we keep the discipline of finishing a task only when its tests pass.
- complete each task fully before moving to the next
- make small, focused changes
- **CRITICAL: every task MUST include new/updated tests** for code changes in that task
  - tests are not optional — they are a required part of the checklist
  - tests cover both success and error scenarios
  - prefer table-driven Go tests; use `github.com/stretchr/testify` (already in `go.sum`) for assertions
- **CRITICAL: all tests must pass before starting next task** — no exceptions
- **CRITICAL: update this plan file when scope changes during implementation**
- run tests after each change: `go test ./...`
- atomic commits per task: stage specific files (`git add path/to/file`), never `git add .`
- no `git add` of generated artifacts (`results/**/*.json`, model binaries, Orion outputs) unless explicitly committed as a snapshot

## Testing Strategy

- **Unit tests** (required per task): Go `*_test.go` next to each source file. Use `testify/assert` and `testify/require`. Phase-1 tests run with a smaller `LogN` set (e.g. `LogN=14`) where it doesn't break the protocol so the unit suite stays fast — full-`LogN` runs go through the CLI or the integration build tag.
- **Integration test** (Task 11, build-tagged `//go:build integration`): one end-to-end test exercising the full §3 protocol in-process with the production `LogN=16` params. Drives every package together. Run with `go test -tags=integration ./...`.
- **Noise / parameter validation** (build-tagged `//go:build noise`): one slow test (~minutes, dozens of fresh keygens) that empirically measures the post-decryption noise distribution and asserts the §`ε and σ_flood` margin holds. Justifies the constants in DESIGN.md.
- **Python suite** (Phase 2 only): `pytest`, `ruff check`, `mypy --strict` for the `bench/` and `models/` uv projects. Pytest covers the image-preprocessing pipeline against fixed test vectors so it can be cross-validated against the JS browser pipeline in a later phase.
- **No e2e UI tests** — Phase 3 work, out of scope here.

## Progress Tracking

- mark completed items with `[x]` immediately when done
- add newly discovered tasks with ➕ prefix
- document issues/blockers with ⚠️ prefix
- update plan if implementation deviates from original scope
- keep plan in sync with actual work done

## Solution Overview

The implementation strictly mirrors DESIGN.md §`Implementation/Layout` and §`Components`. There is essentially one correct shape for each package — function signatures and types are quoted verbatim in the design — so this plan focuses on ordering, not on rediscovering structure.

**Build order (bottom-up; each layer depends only on what came before):**

```
internal/bench  ──►  cmd/ppiav-cli (later)
                ┐
internal/protocol ──►  internal/authenticator ──►  internal/vagent ─────┐
              │                                                          │
              ├────►  internal/vservice ─────────────────────────────────┤
              ├────►  internal/vclient  ─────────────────────────────────┤
              └────►  internal/rservice ─────────────────────────────────┤
                                                                         ▼
                                                                cmd/ppiav-cli (Phase 1)
                                                                         │
                                       models/ (Python uv)  ──►  Phase-2 reweave
```

**Key design decisions, decided in the design doc, that constrain implementation:**

1. **MPD-Auth is baseline from Phase 1.** Rotation keys are generated in Stage 2d even though `x²` itself uses none — `Auth` needs them. This means `internal/authenticator` and the per-rotation Galois-share handshake land in Phase 1, not Phase 2 or 4. The collaborative `multiparty.GaloisKeyGen` runs once per index `j ∈ [1, λ)` (default `λ=128`, so 127 shares per side).
2. **CRS is sid-derived, not wire-borne.** Both parties construct `sampling.NewKeyedPRNG("ppiav-crs/v1|" + sid)`. The draw order is fixed (§`internal/protocol`): `PublicKeyGen.SampleCRP`, then `RelinearizationKeyGen.SampleCRP`, then `GaloisKeyGen.SampleCRP` per rotation in ascending index order.
3. **Parameters bundle CKKS + authenticator + flooding.** `protocol.Params{ CKKS, Authenticator, FloodSigma }`. `FloodSigma` lives in `protocol.Params` not `authenticator.Config` because VClient is its sole consumer.
4. **`Authenticator` is a stateful bundle + standalone `KeyGen`.** Cache `pt_one_hot` once per `Authenticator` (session-independent at scale 1). Each session calls `authenticator.KeyGen(cfg, rand)` to mint a single-use `Key{S, SeedF}` which is `BinaryMarshaler`-serialisable.
5. **VClient never sees plaintext.** No `Decryptor` lives in `internal/vclient`. Joint decryption flow: VAgent builds `ct_M` → VAgent streams to VClient → VClient produces `KeySwitchShare` with noise flooding (`σ_flood = 2¹⁶`) → VAgent combines with its own share and finishes.
6. **Image preprocessing is upstream of `internal/vclient`.** `EncryptImage` consumes a `[]float64` of length exactly `12288 = 3·64·64`; wrong length is a hard error (no silent padding). The 5-step normalisation pipeline (resize-bicubic, divide-255, `(x-0.5)/0.5`, HWC→CHW, flatten) is owned by the Python `models/prepare_samples.py` in Phase 1/2 (CLI consumes `.bin`).
7. **In-process orchestration.** `cmd/ppiav-cli` instantiates one `vclient.Client`, one `vagent.Agent`, one `vservice.Service`, one `rservice.Service` and wires their method calls directly. No HTTP, no goroutines beyond what `internal/bench` needs.

## Technical Details

**`internal/protocol` constants and CRS construction** (verbatim from DESIGN.md §`internal/protocol`):

```go
const crsDomain = "ppiav-crs/v1"

func newSessionCRS(sid SessionID) (*sampling.KeyedPRNG, error) {
    return sampling.NewKeyedPRNG([]byte(crsDomain + "|" + string(sid)))
}
```

**Phase 1 CKKS defaults** (§`Implementation/Layout`):

| Knob              | Value                        |
| ----------------- | ---------------------------- |
| `LogN`            | 16 (32768 slots)             |
| `LogQ`            | `[55, 40, 40, …, 40]` (1+15) |
| `LogP`            | `[55] × 6`                   |
| `LogDefaultScale` | 40 (Δ = 2⁴⁰)                 |
| `RingType`        | Standard                     |
| `λ`               | 128                          |
| `\|S\|`           | 64 (derived `λ/2`)           |
| `ε`               | 2²⁰                          |
| `σ_flood`         | 2¹⁶                          |

**Phase 2 CKKS source:** the Orion C3AE compiled manifest at `~/Dev/orion/examples/c3ae-demo/models/params.py:51` (`logn16` profile). DESIGN.md states the same `LogN/LogQ/LogP/Δ` are reused, so Phase 2 only changes the source of truth — values do not move. The `inputLevel` and any scale schedule come from `Model.ClientParams()` of the compiled manifest.

**Authenticated ciphertext construction** (§`Multiparty decryption with authentication / Auth`):

1. `ct_m = result_ct · pt_one_hot` (ct × pt at scale 1; no rescale, no level consumed).
2. Sample `S ⊂ [0, λ)`, `|S| = λ/2`.
3. Build `v` of length `λ`: `v[i] = F(seedF, i)` if `i ∈ S` else `0`. F samples from `(-Q_0/2, Q_0/2)`.
4. `ct_m^Rep = Σ_{j ∈ [0, λ) \ S} Rot(ct_m, j)`.
5. Encrypt `v` at scale Δ → `ct_v`.
6. `ct_M = ct_m^Rep + ct_v`.

**Joint decryption + Ver** (§`Auth/Ver`):

- Combine VClient's `KeySwitchShare` (with `σ_flood = 2¹⁶`) and VAgent's `KeySwitchShare` (from `sk_a`).
- Apply key-switch to recover plaintext slot vector `P`.
- Accept iff: for all `i ∈ S`, `|P[i]·Δ − v[i]| < ε`; and for all `i ∈ [0, λ) \ S`, `|P[i]·Δ − P[j*]·Δ| < ε` for the smallest `j* ∈ [0, λ) \ S`.
- Recovered message: `m_recovered = P[j*]`. `Verdict = Accept` iff `m_recovered > 0`.

**Required Galois rotation indices** (Phase 1+2 baseline, before any Phase-2 model adds its own): `1, 2, …, λ-1 = 127`. The set is the union over all possible `S`, so any single session's `Auth` can run regardless of which `S` was sampled. Phase 2 unions this with the rotation set declared by the compiled C3AE manifest.

**`internal/bench` data shape** (§`internal/bench`): `Sample` carries wall time, heap stats, GC, optional artifact size. `Run` bundles samples + GoVersion/GOOS/GOARCH/NumCPU/started + arbitrary metadata. `Run.WriteJSON(path)` is the only writer. Python `bench/` reads these.

**Synthetic `x²` inference** (Phase 1, §`Level budget — Phase 1`): consumes exactly 1 level — one ciphertext × ciphertext multiplication followed by rescaling. The relinearization key from Stage 2c is needed here. Output slot 0 is the "logit"; for the synthetic case we set it deliberately positive or negative in test fixtures to exercise Accept/Reject paths.

## What Goes Where

- **Implementation Steps** (`[ ]` checkboxes): everything inside `~/Dev/ppiav/` — Go code, Go tests, Python code, JSON output, scripts, plan-file maintenance.
- **Post-Completion** (no checkboxes): things outside this repo or that need a human eyeball — e.g. cross-checking JSON numbers against thesis claims; verifying Orion fork's C3AE demo runs in our environment as a sanity baseline; visual inspection of bench plots.

---

## Implementation Steps

### Task 1: Bootstrap `internal/bench` measurement harness

**Files:**

- Create: `internal/bench/bench.go`
- Create: `internal/bench/bench_test.go`

Reason this is first: every later task that does crypto work logs samples through `bench.Measure`/`bench.Repeat`. Building it as a leaf with zero dependencies means nothing downstream waits on it.

- [ ] create `internal/bench/bench.go` implementing `Sample`, `Run`, `NewRun`, `(*Run).Append`, `(*Run).WriteJSON`, `Measure`, `MeasureWithSize`, `Repeat`, `RepeatWithWarmup` per DESIGN.md §`internal/bench`. Use `runtime.MemStats` for heap fields, `runtime.GC()` + a steady-state read for stable accounting, `time.Now()` deltas for wall time. Linux-only `VmHWM` parses `/proc/self/status`; non-Linux returns 0.
- [ ] make `Run.WriteJSON` atomic — write to a `tmp` sibling then rename — so a partially-written file never lands in `results/`.
- [ ] write table-driven tests for `Measure` (single-shot success + error propagation), `Repeat` (correct `Iter` indexing, propagates errors), `RepeatWithWarmup` (warmup excluded from samples), and `Run.WriteJSON` (round-trips through `encoding/json`).
- [ ] write a sanity test that `Sample.Wall > 0` for a `time.Sleep(time.Millisecond)` body.
- [ ] run tests — must pass before Task 2: `go test ./internal/bench/...`

### Task 2: `internal/protocol` — domain types, parameter sets, wire messages, CRS

**Files:**

- Create: `internal/protocol/types.go`
- Create: `internal/protocol/params.go`
- Create: `internal/protocol/wire.go`
- Create: `internal/protocol/crs.go`
- Create: `internal/protocol/types_test.go`
- Create: `internal/protocol/params_test.go`
- Create: `internal/protocol/crs_test.go`

- [ ] `types.go`: `SessionID string`, `Verdict uint8` + the `VerdictUnknown/Accept/Reject` constants. `Verdict.String()` for diagnostics.
- [ ] `params.go`: `Params{ CKKS ckks.Parameters, Authenticator authenticator.Config, FloodSigma float64 }` and `Defaults() (Params, error)`. Defaults build a `ckks.Parameters` from a `ckks.ParametersLiteral` with the Phase-1 values from DESIGN.md (`LogN=16`, `LogQ=[55]+[40]×15`, `LogP=[55]×6`, `LogDefaultScale=40`, `RingType=ring.Standard`). `Authenticator` is `authenticator.DefaultConfig()`. `FloodSigma = math.Exp2(16)`.
- [ ] **Note:** `authenticator.Config` is consumed here but defined in Task 3 — break the dependency with a deferred sub-step: stub `Config` and `DefaultConfig` in `internal/protocol/params.go` as a temporary `type Config struct{ Lambda int; Epsilon float64 }` and move it to `internal/authenticator` in Task 3, then update `params.go` to import it. Mark the stub with `// TODO(task 3): move to internal/authenticator`.
- [ ] `wire.go`: declare every wire-message type from DESIGN.md §`internal/protocol`: `SessionOpen`, `VerificationSession`, `VClientPKShare`, `VAgentPKShare`, `VClientRLKRound1`, `VAgentRLKRound1`, `VClientRLKRound2`, `VClientGaloisKeyShare`, `InferEvalKeys`, `EncryptedImage`, `AuthenticatedResult`, `PartialDecryption`, `VerdictNotification`. Phase-4-only fields (`GKSMaster`) are not declared yet.
- [ ] `crs.go`: `const crsDomain = "ppiav-crs/v1"` and `func NewSessionCRS(sid SessionID) (*sampling.KeyedPRNG, error)` exactly as in DESIGN.md. Also a `CanonicalRotationIndices(lambda int) []int` helper that returns `[1..lambda)` so the CRP draw order can be shared between VAgent and VClient.
- [ ] tests: `params_test.go` constructs `Defaults()` and asserts `LogN==16`, slot count 32768, max level 15, default scale `2^40`. `crs_test.go` asserts two `NewSessionCRS` instances for the same sid produce identical first-32-byte outputs, and different sids diverge. `types_test.go` asserts `Verdict.String()` round-trip.
- [ ] write success-case tests for each wire-message type's binary round-trip — use `encoding.BinaryMarshaler` where the embedded Lattigo type already implements it, and a `t.Skip` placeholder where it doesn't (we'll fill those in Task 9 when the CLI serialises them anyway; not load-bearing for in-process Phase-1 use).
- [ ] run tests — must pass before Task 3.

### Task 3: `internal/authenticator` — Config, Key, KeyGen, Auth, Ver

**Files:**

- Create: `internal/authenticator/config.go`
- Create: `internal/authenticator/key.go`
- Create: `internal/authenticator/authenticator.go`
- Create: `internal/authenticator/ver.go`
- Create: `internal/authenticator/config_test.go`
- Create: `internal/authenticator/key_test.go`
- Create: `internal/authenticator/authenticator_test.go`
- Modify: `internal/protocol/params.go` (replace the Task-2 stub import with the real package import)

- [ ] `config.go`: `Config{ Lambda int; Epsilon float64 }`, `DefaultConfig() Config` returning `{Lambda: 128, Epsilon: math.Exp2(20)}`. Validate `Lambda > 0` and `Lambda % 2 == 0` (so `|S| = Lambda/2` is exact) — return error from `New` on violation.
- [ ] remove the stub from `internal/protocol/params.go` and import the real `Config`.
- [ ] `key.go`: `Key{ S []int; SeedF [32]byte }`. `MarshalBinary` writes a fixed header + sorted-ascending `S` as little-endian uint32s + `SeedF`. `UnmarshalBinary` reverses it and validates `len(S) == Lambda/2` and `S ⊂ [0, Lambda)`. Sorting on the wire makes equality testing deterministic.
- [ ] `KeyGen(cfg Config, rand io.Reader) (Key, error)`: sample `|S| = Lambda/2` distinct indices from `[0, Lambda)` without replacement using a Fisher-Yates shuffle over `[0, Lambda)` truncated. Read 32 bytes from `rand` into `SeedF`. Return the key.
- [ ] `authenticator.go`: `Authenticator` struct holds `cfg`, `params ckks.Parameters`, and the cached `pt_one_hot *rlwe.Plaintext` (encode `[1, 0, …, 0]` at scale 1.0 via `encoder.EncodeNew`). `New(cfg, params)` constructs it. Also stash a `*ckks.Encoder` here for the encode of `v`; encoders are concurrency-safe in v6.2.0 so one shared instance is fine.
- [ ] implement `Auth`: validate the `eval` Galois set covers `[1, Lambda)` using `params.SolveDiscreteLogGaloisElement` per DESIGN.md §`Implementation notes`; mask `result_ct` against the cached `pt_one_hot` (ct×pt, no rescale); seed a `crypto/rand` PRG from `key.SeedF` and generate `v` (uniform over `(-Q_0/2, Q_0/2)`; `Q_0` is `params.Q()[0]`); rotate-and-sum over `[0, Lambda) \ S`; encrypt `v` at scale Δ; add. Return `ct_M`.
- [ ] `ver.go`: implement `Ver(key Key, plaintext []float64) (m float64, ok bool)`. Compute Δ = `params.DefaultScale().Float64()`. Two checks per DESIGN.md §`Auth/Ver`: verification-slot match and value-slot pairwise agreement. Pick `j*` = smallest index in `[0, Lambda) \ S`. Return `(P[j*], true)` on pass, `(0, false)` on fail.
- [ ] tests:
  - `config_test.go`: `DefaultConfig` returns the documented defaults; `New` rejects odd `Lambda`.
  - `key_test.go`: `KeyGen` produces `|S| = Lambda/2`, distinct, in range; round-trip through `MarshalBinary`/`UnmarshalBinary`; truncated input errors cleanly.
  - `authenticator_test.go`: `Auth` over a hand-crafted `result_ct` with `m=0.5` at slot 0 (encrypt directly under a non-multi-party `sk`/`pk` for isolation) produces a ciphertext that, when decrypted, has `m` in every slot of `[0, Lambda) \ S` and the expected verification values in `S` slots. `Ver` accepts the honest decryption and rejects a hand-tampered plaintext where one `S` slot is off by `> ε`. Run `Auth` with a smaller `Lambda` (e.g. 16) to keep the unit suite fast.
- [ ] run tests — must pass before Task 4: `go test ./internal/authenticator/... ./internal/protocol/...`.

### Task 4: `internal/vservice` — sid issuer, evaluator, `x²` inference

**Files:**

- Create: `internal/vservice/service.go`
- Create: `internal/vservice/infer.go`
- Create: `internal/vservice/service_test.go`
- Create: `internal/vservice/infer_test.go`

- [ ] `service.go`: `Service` struct with `params protocol.Params`, `sessions map[SessionID]*sessionState`, `mu sync.Mutex`. `sessionState` holds the per-session `*ckks.Evaluator`. `New(params)` constructor.
- [ ] `OpenSession() (SessionID, error)`: draw ≥128 bits from `crypto/rand`, hex-encode, allocate the session slot. Return `SessionID`. Error if random read fails. **Do not** generate the evaluator yet — `StoreEvalKeys` does that.
- [ ] `Params() protocol.Params`: return `s.params`.
- [ ] `StoreEvalKeys(sid, rlk *rlwe.RelinearizationKey, gks *rlwe.GaloisKeySet) error`: under `s.mu`, look up the session, build a `ckks.NewEvaluator(params.CKKS, rlwe.NewMemEvaluationKeySet(rlk, gks.GetKeys()...))`. Error if sid unknown. (Phase 4 will swap the `gks` argument for a hierkeys master key.)
- [ ] `infer.go`: `Infer(sid, inputCt) (*rlwe.Ciphertext, error)` — Phase 1 implements `x²`. Under `s.mu` (or after copying the evaluator pointer out) call `eval.MulRelinNew(inputCt, inputCt)` then `eval.RescaleNew`. Error if sid unknown.
- [ ] tests:
  - `service_test.go`: `OpenSession` returns distinct sids on consecutive calls; `StoreEvalKeys` errors on unknown sid; `Params` returns the original params.
  - `infer_test.go`: end-to-end x² test using single-party Lattigo keys (skip the multi-party handshake here — it's tested in Task 8). Encrypt `m=0.3`, infer, decrypt, assert `|m' − 0.09| < 1e-4`. Also assert level drops by exactly 1 after `Infer`. Use `LogN=14` parameters here for speed; do not depend on `protocol.Defaults()`.
- [ ] run tests — must pass before Task 5.

### Task 5: `internal/vclient` — client-side shares, partial decryption, image encryption

**Files:**

- Create: `internal/vclient/client.go`
- Create: `internal/vclient/keygen.go`
- Create: `internal/vclient/image.go`
- Create: `internal/vclient/partial_decrypt.go`
- Create: `internal/vclient/client_test.go`
- Create: `internal/vclient/keygen_test.go`
- Create: `internal/vclient/image_test.go`
- Create: `internal/vclient/partial_decrypt_test.go`

- [ ] `client.go`: `Client` struct + `New(params, sid)` constructor exactly per DESIGN.md §`internal/vclient`. Generate `sk_c` via `multiparty.PublicKeyGenProtocol{}.AllocateShare`-style init or `rlwe.NewKeyGenerator(params.CKKS).GenSecretKeyNew()`. Build the CRS via `protocol.NewSessionCRS(sid)`.
- [ ] `keygen.go`:
  - `GenPKShare()`: instantiate `multiparty.NewPublicKeyGenProtocol(params)`, call `proto.AllocateShare()`, sample CRP via `proto.SampleCRP(crs)` (first CRP draw per the canonical order), call `proto.GenShare(skShare, crp, &share)`. Return the share.
  - `AggregatePK(agentShare)`: re-run `AllocateShare`, then `proto.AggregateShares(clientShare, agentShare, &aggregate)`; `proto.GenPublicKey(aggregate, crp, pkAgg)`. Persist `c.pkAgg` and build `c.encryptor`.
  - `GenRLKShareRound1` / `AggregateRLKRound1` / `GenRLKShareRound2`: standard two-round flow with `multiparty.NewRelinearizationKeyGenProtocol(params)`. The Round-2 share is shipped but not aggregated client-side (VAgent and VService own the final rlk; VClient doesn't need it).
  - `GenGaloisShares() ([]multiparty.GaloisKeyGenShare, error)`: iterate `protocol.CanonicalRotationIndices(params.Authenticator.Lambda)`, sample a CRP per index in ascending order (canonical draw order), generate a share per index. Return the slice.
- [ ] `image.go`: `EncryptImage(image []float64) (*rlwe.Ciphertext, error)`. Hard-fail on `len(image) != 12288`. Pad with zeros to `params.MaxSlots()`. Encode at `params.DefaultScale()`. Encrypt under `c.pkAgg` via `c.encryptor.EncryptNew(pt)`. The level question — DESIGN.md says "the compiled model's input level, padded to MaxSlots". In Phase 1 there is no compiled model, so encrypt at the max level (`params.MaxLevel()`); document the override.
- [ ] `partial_decrypt.go`: `PartialDecrypt(authenticatedCt) (multiparty.KeySwitchShare, error)`. Use `multiparty.NewKeySwitchProtocol(params.CKKS, ring.DiscreteGaussian{Sigma: params.FloodSigma, Bound: 6 * params.FloodSigma})`. The smudging mitigates CKKS IND-CPA^D (Li–Micciancio 2021): without it, VAgent observes `(c1·sk_c + e_fresh, plaintext)` per session and can statistically recover `sk_c` because CKKS decryption noise is deterministic in `(c, sk)`. Allocate share, call `proto.GenShare(c.skShare, zeroSk, authenticatedCt, &share)` where `zeroSk` is `rlwe.NewSecretKey(params.CKKS)` (zero-valued sk → decryption rather than key-switch). Return the share.
- [ ] tests:
  - `keygen_test.go`: drive each Generate/Aggregate pair against a hand-rolled "VAgent stub" — instantiate the same multi-party protocol on the test side with a synthetic `sk_a`, do the matching half of the handshake, assert the aggregate pk + rlk + per-rotation Galois keys decrypt/rotate correctly against `sk_c + sk_a`. Run with `LogN=14` and `λ=8` for speed.
  - `image_test.go`: wrong-length input is rejected; right-length input encrypts and decrypts back within float-precision tolerance against the test-only `sk_c + sk_a`.
  - `partial_decrypt_test.go`: round-trip — encrypt `m=0.42` under aggregated pk, run `PartialDecrypt` + the VAgent side from a stub, assert `|m_decrypted − 0.42| < ε` (use `ε = 1e-4` for the unit test; the production `ε` is for §`Ver`'s bound and is much looser).
- [ ] run tests — must pass before Task 6.

### Task 6: `internal/vagent` — agent-side shares, authenticated ct, finalize decryption

**Files:**

- Create: `internal/vagent/agent.go`
- Create: `internal/vagent/keygen.go`
- Create: `internal/vagent/authenticate.go`
- Create: `internal/vagent/finalize.go`
- Create: `internal/vagent/agent_test.go`
- Create: `internal/vagent/keygen_test.go`
- Create: `internal/vagent/authenticate_test.go`
- Create: `internal/vagent/finalize_test.go`

- [ ] `agent.go`: `Agent`, `sessionState`, `New(params)`, `OpenSession(sid)` per DESIGN.md §`internal/vagent`. `OpenSession` registers the sid, mints `sk_a`, calls `authenticator.KeyGen(params.Authenticator, crypto/rand.Reader)` for the session's `authKey`, builds the CRS the same way VClient does.
- [ ] `keygen.go`: mirrors `internal/vclient/keygen.go` with a `Gen*Share` / `Aggregate*` split on each step (symmetric to VClient's API):
  - `GenPKShare(sid) → agentShare`: draw the CRP (first in canonical order), generate `pk_a` share. Return for delivery to VClient.
  - `AggregatePK(sid, clientShare)`: combine with the stashed agent share, build `pkAgg` + `encryptor`, persist on session state.
  - `GenRLKShareRound1(sid) → agentShare`, `AggregateRLKRound1(sid, clientShare)`: same pattern; RLK CRP is drawn once in Round 1 and **reused** in Round 2 (cache it on session state).
  - `GenRLKShareRound2(sid) → agentShare`, `AggregateRLKRound2(sid, clientShare)`: agent's round-2 share does not go over the wire to VClient (VClient does not retain rlk) but the method exists for in-process symmetry; `AggregateRLKRound2` finalises `rlkAgg`.
  - `GenGaloisShares(sid) → []agentShares`: iterate `params.RotationIndices()` (see Task 13; in Phase 1 this is `[1, λ)`), drawing one CRP per index in ascending order. Return the slice.
  - `AggregateGaloisShares(sid, clientShares) → (rlk, gks, err)`: validate `len(clientShares) == len(params.RotationIndices())`; combine pairwise per index to assemble `*rlwe.GaloisKeySet`; build `eval` from `rlkAgg + gksAgg`. Return `(rlkAgg, gksAgg)` so the caller (CLI) hands them to `vservice.StoreEvalKeys`.
- [ ] `authenticate.go`: `BuildAuthenticatedCt(sid, resultCt) → *rlwe.Ciphertext`: look up session, call `a.auth.Auth(sess.authKey, encoder, encryptor, eval, resultCt)`. Return the result.
- [ ] `finalize.go`: `FinalizeDecryption(sid, authenticatedCt, clientShare) → Verdict`. Compute VAgent's `KeySwitchShare` via `multiparty.NewKeySwitchProtocol(params.CKKS, ring.DiscreteGaussian{Sigma: 0, Bound: 0})` — VAgent does **not** smudge. The IND-CPA^D vulnerability that motivates VClient's smudging requires the counterparty to see both `(share, plaintext)`; VClient sees neither VAgent's share nor the plaintext, so VAgent's share has no exposure to mitigate. The `eFresh` noise added automatically by `GenShare` (RLWE-foundational, not opt-in) is sufficient. Verify at code time that Lattigo accepts `Sigma: 0` at `keyswitch_sk.go:57`; if the sampler init trips, fall back to a smallest-non-zero σ — it doesn't matter for security because `eFresh` dominates either way. Aggregate shares, apply key-switch + decryption to recover the plaintext. Decode to slot vector. Call `a.auth.Ver(authKey, plaintext)`. If `!ok` → `VerdictReject`. Else `m > 0` → `Accept`, else `Reject`. Drop the session entry (single-use `authKey`).
- [ ] tests:
  - `keygen_test.go`: same handshake-stub pattern as Task 5 but with the VClient role faked. Asserts aggregated pk/rlk/gks are bit-identical to VClient's view.
  - `authenticate_test.go`: feed a known `result_ct` (encrypted `m=0.7` at slot 0, garbage elsewhere), call `BuildAuthenticatedCt`, decrypt with `sk_c + sk_a`, assert the §`Auth` layout (`m` in non-`S` slots, `v[i] / Δ` in `S` slots).
  - `finalize_test.go`: full joint-decryption happy path with `m=0.7` → `Accept`; with `m=-0.3` → `Reject`. Tamper-case: VClient submits a `KeySwitchShare` from a wrong sk → `Reject`. Run with `λ=16` for speed.
- [ ] run tests — must pass before Task 7.

### Task 7: `internal/rservice` — verdict gating

**Files:**

- Create: `internal/rservice/service.go`
- Create: `internal/rservice/service_test.go`

- [ ] `service.go`: `Service{ sessions map[SessionID]Verdict; mu sync.Mutex }`. `New() *Service`, `AcceptVerdict(sid, v) error` (upsert), `CheckAccess(sid) Verdict` (missing → `VerdictUnknown`).
- [ ] `service_test.go`: missing sid returns `VerdictUnknown`; `AcceptVerdict` then `CheckAccess` returns the upserted verdict; double-upsert returns the latest value; concurrent `AcceptVerdict` from many goroutines doesn't race (`go test -race`).
- [ ] run tests — must pass before Task 8.

### Task 8: in-process orchestrator + Phase-1 happy-path integration test

**Files:**

- Create: `internal/orchestrator/runner.go`
- Create: `internal/orchestrator/runner_test.go`
- Create: `internal/orchestrator/integration_test.go`

The orchestrator is the in-process glue that the CLI in Task 9 wraps. Putting it in `internal/` rather than `cmd/` keeps it test-importable. It owns the call sequence — every method here mirrors one stage of DESIGN.md §`Protocol`.

- [ ] `runner.go`: `Runner` struct bundles `vclient.Client`, `vagent.Agent`, `vservice.Service`, `rservice.Service`. `NewRunner(params)` constructs them. `Open()` runs Stage 1 (`vservice.OpenSession` → `vagent.OpenSession` → returns sid). `Setup(ctx)` drives Stages 2a–d (params handshake, pk handshake, two rlk rounds, Galois handshake, `vservice.StoreEvalKeys`). `Infer(image []float64) → *rlwe.Ciphertext` runs Stage 3. `Verify(resultCt) → Verdict` runs Stage 4 and submits to RService.
- [ ] each `Runner` method is a stripped-down wrapper around the underlying call — no business logic — but each one is a natural `bench.Measure` boundary, so they return error-only and the CLI wraps them.
- [ ] `runner_test.go`: unit tests against a smaller `LogN=14`, `λ=8` profile. Drive `Open` → `Setup` → encrypt `m=0.5` → `Infer` → `Verify`. Assert `Verdict.Accept` (squared positive logit ⇒ `m'=0.25 > 0`). Also assert each method advances state in the right order (calling `Verify` before `Setup` is an error).
- [ ] `integration_test.go` (build tag `//go:build integration`): full DESIGN.md `LogN=16` defaults, end-to-end. Provide an image vector that's all 0.5 (so encrypted `m=0.5`, `x²` produces `0.25` at every slot, `Ver` accepts, `Verdict = Accept`). Provide a second case with image of all `-0.3` (still positive squared, still Accept — there is no negative `m` after `x²`, so we instead drive Reject via a `ForceReject` test hook on `Runner` that swaps in a `m=-0.5` plaintext after inference — document this is a test-only path).
- [ ] also include a tamper test in `integration_test.go`: between `Infer` and `Verify`, replace the `result_ct` with `result_ct + ct_one` (encrypt `1` under the aggregated pk and add) — `Ver` should reject because the verification-slot values won't match.
- [ ] run tests — must pass before Task 9: `go test ./... && go test -tags=integration ./internal/orchestrator/...`

### Task 9: `cmd/ppiav-cli` — CLI entry points and JSON bench output

**Files:**

- Create: `cmd/ppiav-cli/main.go`
- Create: `cmd/ppiav-cli/e2e.go`
- Create: `cmd/ppiav-cli/steps.go`
- Create: `cmd/ppiav-cli/main_test.go`

- [ ] `main.go`: subcommand dispatcher using stdlib `flag` (no `cobra` — keep deps tight; the design says simple/idiomatic Go). Subcommands `e2e`, `keygen`, `encrypt-image`, `infer`, `mac` (Auth), `decrypt-result` (joint decryption), `verify-mac` (Ver). Common `--n int` flag (default 1) and `--out string` flag (default `results/phase1/<step>.json`).
- [ ] `e2e.go`: runs the full §3 protocol via `internal/orchestrator.Runner`, wrapping each method in `bench.Measure` and emitting one `bench.Run` per command invocation. README claims `go run ./cmd/ppiav-cli e2e --n 5` works — implement to match.
- [ ] `steps.go`: each per-step subcommand isolates one operation in a hot loop after a one-time setup. `keygen` drives only Stage 2 with fresh sids; `encrypt-image` reuses a single Stage-2 setup and re-encrypts a fixed image `--n` times; etc.
- [ ] image input: `e2e` and `encrypt-image` accept `--image path/to/sample.bin` (12288 little-endian float64). For Phase 1 (before `models/` exists), the CLI generates a deterministic synthetic image (e.g. `sin` over `[0, 1]` scaled into `[-1, 1]`) when `--image` is empty, and writes it as a `.bin` fixture under `results/phase1/inputs/` so reruns are reproducible.
- [ ] `main_test.go`: smoke test — run `e2e` with `--n 1` inside a `testing.T` (via direct function call, not `exec.Command`), capture the JSON output, assert the sample count matches and `Wall > 0` per stage.
- [ ] `gitignore`: append `results/phase1/inputs/` and `results/phase1/*.json` to `.gitignore` so generated JSON isn't committed by accident. Snapshot commits stay manual.
- [ ] run tests — must pass before Task 10.

### Task 10: Python `bench/` uv project — tables + plots

**Files:**

- Create: `bench/pyproject.toml`
- Create: `bench/bench/__init__.py`
- Create: `bench/bench/load.py`
- Create: `bench/bench/tables.py`
- Create: `bench/bench/plot.py`
- Create: `bench/tests/test_load.py`
- Create: `bench/tests/test_tables.py`
- Create: `bench/README.md` (≤ 30 lines)

- [ ] `pyproject.toml`: `uv`-managed project. Deps: `numpy`, `pandas`, `matplotlib`. Dev deps: `pytest`, `ruff`, `mypy`. Strict mypy config. Pin Python ≥ 3.12.
- [ ] `load.py`: `load_run(path: Path) -> Run` and `load_dir(dir: Path) -> list[Run]`. Use `pydantic` (or vanilla dataclasses + `json.loads` — pick dataclasses to stay dep-light) to parse the JSON shape emitted by `internal/bench`. Validate samples non-empty.
- [ ] `tables.py`: `python -m bench.tables <dir>` prints a Markdown table per stage with columns: stage, n, mean wall ms, p50, p95, mean heap delta MiB. Round numbers sensibly.
- [ ] `plot.py`: `python -m bench.plot <dir>` writes per-stage PNG bar plots (one PNG per stage, x = sample index, y = wall ms) into `<dir>/plots/`.
- [ ] tests: `test_load.py` round-trips a fixture JSON; `test_tables.py` asserts table output contains every stage name. Fixtures committed under `bench/tests/fixtures/`.
- [ ] lint/type/test gate: `cd bench && uv run pytest && uv run ruff check . && uv run mypy bench tests` — all green before Task 11.
- [ ] run tests — must pass before Task 11.

### Task 11: Phase 1 noise validation (build-tagged) and phase-1 acceptance run

**Files:**

- Create: `internal/protocol/noise_test.go`
- Create: `results/phase1/.gitkeep` (already exists; verify)
- Modify: `README.md` (update phase-1 status section to match reality if it drifted)

- [ ] `noise_test.go` (build tag `//go:build noise`): run 100 fresh keygen + encrypt + `x²` + auth + joint-decrypt cycles; compute the empirical std of `P[i]·Δ − v[i]` across all `S` slots, and of `P[i]·Δ − P[j*]·Δ` across all non-`S` slot pairs. Assert both stds are `< ε / 3` (Gaussian-tail safety margin from §`ε and σ_flood`). Asserts that the documented constants hold against the implemented stack.
- [ ] run `go run ./cmd/ppiav-cli e2e --n 5` and the per-step commands per README. Verify JSON files materialise in `results/phase1/`.
- [ ] run `cd bench && uv run python -m bench.tables ../results/phase1` and visually inspect the table.
- [ ] run `cd bench && uv run python -m bench.plot ../results/phase1` and visually inspect the plots.
- [ ] update `README.md` quick-start commands if any drifted (e.g. flag names, paths).
- [ ] run full Go test suite incl. integration + noise tag: `go test ./... && go test -tags=integration ./... && go test -tags=noise ./internal/protocol/...`
- [ ] run tests — Phase 1 must be green before Task 12 (Phase 2 begins).

### Task 12: `models/` Python uv project — C3AE training pipeline

**Files:**

- Create: `models/pyproject.toml`
- Create: `models/models/__init__.py`
- Create: `models/models/data.py`
- Create: `models/models/train.py`
- Create: `models/models/compile.py`
- Create: `models/models/prepare_samples.py`
- Create: `models/tests/test_data.py`
- Create: `models/tests/test_prepare_samples.py`
- Create: `models/README.md` (≤ 50 lines)

The model code is a clean rewrite — DESIGN.md is explicit that we do **not** copy from `~/Dev/orion/examples/c3ae-demo/` or thesis experiments. Reference them for shape only.

- [ ] `pyproject.toml`: uv project. Deps include `torch` (or `tensorflow` — pick whichever Orion's compiler accepts as input; verify by reading the Orion frontend before locking the choice), `pillow`, `numpy`. Dev: `pytest`, `ruff`, `mypy`.
- [ ] ⚠️ open question to resolve at start of this task: confirm the framework Orion's `c3ae-demo` consumes (PyTorch ONNX export vs. native). Read `~/Dev/orion/examples/c3ae-demo/models/` for the answer; do not copy code. Record the answer in `models/README.md`.
- [ ] `data.py`: UTKFace loader — accepts an unpacked UTKFace dataset path, yields `(image, age)`. No download logic (manual prep documented in `models/README.md`). Binarise age at the trained threshold to produce a `±1` label.
- [ ] `train.py`: C3AE binary-classifier training script. CLI: `python -m models.train --data <path> --threshold 25 --epochs N --out <ckpt>`. The threshold goes into the head and is baked into the trained model.
- [ ] `compile.py`: `python -m models.compile --ckpt <ckpt> --out <orion-out-dir>` — invokes the Orion compiler frontend on the trained checkpoint, producing the compiled circuit + manifest. Wraps Orion's Python entry point; don't reimplement compilation.
- [ ] `prepare_samples.py`: implements the 5-step preprocessing exactly per DESIGN.md §`internal/vclient` and writes 12288-float64 `.bin` files. CLI: `python -m models.prepare_samples --in <image> --out <bin>`. Also a `--positive`/`--negative` mode that samples N images on each side of the threshold for the bench harness.
- [ ] tests: `test_prepare_samples.py` asserts the 5 steps produce the expected output on a fixed PNG fixture, byte-for-byte matching a recorded `.bin` golden file (regenerate the golden once and commit it). `test_data.py` smoke-tests the UTKFace loader on a 3-image fixture.
- [ ] gate: `cd models && uv run pytest && uv run ruff check . && uv run mypy models tests` — all green before Task 13.
- [ ] **acceptance for this task**: produce one trained checkpoint, one compiled Orion artifact, and at least one `positive.bin` + one `negative.bin` sample. Commit the manifest JSON (not the binary weights — gitignore those) under `models/artifacts/manifest.json` so the Go side has a stable input. Document the dataset path users must point at in `models/README.md`.
- [ ] run tests — must pass before Task 13.

### Task 13: extend `internal/protocol/params.go` with the Orion manifest source

**Files:**

- Modify: `internal/protocol/params.go`
- Create: `internal/protocol/orion_params.go`
- Create: `internal/protocol/orion_params_test.go`

- [ ] `orion_params.go`: `LoadOrionParams(manifestPath string) (Params, error)`. Read the manifest JSON produced by Task 12, extract `LogN`, `LogQ`, `LogP`, `LogDefaultScale`, `RingType`, plus the per-circuit `InputLevel` and rotation index set. Build `Params` with the same `Authenticator.Lambda` defaults but with the union of rotation indices `[1..λ) ∪ orion_rotations` exposed via a `RotationIndices()` method.
- [ ] modify `internal/protocol/params.go` `Defaults()` to remain Phase-1 callable; do not break callers from Task 2.
- [ ] tests: `orion_params_test.go` parses a committed fixture manifest under `internal/protocol/testdata/orion_manifest.json` and asserts the loaded `Params` matches the documented C3AE shape (`LogN=16`, `LogQ` length 16, etc.). Round-trip the `RotationIndices` and assert `[1..127]` is a subset.
- [ ] update `CanonicalRotationIndices` (Task 2) to a `Params.RotationIndices() []int` method that returns the full union.
- [ ] propagate the change: VClient (`GenGaloisShares`) and VAgent (`GenGaloisShares` + `AggregateGaloisShares`) iterate `params.RotationIndices()` instead of `CanonicalRotationIndices(lambda)`. Update Task-5 and Task-6 tests accordingly.
- [ ] run tests — must pass before Task 14: `go test ./... && go test -tags=integration ./...`

### Task 14: `internal/vservice/infer.go` — swap `x²` for Orion C3AE

**Files:**

- Modify: `internal/vservice/infer.go`
- Create: `internal/vservice/orion.go`
- Create: `internal/vservice/orion_test.go`

- [ ] `orion.go`: load the compiled Orion circuit at `Service` construction time via the Orion Go runtime (or per-session if Orion's runtime requires session-tied state; verify before coding). `Service` gains an `*orion.Model` field built from the manifest path passed to `New(params, orionDir)`. `New(params)` becomes `New(params, opts ...Option)` with a functional-options pattern so Phase-1 callers (CLI test path) can omit Orion.
- [ ] modify `infer.go`: `Infer` dispatches on whether `Service` has an Orion model loaded. Phase-1 path (`x²`) stays for the `keygen`-only and unit-test code paths; Phase-2 path runs the Orion circuit via `model.InferEncrypted(inputCt) → outputCt`.
- [ ] `orion_test.go`: requires the Task-12 artifacts. Load a fixed `positive.bin`, encrypt under multi-party pk, run `Infer`, decrypt with `sk_c + sk_a`, assert the recovered logit has the expected sign. Same for `negative.bin`. Use a build tag `//go:build orion` so the unit suite stays runnable without model artifacts.
- [ ] update `internal/orchestrator.NewRunner` to accept an `OrionPath` option; CLI `e2e` flag `--orion <dir>` plumbs through.
- [ ] update `internal/orchestrator/integration_test.go` to gain a Phase-2 variant (build tag `//go:build integration && orion`) running the full protocol against the C3AE artifact.
- [ ] run tests — must pass before Task 15.

### Task 15: CLI Phase-2 driver + bench numbers

**Files:**

- Modify: `cmd/ppiav-cli/main.go`
- Modify: `cmd/ppiav-cli/e2e.go`
- Modify: `cmd/ppiav-cli/steps.go`
- Modify: `cmd/ppiav-cli/main_test.go`
- Modify: `README.md`

- [ ] add a `--orion <dir>` flag to every subcommand. When set, output JSON lands under `results/phase2/` not `results/phase1/`.
- [ ] add a `--image positive.bin|negative.bin|<path>` mode that resolves the canonical Task-12 outputs by name. Reject missing files clearly.
- [ ] update `main_test.go` smoke test to cover the Phase-2 path (skipped via build tag if model artifacts missing).
- [ ] update `README.md` quick-start commands to add the Phase-2 variants alongside the Phase-1 ones.
- [ ] run tests — must pass before Task 16.

### Task 16: Verify acceptance criteria

- [ ] verify every requirement from Overview is implemented for Phase 1 and Phase 2.
- [ ] verify Failure-Mode F1 (Ver returns false) and F2 (malformed input) tests exist and pass.
- [ ] verify Failure-Mode F3 (inference error) by injecting a deliberate error in `vservice.Infer` from a test and asserting `Reject` propagates.
- [ ] verify F4a/F4b are documented as deferred (HTTP-only) — leave a TODO in `README.md` linking to DESIGN.md §`Failure modes`.
- [ ] run full Go test suite incl. integration + noise + orion tags: `go test ./... && go test -tags=integration ./... && go test -tags=noise ./internal/protocol/... && go test -tags=integration,orion ./internal/orchestrator/... && go test -tags=orion ./internal/vservice/...`
- [ ] run Python suites: `cd bench && uv run pytest && uv run ruff check . && uv run mypy bench tests` ; same in `models/`.
- [ ] run `go vet ./...` and confirm no warnings.
- [ ] verify all README quick-start commands work copy-paste.
- [ ] take a snapshot bench run on the dev machine for Phase 1 and Phase 2; commit the JSON under `results/phase1/snapshot/` and `results/phase2/snapshot/` (this _is_ a deliberate commit of generated output — note its provenance in the commit message).

### Task 17: Update documentation and close out

- [ ] update `CLAUDE.md` "Status" line to reflect Phase 1+2 completion.
- [ ] update `CLAUDE.md` Implementation Phases checklist if it tracks phase status.
- [ ] confirm `README.md` accurately documents what works.
- [ ] move this plan to `docs/plans/completed/` (run `mkdir -p docs/plans/completed`).
- [ ] commit the move atomically as a separate commit.

---

## Post-Completion

_Items requiring manual intervention or external systems — no checkboxes, informational only._

**Manual verification**

- visually inspect the bench plots and Markdown tables for outliers — pre-warmup transients or GC spikes that should be excluded.
- cross-check the noise-test empirical σ values against the §`Noise magnitude` analytic predictions; if they diverge significantly, file a follow-up to recalibrate `ε`/`σ_flood`.
- sanity-check the C3AE compiled output by running Orion's own demo against the same checkpoint and confirming the logit values match within float-precision tolerance.

**External system updates**

- none. This plan does not touch any deployment system or consuming project — Phase 3 is the first time HTTP services or browser SPAs appear, and that is out of scope here.

**Follow-up plans (not part of this plan, but to file once this lands)**

- Phase 3: HTTP services + browser SPAs + WASM bridge (`web/ppiav`).
- Phase 4: lattigo-hierkeys integration (`gks_master` wire format).
- Noise-calibration replan: deferred per DESIGN.md until all four phases have landed; replan after Phase 4 with `σ_B` measurements from every phase.
