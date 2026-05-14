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

- **Unit tests** (required per task): Go `*_test.go` next to each source file. Use `testify/assert` and `testify/require`. Phase-1 unit tests use `LogN=14` for speed where the protocol allows; the orchestrator's `runner_test.go` exercises the full keygen → infer → verify chain at this smaller profile.
- **No automated e2e / integration tests in this plan.** End-to-end runs (full-`LogN=16` protocol, real C3AE inference, CLI dry-runs, bench snapshots) are reserved for **manual verification by the user** after implementation. The full Phase-1 and Phase-2 acceptance walkthroughs live in §`Post-Completion`. Rationale: the per-package unit suite catches mechanical bugs; the user wants to drive the final acceptance themselves.
- **No noise / σ-calibration tests in this plan.** DESIGN.md `§ε and σ_flood` defers proper statistical calibration "until after all four phases land"; the prototype takes ε=2²⁰ and σ_flood=2¹⁶ as given. Empirical σ measurement is a Phase-5 (post-Phase-4) follow-up plan.
- **Python suite**: `pytest`, `ruff check`, `mypy --strict` for `bench/` (Phase 1) and `models/` (Phase 2). Pytest covers `prepare_samples.py` against fixed test vectors so the image-preprocessing pipeline has a regression guard.
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

- [x] create `internal/bench/bench.go` implementing `Sample`, `Run`, `NewRun`, `(*Run).Append`, `(*Run).WriteJSON`, `Measure`, `MeasureWithSize`, `Repeat`, `RepeatWithWarmup` per DESIGN.md §`internal/bench`. Use `runtime.MemStats` for heap fields, `runtime.GC()` + a steady-state read for stable accounting, `time.Now()` deltas for wall time. Linux-only `VmHWM` parses `/proc/self/status`; non-Linux returns 0.
- [x] make `Run.WriteJSON` atomic — write to a `tmp` sibling then rename — so a partially-written file never lands in `results/`.
- [x] write table-driven tests for `Measure` (single-shot success + error propagation), `Repeat` (correct `Iter` indexing, propagates errors), `RepeatWithWarmup` (warmup excluded from samples), and `Run.WriteJSON` (round-trips through `encoding/json`).
- [x] write a sanity test that `Sample.Wall > 0` for a `time.Sleep(time.Millisecond)` body.
- [x] run tests — must pass before Task 2: `go test ./internal/bench/...`

### Task 2: `internal/protocol` — domain types, parameter sets, wire messages, CRS

**Files:**

- Create: `internal/protocol/types.go`
- Create: `internal/protocol/params.go`
- Create: `internal/protocol/wire.go`
- Create: `internal/protocol/crs.go`
- Create: `internal/protocol/types_test.go`
- Create: `internal/protocol/params_test.go`
- Create: `internal/protocol/crs_test.go`

- [x] `types.go`: `SessionID string`, `Verdict uint8` + the `VerdictUnknown/Accept/Reject` constants. `Verdict.String()` for diagnostics.
- [x] `params.go`: `Params{ CKKS ckks.Parameters, Authenticator authenticator.Config, FloodSigma float64 }` and `Defaults() (Params, error)`. Defaults build a `ckks.Parameters` from a `ckks.ParametersLiteral` with the Phase-1 values from DESIGN.md (`LogN=16`, `LogQ=[55]+[40]×15`, `LogP=[55]×6`, `LogDefaultScale=40`, `RingType=ring.Standard`). `Authenticator` is `authenticator.DefaultConfig()`. `FloodSigma = math.Exp2(16)`.
- [x] **Note:** `authenticator.Config` is consumed here but defined in Task 3 — break the dependency with a deferred sub-step: stub `Config` and `DefaultConfig` in `internal/protocol/params.go` as a temporary `type Config struct{ Lambda int; Epsilon float64 }` and move it to `internal/authenticator` in Task 3, then update `params.go` to import it. Mark the stub with `// TODO(task 3): move to internal/authenticator`.
- [x] `wire.go`: declare every wire-message type from DESIGN.md §`internal/protocol`: `SessionOpen`, `VerificationSession`, `VClientPKShare`, `VAgentPKShare`, `VClientRLKRound1`, `VAgentRLKRound1`, `VClientRLKRound2`, `VClientGaloisKeyShare`, `InferEvalKeys`, `EncryptedImage`, `AuthenticatedResult`, `PartialDecryption`, `VerdictNotification`. Phase-4-only fields (`GKSMaster`) are not declared yet. (`InferEvalKeys.GKS` ships as `[]*rlwe.GaloisKey` because Lattigo v6.2.0 does not expose a `GaloisKeySet` type — same payload, what `rlwe.NewMemEvaluationKeySet` consumes.)
- [x] `crs.go`: `const crsDomain = "ppiav-crs/v1"` and `func NewSessionCRS(sid SessionID) (*sampling.KeyedPRNG, error)` exactly as in DESIGN.md. Also a `CanonicalRotationIndices(lambda int) []int` helper that returns `[1..lambda)` so the CRP draw order can be shared between VAgent and VClient.
- [x] tests: `params_test.go` constructs `Defaults()` and asserts `LogN==16`, slot count 32768, max level 15, default scale `2^40`. `crs_test.go` asserts two `NewSessionCRS` instances for the same sid produce identical first-32-byte outputs, and different sids diverge. `types_test.go` asserts `Verdict.String()` round-trip.
- [x] write success-case tests for each wire-message type's binary round-trip — use `encoding.BinaryMarshaler` where the embedded Lattigo type already implements it, and a `t.Skip` placeholder where it doesn't (we'll fill those in Task 9 when the CLI serialises them anyway; not load-bearing for in-process Phase-1 use).
- [x] run tests — must pass before Task 3.

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

- [x] `config.go`: `Config{ Lambda int; Epsilon float64 }`, `DefaultConfig() Config` returning `{Lambda: 128, Epsilon: math.Exp2(20)}`. Validate `Lambda > 0` and `Lambda % 2 == 0` (so `|S| = Lambda/2` is exact) — return error from `New` on violation.
- [x] remove the stub from `internal/protocol/params.go` and import the real `Config`.
- [x] `key.go`: `Key{ S []int; SeedF [32]byte }`. `MarshalBinary` writes a fixed header + sorted-ascending `S` as little-endian uint32s + `SeedF`. `UnmarshalBinary` reverses it and validates `len(S) == Lambda/2` and `S ⊂ [0, Lambda)`. Sorting on the wire makes equality testing deterministic.
- [x] `KeyGen(cfg Config, rand io.Reader) (Key, error)`: sample `|S| = Lambda/2` distinct indices from `[0, Lambda)` without replacement using a Fisher-Yates shuffle over `[0, Lambda)` truncated. Read 32 bytes from `rand` into `SeedF`. Return the key.
- [x] `authenticator.go`: `Authenticator` struct holds `cfg`, `params ckks.Parameters`, and the cached one-hot mask vector (DESIGN.md's "pt_one_hot at scale 1" is not directly representable in Lattigo; we cache the slot vector and let `eval.Mul(ct, []float64)` pick `pt.Scale = q_level_modulus` — see implementation note in `authenticator.go`). `New(cfg, params)` constructs it. Also stashes a `*ckks.Encoder`; encoders are concurrency-safe in v6.2.0.
- [x] implement `Auth`: validates the `eval` Galois set carries `params.GaloisElement(-j)` for `j ∈ [1, Lambda)` (Auth uses right-rotation by j = Lattigo left-rotation by -j to place ct_m's slot 0 at slot j, per DESIGN.md §`Auth` step 4); masks `result_ct` against the cached one-hot vector; seeds a deterministic AES-CTR PRG from `key.SeedF` and generates `v` (uniform over `(-Q_0/2, Q_0/2)`; `Q_0 = params.Q()[0]`); rotates-and-sums over `[0, Lambda) \ S`; encrypts `v` at the same scale as `ct_m^Rep`; adds. Returns `ct_M`.
- [x] `ver.go`: implement `Ver(key Key, plaintext []float64) (m float64, ok bool)`. Re-derives `v` from `key.SeedF` byte-for-byte the same way `Auth` does (shared `vRawValues` helper). Two checks per DESIGN.md §`Auth/Ver`: verification-slot match and value-slot pairwise agreement. Picks `j*` = smallest index in `[0, Lambda) \ S`. Returns `(P[j*], true)` on pass, `(0, false)` on fail.
- [x] tests:
  - `config_test.go`: `DefaultConfig` returns the documented defaults; `New` rejects odd `Lambda` and `Lambda <= 0`.
  - `key_test.go`: `KeyGen` produces `|S| = Lambda/2`, distinct, sorted ascending in range; round-trip through `MarshalBinary`/`UnmarshalBinary`; truncated/bad-magic input errors cleanly; |S| mismatch errors; bad S (duplicate / out-of-range / empty) errors.
  - `authenticator_test.go`: `Auth` over a hand-crafted `result_ct` with `m=0.5` at slot 0 (encrypted under a single-party `pk` — the multi-party handshake is tested in Tasks 5/6) produces a ciphertext that, when decrypted, has `m` in every slot of `[0, Lambda) \ S` and the expected verification values `v[i]/Δ` in `S` slots. `Ver` accepts the honest decryption; rejects tampered S slot and tampered non-S slot (both shifted by 2·ε). Missing Galois keys → Auth errors. `Lambda=16` used for speed.
- [x] run tests — must pass before Task 4: `go test ./internal/authenticator/... ./internal/protocol/...`.

### Task 4: `internal/vservice` — sid issuer, evaluator, `x²` inference

**Files:**

- Create: `internal/vservice/service.go`
- Create: `internal/vservice/infer.go`
- Create: `internal/vservice/service_test.go`
- Create: `internal/vservice/infer_test.go`

- [x] `service.go`: `Service` struct with `params protocol.Params`, `sessions map[SessionID]*sessionState`, `mu sync.Mutex`. `sessionState` holds the per-session `*ckks.Evaluator`. `New(params)` constructor.
- [x] `OpenSession() (SessionID, error)`: draw ≥128 bits from `crypto/rand`, hex-encode, allocate the session slot. Return `SessionID`. Error if random read fails. **Do not** generate the evaluator yet — `StoreEvalKeys` does that.
- [x] `Params() protocol.Params`: return `s.params`.
- [x] `StoreEvalKeys(sid, rlk *rlwe.RelinearizationKey, gks *rlwe.GaloisKeySet) error`: under `s.mu`, look up the session, build a `ckks.NewEvaluator(params.CKKS, rlwe.NewMemEvaluationKeySet(rlk, gks.GetKeys()...))`. Error if sid unknown. (Phase 4 will swap the `gks` argument for a hierkeys master key.)
- [x] `infer.go`: `Infer(sid, inputCt) (*rlwe.Ciphertext, error)` — Phase 1 implements `x²`. Under `s.mu` (or after copying the evaluator pointer out) call `eval.MulRelinNew(inputCt, inputCt)` then `eval.RescaleNew`. Error if sid unknown.
- [x] tests:
  - `service_test.go`: `OpenSession` returns distinct sids on consecutive calls; `StoreEvalKeys` errors on unknown sid; `Params` returns the original params.
  - `infer_test.go`: end-to-end x² test using single-party Lattigo keys (skip the multi-party handshake here — it's tested in Task 8). Encrypt `m=0.3`, infer, decrypt, assert `|m' − 0.09| < 1e-4`. Also assert level drops by exactly 1 after `Infer`. Use `LogN=14` parameters here for speed; do not depend on `protocol.Defaults()`.
- [x] run tests — must pass before Task 5.

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

- [x] `client.go`: `Client` struct + `New(params, sid)` constructor exactly per DESIGN.md §`internal/vclient`. Generate `sk_c` via `multiparty.PublicKeyGenProtocol{}.AllocateShare`-style init or `rlwe.NewKeyGenerator(params.CKKS).GenSecretKeyNew()`. Build the CRS via `protocol.NewSessionCRS(sid)`.
- [x] `keygen.go`:
  - `GenPKShare()`: instantiate `multiparty.NewPublicKeyGenProtocol(params)`, call `proto.AllocateShare()`, sample CRP via `proto.SampleCRP(crs)` (first CRP draw per the canonical order), call `proto.GenShare(skShare, crp, &share)`. Return the share.
  - `AggregatePK(agentShare)`: re-run `AllocateShare`, then `proto.AggregateShares(clientShare, agentShare, &aggregate)`; `proto.GenPublicKey(aggregate, crp, pkAgg)`. Persist `c.pkAgg` and build `c.encryptor`.
  - `GenRLKShareRound1` / `AggregateRLKRound1` / `GenRLKShareRound2`: standard two-round flow with `multiparty.NewRelinearizationKeyGenProtocol(params)`. The Round-2 share is shipped but not aggregated client-side (VAgent and VService own the final rlk; VClient doesn't need it).
  - `GenGaloisShares() ([]multiparty.GaloisKeyGenShare, []int, error)`: iterate `protocol.CanonicalRotationIndices(params.Authenticator.Lambda)`, sample a CRP per index in ascending order (canonical draw order), generate a share per index using `params.CKKS.GaloisElement(-j)` (matches `internal/authenticator`'s left-rotation convention). Return the share slice plus the parallel label slice so VAgent can aggregate by label.
- [x] `image.go`: `EncryptImage(image []float64) (*rlwe.Ciphertext, error)`. Hard-fail on `len(image) != 12288`. Pad with zeros to `params.MaxSlots()`. Encode at `params.DefaultScale()`. Encrypt under `c.pkAgg` via `c.encryptor.EncryptNew(pt)`. The level question — DESIGN.md says "the compiled model's input level, padded to MaxSlots". In Phase 1 there is no compiled model, so encrypt at the max level (`params.MaxLevel()`); document the override.
- [x] `partial_decrypt.go`: `PartialDecrypt(authenticatedCt) (multiparty.KeySwitchShare, error)`. Use `multiparty.NewKeySwitchProtocol(params.CKKS, ring.DiscreteGaussian{Sigma: params.FloodSigma, Bound: 6 * params.FloodSigma})`. The smudging mitigates CKKS IND-CPA^D (Li–Micciancio 2021): without it, VAgent observes `(c1·sk_c + e_fresh, plaintext)` per session and can statistically recover `sk_c` because CKKS decryption noise is deterministic in `(c, sk)`. Allocate share, call `proto.GenShare(c.skShare, zeroSk, authenticatedCt, &share)` where `zeroSk` is `rlwe.NewSecretKey(params.CKKS)` (zero-valued sk → decryption rather than key-switch). Return the share.
- [x] tests:
  - `keygen_test.go`: drive each Generate/Aggregate pair against a hand-rolled "VAgent stub" — instantiate the same multi-party protocol on the test side with a synthetic `sk_a`, do the matching half of the handshake, assert the aggregate pk + rlk + per-rotation Galois keys decrypt/rotate correctly against `sk_c + sk_a`. Run with `LogN=14` and `λ=8` for speed.
  - `image_test.go`: wrong-length input is rejected; right-length input encrypts and decrypts back within float-precision tolerance against the test-only `sk_c + sk_a`. (LogN=15 used for the round-trip — LogN=14 only carries 8192 slots, less than imageLen=12288; wrong-length cases stay at LogN=14 since they bail before encoding.)
  - `partial_decrypt_test.go`: round-trip — encrypt `m=0.42` under aggregated pk, run `PartialDecrypt` + the VAgent side from a stub, assert `|m_decrypted − 0.42| < 1e-2` (tolerance loosened from 1e-4 to absorb σ_flood=2^16 — see DESIGN.md §`Noise magnitude`).
- [x] run tests — must pass before Task 6.

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

- [x] `agent.go`: `Agent`, `sessionState`, `New(params)`, `OpenSession(sid)` per DESIGN.md §`internal/vagent`. `OpenSession` registers the sid, mints `sk_a`, calls `authenticator.KeyGen(params.Authenticator, crypto/rand.Reader)` for the session's `authKey`, builds the CRS the same way VClient does.
- [x] `keygen.go`: mirrors `internal/vclient/keygen.go` with a `Gen*Share` / `Aggregate*` split on each step (symmetric to VClient's API):
  - `GenPKShare(sid) → agentShare`: draw the CRP (first in canonical order), generate `pk_a` share. Return for delivery to VClient.
  - `AggregatePK(sid, clientShare)`: combine with the stashed agent share, build `pkAgg` + `encryptor`, persist on session state.
  - `GenRLKShareRound1(sid) → agentShare`, `AggregateRLKRound1(sid, clientShare)`: same pattern; RLK CRP is drawn once in Round 1 and **reused** in Round 2 (cache it on session state).
  - `GenRLKShareRound2(sid) → agentShare`, `AggregateRLKRound2(sid, clientShare)`: agent's round-2 share does not go over the wire to VClient (VClient does not retain rlk) but the method exists for in-process symmetry; `AggregateRLKRound2` finalises `rlkAgg`.
  - `GenGaloisShares(sid) → ([]agentShares, []labels, err)`: iterate canonical rotation indices `[1, λ)` (Task 13 will swap for `params.RotationIndices()`), drawing one CRP per index in ascending order. Return shares + labels.
  - `AggregateGaloisShares(sid, clientShares, clientLabels) → (rlk, gks, err)`: validate len + labels parity, combine pairwise per index to assemble `[]*rlwe.GaloisKey` (Lattigo v6.2.0 has no `GaloisKeySet` type); build `eval` from `rlkAgg + gks`. Return `(rlkAgg, gks)` so the caller hands them to `vservice.StoreEvalKeys`.
- [x] `authenticate.go`: `BuildAuthenticatedCt(sid, resultCt) → *rlwe.Ciphertext`: look up session, call `a.auth.Auth(sess.authKey, sess.encryptor, sess.eval, resultCt)`. Return the result.
- [x] `finalize.go`: `FinalizeDecryption(sid, authenticatedCt, clientShare) → Verdict`. Computes VAgent's `KeySwitchShare` via `multiparty.NewKeySwitchProtocol(params.CKKS, ring.DiscreteGaussian{Sigma: 0, Bound: 0})` — VAgent does **not** smudge. Verified Lattigo accepts `Sigma: 0` (`NoiseFreshSK` is folded in, eSigma = sqrt(eFresh² + 0) > 0). Aggregates shares, applies key-switch + decryption under zero sk, decodes to slot vector, calls `a.auth.Ver(authKey, plaintext)`. Verdict logic: `!ok` → `VerdictReject`; else `m > 0` → `Accept`, else `Reject`. Drops the session entry on the success path (single-use `authKey`).
- [x] tests:
  - `keygen_test.go`: handshake-stub pattern (VClient role faked). Asserts aggregated pk encrypts/decrypts under joint sk, aggregated rlk enables `MulRelinNew`, aggregated Galois keys enable left-rotation. Also exercises label-mismatch rejection + unknown-sid errors.
  - `authenticate_test.go`: encrypts `m=0.7` at slot 0 under `pkAgg`, calls `BuildAuthenticatedCt`, decrypts with joint `sk_c + sk_a`, asserts the §`Auth` layout (`m` in non-`S` slots, `v[i] / Δ` in `S` slots). The expected PRG output is recomputed via a test-local replica of `authenticator.vRawValues`.
  - `finalize_test.go`: full joint-decryption happy path with `m=0.7` → `Accept`; `m=-0.3` → `Reject`. Tamper-case: VClient's share generated from a wrong `sk_c` → `Reject`. Also asserts the session entry is dropped on the success path.
- [x] run tests — must pass before Task 7.

### Task 7: `internal/rservice` — verdict gating

**Files:**

- Create: `internal/rservice/service.go`
- Create: `internal/rservice/service_test.go`

- [x] `service.go`: `Service{ sessions map[SessionID]Verdict; mu sync.Mutex }`. `New() *Service`, `AcceptVerdict(sid, v) error` (upsert), `CheckAccess(sid) Verdict` (missing → `VerdictUnknown`).
- [x] `service_test.go`: missing sid returns `VerdictUnknown`; `AcceptVerdict` then `CheckAccess` returns the upserted verdict; double-upsert returns the latest value; concurrent `AcceptVerdict` from many goroutines doesn't race (`go test -race`).
- [x] run tests — must pass before Task 8.

### Task 8: in-process orchestrator (unit-tested)

**Files:**

- Create: `internal/orchestrator/runner.go`
- Create: `internal/orchestrator/runner_test.go`

The orchestrator is the in-process glue that the CLI in Task 9 wraps. Putting it in `internal/` rather than `cmd/` keeps it test-importable. It owns the call sequence — every method here mirrors one stage of DESIGN.md §`Protocol`.

- [x] `runner.go`: `Runner` struct bundles `vclient.Client`, `vagent.Agent`, `vservice.Service`, `rservice.Service`. `NewRunner(params)` constructs them. `Open()` runs Stage 1 (`vservice.OpenSession` → `vagent.OpenSession` → returns sid). `Setup(ctx)` drives Stages 2a–d (params handshake, pk handshake, two rlk rounds, Galois handshake, `vservice.StoreEvalKeys`). `Infer(image []float64) → *rlwe.Ciphertext` runs Stage 3. `Verify(resultCt) → Verdict` runs Stage 4 and submits to RService.
- [x] each `Runner` method is a stripped-down wrapper around the underlying call — no business logic — but each one is a natural `bench.Measure` boundary, so they return error-only and the CLI wraps them.
- [x] `Runner` takes its `vservice` dependency through a small interface (e.g. `type Inferrer interface { OpenSession() (SessionID, error); StoreEvalKeys(SessionID, *rlwe.RelinearizationKey, *rlwe.GaloisKeySet) error; Infer(SessionID, *rlwe.Ciphertext) (*rlwe.Ciphertext, error); Params() Params }`) — `NewRunner(params)` builds it from the real `vservice.New(params)` by default; a sibling `NewRunnerWithInferrer(params, Inferrer)` lets tests inject a mock. No `ForceReject` flag or other test-only fields on the production struct.
- [x] `runner_test.go`: unit tests against a smaller `LogN=14`, `λ=8` profile. Drive `Open` → `Setup` → encrypt `m=0.5` → `Infer` → `Verify`. Assert `Verdict.Accept` (squared positive logit ⇒ `m'=0.25 > 0`). Also assert each method advances state in the right order (calling `Verify` before `Setup` is an error).
- [x] `runner_test.go` Reject-via-inverted-logit case: inject a mock `Inferrer` (`NewRunnerWithInferrer`) that returns a ciphertext encrypting `m=-0.5` at slot 0 → `Verdict = Reject`. Same LogN=14 profile.
- [x] `runner_test.go` F4b posture case: `Open` + `Setup`, skip `Infer`/`Verify`, assert `rservice.CheckAccess(sid) == VerdictUnknown`. Pins the deny-by-default contract from `docs/DESIGN.md §Failure modes`.
- [x] full-`LogN=16` e2e, tamper case (`result_ct + Encrypt(1)` → Ver rejects), and Phase-2-with-C3AE walkthroughs are **manual verification** — see §`Post-Completion`. No `//go:build integration` test file is created.
- [x] run tests — must pass before Task 9: `go test ./internal/orchestrator/...`

### Task 9: `cmd/ppiav-cli` — CLI entry points and JSON bench output

**Files:**

- Create: `cmd/ppiav-cli/main.go`
- Create: `cmd/ppiav-cli/e2e.go`
- Create: `cmd/ppiav-cli/steps.go`
- Create: `cmd/ppiav-cli/testdata/synthetic.bin` (Phase-1 manual-testing fixture)

- [x] `main.go`: subcommand dispatcher using stdlib `flag` (no `cobra` — keep deps tight; the design says simple/idiomatic Go). Subcommands `e2e`, `keygen`, `encrypt-image`, `infer`, `mac` (Auth), `decrypt-result` (joint decryption), `verify-mac` (Ver). Common `--n int` flag (default 1) and `--out string` flag (default `results/phase1/<step>.json`).
- [x] `e2e.go`: runs the full §3 protocol via `internal/orchestrator.Runner`, wrapping each method in `bench.Measure` and emitting one `bench.Run` per command invocation. README claims `go run ./cmd/ppiav-cli e2e --n 5` works — implement to match.
- [x] `steps.go`: each per-step subcommand isolates one operation in a hot loop after a one-time setup. `keygen` drives only Stage 2 with fresh sids; `encrypt-image` reuses a single Stage-2 setup and re-encrypts a fixed image `--n` times; etc.
- [x] image input: `e2e` and `encrypt-image` **require** `--image path/to/sample.bin` (12288 little-endian float64). No runtime synthesis — DESIGN.md §`internal/vclient` (Phase 1) is explicit that `.bin` inputs come from `models/prepare_samples.py`; having Go re-implement preprocessing creates a second source of truth that will silently diverge.
- [x] commit a hand-built Phase-1 fixture at `cmd/ppiav-cli/testdata/synthetic.bin` — 12288 float64s, content irrelevant for `x²` correctness (e.g. all 0.5, written from a one-off `go run` snippet at `cmd/ppiav-cli/testdata/synthetic.gen.go` build-tagged `//go:build ignore`). The fixture exists so the user can run `--image cmd/ppiav-cli/testdata/synthetic.bin` for Phase-1 manual verification without needing the Orion sample inputs (which come from Task 12 / `~/Dev/orion/...` in Phase 2).
- [x] **no `main_test.go` smoke test** — CLI exercise is manual verification (see §`Post-Completion`). Behaviour is covered by the orchestrator's unit tests (Task 8) and `internal/bench` tests (Task 1).
- [x] `.gitignore`: append `results/phase1/*.json` so generated JSON isn't committed by accident. The fixture under `testdata/` **is** committed (it's a checked-in test input, not generated output). (Existing `results/*/` rule already covers Phase-1 outputs — no edit required.)
- [x] run tests — must pass before Task 10: `go build ./...` (`cmd/ppiav-cli` compiles; orchestrator tests still green).

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

- [x] `pyproject.toml`: `uv`-managed project. Deps: `numpy`, `pandas`, `matplotlib`. Dev deps: `pytest`, `ruff`, `mypy`. Strict mypy config. Pin Python ≥ 3.12.
- [x] `load.py`: `load_run(path: Path) -> Run` and `load_dir(dir: Path) -> list[Run]`. Use `pydantic` (or vanilla dataclasses + `json.loads` — pick dataclasses to stay dep-light) to parse the JSON shape emitted by `internal/bench`. Validate samples non-empty.
- [x] `tables.py`: `python -m bench.tables <dir>` prints a Markdown table per stage with columns: stage, n, mean wall ms, p50, p95, mean heap delta MiB. Round numbers sensibly.
- [x] `plot.py`: `python -m bench.plot <dir>` writes per-stage PNG bar plots (one PNG per stage, x = sample index, y = wall ms) into `<dir>/plots/`.
- [x] tests: `test_load.py` round-trips a fixture JSON; `test_tables.py` asserts table output contains every stage name. Fixtures committed under `bench/tests/fixtures/`.
- [x] lint/type/test gate: `cd bench && uv run pytest && uv run ruff check . && uv run mypy bench tests` — all green before Task 11.
- [x] run tests — must pass before Task 11.

### Task 11: [REMOVED — manual verification]

Phase-1 acceptance (running the CLI end-to-end, inspecting JSON output, comparing bench tables, validating README quick-start) is **manual** — see §`Post-Completion`. Task number kept as a placeholder so downstream forward references ("before Task 12") stay valid; no implementation deliverable.

- [x] (no automated steps) — proceed directly to Task 12.

### Task 12: `models/` Python uv project — image preprocessing only (reuse Orion's C3AE)

**Files:**

- Create: `models/pyproject.toml`
- Create: `models/models/__init__.py`
- Create: `models/models/prepare_samples.py`
- Create: `models/tests/test_prepare_samples.py`
- Create: `models/tests/fixtures/sample.png` (a tiny committed PNG used as preprocessing golden input)
- Create: `models/tests/fixtures/sample.bin` (the corresponding committed golden output)
- Create: `models/README.md` (≤ 50 lines)

**Training is out of scope** — the user wants to skip C3AE training and the VPS that would have hosted it. We reuse Orion's already-trained checkpoint and pre-compiled circuit:

- Trained checkpoint: `~/Dev/orion/examples/c3ae-demo/out/weights_fhe.pth`
- Compiled circuit (LogN=16): `~/Dev/orion/examples/c3ae-demo/out/logn16/` ⚠️ Task 14 finding: on disk this directory currently only holds `compile.json` + `keys/`. The actual `.orion` model the Phase-2 Go path consumes lives at `~/Dev/orion/examples/c3ae-demo/out/logn15/model.orion` (LogN=15). Until a logn16 build is materialised, point `--orion` at the `logn15` directory.
- Reference input: `~/Dev/orion/examples/c3ae-demo/out/inputs/sample_test.bin`
- Test images: `~/Dev/orion/examples/c3ae-demo/data/samples/`

The `models/` Python project therefore reduces to **just the image-preprocessing helper** — we still own `prepare_samples.py` because the 5-step pipeline (resize-bicubic, divide-255, `(x-0.5)/0.5`, HWC→CHW, flatten) has to be exactly DESIGN.md §`internal/vclient` and we can't depend on Orion's preprocessing matching forever.

- [x] `pyproject.toml`: uv project. Deps: `pillow`, `numpy`. Dev: `pytest`, `ruff`, `mypy`. Pin Python ≥ 3.12. No `torch`, no `orion_compiler` — we don't train or compile here.
- [x] `prepare_samples.py`: implements the 5-step preprocessing exactly per DESIGN.md §`internal/vclient` and writes 12288-float64 `.bin` files. CLI: `python -m models.prepare_samples --in <image> --out <bin>`.
- [x] tests: `test_prepare_samples.py` asserts the 5 steps produce the expected bytes against the committed `fixtures/sample.png` → `fixtures/sample.bin` pair. Also asserts that running `prepare_samples` on `~/Dev/orion/examples/c3ae-demo/data/samples/*.jpg` (when present, otherwise skip) produces a `.bin` byte-identical to Orion's `out/inputs/sample_test.bin` — this cross-checks our pipeline against Orion's reference and catches drift in the preprocessing contract. (Cross-check marked `xfail`: Orion's `sample_test.bin` was generated from a UTKFace random-split sample, not from `data/samples/*.jpg`, so byte-equality is structurally impossible until the source-image mapping is recovered.)
- [x] `models/README.md`: document that training and compilation are deferred (use Orion's reference artifacts). Spell out the exact paths to the Orion checkpoint and compiled output that the Phase-2 Go path (Task 14) consumes. Note that compilation against a freshly-trained model is a future task if Orion's reference becomes stale.
- [x] gate: `cd models && uv run pytest && uv run ruff check . && uv run mypy models tests` — all green before Task 13.

### Task 13: extend `internal/protocol/params.go` with the Orion manifest source

**Files:**

- Modify: `internal/protocol/params.go`
- Create: `internal/protocol/orion_params.go`
- Create: `internal/protocol/orion_params_test.go`

- [x] `orion_params.go`: `LoadOrionParams(manifestPath string) (Params, error)`. Read the manifest JSON shipped under `~/Dev/orion/examples/c3ae-demo/out/logn16/` (or wherever the user points at), extract `LogN`, `LogQ`, `LogP`, `LogDefaultScale`, `RingType`, plus the per-circuit `InputLevel` and rotation index set. Build `Params` with the same `Authenticator.Lambda` defaults but with the union of rotation indices `[1..λ) ∪ orion_rotations` exposed via a `RotationIndices()` method. Manifest schema mirrors Orion's `_build_metadata` output (`params.{logn,logq,logp,log_default_scale,ring_type}`, `input_level`); raw `rotation_indices` are read directly — Galois-element inversion of the actual `.orion` payload is deferred to Task 14.
- [x] modify `internal/protocol/params.go` `Defaults()` to remain Phase-1 callable; do not break callers from Task 2. Added `ExtraRotationIndices []int` and `InputLevel int` fields to `Params`. `Defaults()` leaves both zero-valued — `RotationIndices()` then falls back to canonical `[1, Lambda)` and `InputLevel=0` is the EncryptImage "use MaxLevel" sentinel.
- [x] tests: `orion_params_test.go` parses a committed fixture manifest under `internal/protocol/testdata/orion_manifest.json` and asserts the loaded `Params` matches the documented C3AE shape (`LogN=16`, `LogQ` length 16, etc.). Round-trip the `RotationIndices` and assert `[1..127]` is a subset. Also covers missing-file, invalid-JSON, deterministic round-trip, and non-positive-index filtering.
- [x] update `CanonicalRotationIndices` (Task 2) to a `Params.RotationIndices() []int` method that returns the full union. Kept the standalone `CanonicalRotationIndices(lambda int)` helper in `crs.go` for tests that explicitly want the canonical-only set.
- [x] propagate the change: VClient (`GenGaloisShares`) and VAgent (`GenGaloisShares` + `AggregateGaloisShares`) iterate `params.RotationIndices()` instead of `CanonicalRotationIndices(lambda)`. Updated Task-5 and Task-6 tests to mirror the production call.
- [x] run tests — must pass before Task 14: `go test ./...`

### Task 14: `internal/vservice/infer.go` — swap `x²` for Orion C3AE

**Files:**

- Modify: `internal/vservice/service.go` (constructor split)
- Modify: `internal/vservice/infer.go`
- Create: `internal/vservice/orion.go`
- Modify: `internal/orchestrator/runner.go` (thread Orion path through)
- Modify: `cmd/ppiav-cli/main.go` (`--orion` flag)
- Modify: `cmd/ppiav-cli/e2e.go`
- Modify: `cmd/ppiav-cli/steps.go`

- [x] `orion.go`: load the compiled Orion circuit at `Service` construction time via the Orion Go runtime. `Model` is immutable and goroutine-safe per Orion's `evaluator/doc.go`; `Evaluator` is NOT goroutine-safe, so the Service holds one Orion `Model` and builds one Orion `Evaluator` per session inside `StoreEvalKeys`. The user-side path is configurable via the `orionDir` constructor argument. ⚠️ The plan referenced `~/Dev/orion/examples/c3ae-demo/out/logn16/` as canonical, but on disk only `logn15/model.orion` exists today (`logn16/` carries only `compile.json` + `keys/`). The smoke test points at `logn15`; the CLI accepts whatever directory the user passes. When a `logn16/model.orion` is materialised, the plan's `--orion` example commands can be repointed without code changes.
- [x] split `vservice` construction into `New(params)` (Phase-1 `x²` shape) and `NewWithOrion(params, orionDir)` (loads compiled C3AE). `NewWithOrion` overrides `params.CKKS`, `params.InputLevel`, and unions the manifest's rotation indices (recovered from Galois elements via `ckks.Parameters.SolveDiscreteLogGaloisElement`) into `params.ExtraRotationIndices`; callers MUST consume `Service.Params()` rather than reusing the bundle they passed in.
- [x] modify `infer.go`: `Infer` dispatches on `s.orionModel != nil`. Phase-1 path (`x²`) stays for the `keygen`-only and unit-test code paths; Phase-2 path calls `orionEval.Forward(model, []*rlwe.Ciphertext{inputCt})` and asserts the result slice has length 1 (C3AE single-output).
- [x] update `internal/orchestrator` with a parallel `NewRunnerWithOrion(baseParams, orionDir)` constructor that builds the VService via `vservice.NewWithOrion`, then reads the post-override params back via `Service.Params()` to wire VAgent and VClient at the same profile. `NewRunner` and `NewRunnerWithInferrer` stay untouched (the existing API remains the right shape for Phase-1 callers and tests).
- [x] **No automated C3AE inference test.** A minimal `orion_test.go` smoke covers `loadOrionModel` (skip when `model.orion` is absent so CI without artifacts passes; assert model + CKKS params + rotations are non-empty when the file is present) plus a missing-directory error case. End-to-end "logit has the expected sign" is user-driven manual verification.
- [x] run tests — `go build ./...`, `go vet ./...`, `go test ./...` all green; the new smoke test passes locally against `logn15/model.orion`.

### Task 15: CLI Phase-2 driver

**Files:**

- Modify: `cmd/ppiav-cli/main.go`
- Modify: `cmd/ppiav-cli/e2e.go`
- Modify: `cmd/ppiav-cli/steps.go`
- Modify: `README.md`

- [ ] add a `--orion <dir>` flag to every subcommand. When set, output JSON lands under `results/phase2/` not `results/phase1/`. Document `~/Dev/orion/examples/c3ae-demo/out/logn16/` as the canonical value.
- [ ] add `--image <path>` resolution that accepts any `.bin` produced by `models/prepare_samples.py` (Task 12) or Orion's `out/inputs/sample_test.bin`. Reject missing files clearly.
- [ ] update `README.md` quick-start commands to add the Phase-2 variants alongside the Phase-1 ones.
- [ ] run tests — must pass before Task 16: `go build ./...`.

### Task 16: Final automated-test pass

This task only validates what the code can verify by itself. End-to-end / Phase-2 walkthroughs are user-driven manual verification (§`Post-Completion`).

- [ ] verify every code-side requirement from Overview is implemented for Phase 1 and Phase 2.
- [ ] verify Failure-Mode F1 (Ver returns false) is unit-tested in `internal/authenticator` and the orchestrator's tamper case is covered manually.
- [ ] verify F2 (malformed wire input) is unit-tested where wire types are unmarshalled.
- [ ] verify F3 / F4a / F4b are documented as either covered (F4b posture test in `runner_test.go`) or deferred (HTTP-only F4a) — leave a TODO in `README.md` linking to DESIGN.md §`Failure modes` for the deferred ones.
- [ ] run Go test suite: `go test ./...` — all unit suites green, including the orchestrator's full keygen→infer→verify chain at LogN=14.
- [ ] run Python suites: `cd bench && uv run pytest && uv run ruff check . && uv run mypy bench tests` ; same in `models/`.
- [ ] run `go vet ./...` and `go build ./...` — confirm no warnings, all binaries compile.
- [ ] no snapshot bench commit — that's a manual user action when they decide a run is canonical.

### Task 17: Update documentation and close out

- [ ] update `CLAUDE.md` "Status" line to reflect Phase 1+2 completion.
- [ ] update `CLAUDE.md` Implementation Phases checklist if it tracks phase status.
- [ ] confirm `README.md` accurately documents what works.
- [ ] move this plan to `docs/plans/completed/` (run `mkdir -p docs/plans/completed`).
- [ ] commit the move atomically as a separate commit.

---

## Post-Completion

_Items requiring manual intervention or external systems — no checkboxes, informational only. The user will drive these after Tasks 1–16 land._

**Phase-1 manual acceptance run**

1. Build the CLI: `go build ./cmd/ppiav-cli` (or `go run ./cmd/ppiav-cli ...` directly).
2. Full protocol with `x²`: `go run ./cmd/ppiav-cli e2e --image cmd/ppiav-cli/testdata/synthetic.bin --n 5`. Expect Verdict=Accept on every iteration (squared logit is non-negative). Verify the JSON output materialises under `results/phase1/e2e.json`.
3. Per-step benches: run each of `keygen`, `encrypt-image`, `infer`, `mac`, `decrypt-result`, `verify-mac` with `--n 5`. Verify one JSON per step in `results/phase1/`.
4. Render Markdown summary tables: `cd bench && uv run python -m bench.tables ../results/phase1`. Inspect.
5. Render PNG plots: `cd bench && uv run python -m bench.plot ../results/phase1`. Open the resulting PNGs.
6. Sanity-check: does the bench profile match expectations from DESIGN.md §`Noise magnitude` (rotation sum is the Phase-1 hot spot)?

**Phase-2 manual acceptance run**

1. Confirm Orion's reference artifacts exist locally: `ls ~/Dev/orion/examples/c3ae-demo/out/logn15/model.orion ~/Dev/orion/examples/c3ae-demo/out/inputs/sample_test.bin`. ⚠️ Use the `logn15` directory until a `logn16/model.orion` is built — see Task 14's note. The CLI `--orion` flag is path-agnostic.
2. Full protocol with C3AE: `go run ./cmd/ppiav-cli e2e --orion ~/Dev/orion/examples/c3ae-demo/out/logn15 --image ~/Dev/orion/examples/c3ae-demo/out/inputs/sample_test.bin --n 5`. Verify Verdict=Accept (or Reject — depends on whether `sample_test.bin` is above or below the trained age threshold) and that the same verdict comes back consistently across iterations.
3. Cross-check: run Orion's own `eval.py` against the same checkpoint + input. The recovered logit values should match ours within float-precision tolerance.
4. Repeat the bench plots/tables pipeline against `results/phase2/`.

**Tamper test (Phase 1)**

Drive a manual tamper case to confirm the protocol rejects: encrypt `m=0.5`, run inference, then before submitting to VAgent's `FinalizeDecryption`, add `Encrypt(1)` to the result ciphertext. Ver should reject, verdict should be Reject. (User can wire this through a small ad-hoc test harness or by patching the CLI temporarily.)

**Snapshot commits**

If the user wants to preserve a bench run as a canonical reference, copy `results/phase{1,2}/*.json` into `results/phase{1,2}/snapshot/` and commit deliberately with a message noting the machine + commit hash + ppiav version.

**Out of scope (explicit)**

- VPS rental for training. Skipped — we reuse Orion's checkpoint.
- C3AE model training, dataset preparation, accuracy validation. Skipped — out of scope per user direction.
- Phase-3 HTTP services + browser SPAs.
- Phase-4 lattigo-hierkeys.
- Phase-5 σ_flood/ε calibration.

**Follow-up plans (not part of this plan, but to file once this lands)**

- **Phase 3**: HTTP services + browser SPAs + WASM bridge (`web/ppiav`).
- **Phase 4**: lattigo-hierkeys integration (`gks_master` wire format).
- **Phase 5 — noise calibration**: deferred per DESIGN.md until all four protocol phases have landed. Replan after Phase 4 to empirically measure σ_B across each phase's params and circuits, derive σ_flood and ε from those measurements with an explicit confidence bound, and either confirm or adjust the 2¹⁶/2²⁰ constants the prototype uses on faith.
