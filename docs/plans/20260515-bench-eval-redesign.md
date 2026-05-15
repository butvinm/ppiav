# Bench + Evaluation Pipeline Redesign

## Overview

Replace the current in-process bench harness (`internal/bench` + the seven `ppiav-cli` step subcommands) with an artifact-pipeline architecture: each protocol stage becomes its own CLI subprocess that loads its inputs from disk, runs one cryptographic operation, and writes its output artifact plus a single-sample timing JSON. A Python driver in `bench/` chains the subprocesses across a 10-image stratified UTKFace batch (single keygen reused), then aggregates per-step JSONs + decoded slot vectors into a `summary.md` and a `plots/` directory. The plan ends with a rented-VPS run that produces the final thesis numbers.

Three problems motivate the rework:

1. **Per-step peak RSS is currently meaningless.** `internal/bench/bench.go` reads `/proc/self/status` VmHWM, which is monotonic over the process lifetime. In the existing single-process e2e bench every Sample.VmHWM is at least as large as the previous Sample, so "RSS of this step" is not actually measured. Splitting steps into separate processes makes per-step peak RSS correct for free.
2. **No protocol-level FPR/FNR or noise distribution is captured today.** `models/eval.py` measures the cleartext model's FPR/FNR, but nothing measures the whole-pipeline FPR/FNR (model + CKKS noise + MPD-Auth + smudging) or the noise the protocol actually produces. This is the single most thesis-relevant correctness number.
3. **Per-message wire bytes are not captured.** `internal/bench/MeasureWithSize` exists but is wired into zero call sites. With the artifact pipeline, every protocol message becomes a file on disk and `os.Stat` gives the wire size directly — no plumbing required.

The redesign **does not touch production protocol code semantics**. The single-use `FinalizeDecryption` eviction stays in production; the new `finalize` subcommand sidesteps it by building a fresh in-process Agent per CLI invocation, so the in-memory session map never sees a replay. GLK is emitted as two files (`glk_master.bin` + `glk_full.bin`) — identical today, will diverge under Phase-4 lattigo-hierkeys.

## Context (from discovery)

- **Affected Go packages:** `internal/bench`, `internal/vagent`, `internal/vclient`, `internal/vservice`, `internal/protocol`, `cmd/ppiav-cli`
- **Affected Python packages:** `bench/bench`, `models/models`
- **Patterns reused:** `internal/protocol/wire.go` already encapsulates Lattigo `MarshalBinary` / `UnmarshalBinary` for keys and ciphertexts; the new disk artifacts use the same wire formats. `internal/bench/bench.go` `Sample`/`Run` JSON shape is preserved (only one new field added). `bench/bench/load.py` mirrors the Go struct.
- **VPS methodology:** modelled on `~/Dev/orion/docs/plans/completed/2026-05-09-c3ae-vps-runs.md`. That plan's logn16 run measured ~114 GB peak RSS on `cpu.16.128.240` (128 GB box) with ~10 GB headroom — 256 GB flavors are not even available on immers.cloud. Reuse `docs/plans/20260514-orion-integration-training-compilation/setup.sh` (already in repo) for FHE-VPS provisioning, with a small branch checkout fix.
- **Constraints:** logn16 only (cleanup of stale `logn15` references already done in this session — `models/models/compile.py:108` comment, the deleted `results/phase2/e2e.json`, plus `models/README.md`, `README.md`, and `setup.sh` updated to drop the 256 GB / `cpu.16.256.240` claim). Lattigo `LogN=15` test-profile references in `internal/vclient/image_test.go` and `internal/orchestrator/runner_test.go` are unrelated (CKKS ring dimension chosen because LogN=14's 8192 slots cannot hold a 12288-element image) and stay.
- **No local weights:** `models/out/` doesn't exist on the dev box; training is part of the VPS phase, not a precondition.

## Development Approach

- **Code-first, then tests** (regular). TDD discipline is overkill for a rework that mostly composes existing primitives.
- **Tests only for code in `internal/`** — production-grade reusable primitives that the Phase-3 HTTP services could also use. The new state-export constructors and the extended `FinalizeDecryption` are not throwaway harness.
- **No tests for `cmd/ppiav-cli/` subcommands** or `bench/bench/eval.py` driver/aggregator/plots — these are the benchmark harness; their correctness check is "do the numbers in `summary.md` look right when a human reads them."
- **One exception:** `bench/bench/load.py` IS the Go↔Python schema boundary and gets a unit test for the new `pre_vm_hwm` round-trip — closer to "code" than "harness."
- **No tests for `models/prepare_samples.py` extension** per the existing `feedback_no_ml_harness_tests.md` memory.
- **Atomic commits**: stage specific files (`git add path/to/file`), never `git add .`. Each task = one commit. Clear, concrete messages.
- Small, focused changes per task. Run `go vet ./... && go test ./...` and `uv run pytest` (in `bench/`) after each task that touches tested code.
- Maintain backward compatibility for `bench/bench/load.py` reading old phase1 JSONs — the new `pre_vm_hwm` field defaults to 0 when absent.
- **Build state stays green between tasks.** When CLI subcommands are added incrementally (Tasks 7-10), each task ends with a `go build ./... && go vet ./...` checkbox to keep the package compilable.

## Testing Strategy

Estimated 6 tests total:

- `internal/bench/bench_test.go` — verify `Sample.PreVmHWM` is populated on Linux.
- `internal/vagent/finalize_test.go` — extend existing tests for the new `FinalizeDecryptionVerbose` that returns the decoded slot vector alongside the verdict.
- `internal/vagent/state_test.go` — round-trip: open a session, `ExportState`, build a new Agent via `NewWithState`, verify a downstream protocol op succeeds.
- `internal/vclient/state_test.go` — same shape for Client.
- `internal/vservice/state_test.go` — round-trip: store keys, export `(sid, params, rlk, glk)`, build new Service via `NewWithState`, verify `Infer` succeeds on a probe ciphertext.
- `bench/tests/test_load.py` — extend with `pre_vm_hwm` round-trip + presence of `delta_rss_mib` property.

No new e2e tests. The existing `internal/orchestrator/runner_test.go` already verifies the in-process protocol chain at LogN=15 — the CLI just splits the chain across processes, so duplicating that test at the CLI level would be ceremony. Full chain validation is deferred to the VPS run (Tasks 25-26), which IS the acceptance test for this entire plan.

## Progress Tracking

- mark completed items with `[x]` immediately when done
- add newly discovered tasks with ➕ prefix
- document issues/blockers with ⚠️ prefix
- update plan if implementation deviates from original scope
- keep plan in sync with actual work done

## Solution Overview

**Architecture:**

```
models/prepare_samples.py     →  models/out/eval_inputs.json + sample_0..9.bin
   (--batch 10 --stratified        + ref logits from PyTorch C3AE-fhe-quad
    --with-ref-logit)

ppiav-cli keygen              →  results/phase2/eval-<ts>/keys/{pk,sk_c,sk_a,rlk,glk_master,glk_full,mac_key,sid,params}
   (run once, bilateral in-process)   + keygen.json (per-round timing + sizes)

ppiav-cli encrypt             →  img_<i>/input_ct.bin   + encrypt.json
ppiav-cli infer  --orion ...  →  img_<i>/result_ct.bin  + infer.json
ppiav-cli mac                 →  img_<i>/auth_ct.bin    + mac.json
ppiav-cli partial-decrypt     →  img_<i>/client_share.bin + partial.json
ppiav-cli finalize --ref-logit→  img_<i>/decoded.json (verdict + noise_per_slot)
                                                       + finalize.json

bench/bench/eval.py aggregate →  results/phase2/eval-<ts>/summary.md
                                 results/phase2/eval-<ts>/plots/*.png
```

**Per-role separation:** `encrypt`/`partial-decrypt` use VClient state only; `infer` uses VService state only; `mac`/`finalize` use VAgent state only. `keygen` is bilateral (both roles in-process) because splitting the 4-round handshake into per-message CLI calls would mean ~12 subcommands; instead it emits per-round timing sub-samples (`keygen.open` / `keygen.pk` / `keygen.rlk-r1` / `keygen.rlk-r2` / `keygen.galois`) and writes one artifact per round to disk so the aggregator can size each via `os.Stat`.

**Why per-step peak RSS works now:** each CLI invocation is a fresh process, so VmHWM at process exit = peak RSS during that one step. A new `pre_vm_hwm` field captures the pre-op snapshot so the aggregator can report `delta_rss = vm_hwm - pre_vm_hwm` (RSS attributable to the op vs. startup baseline).

**Why FinalizeDecryption eviction is not a problem in this design:** the eviction is an in-process `delete(sessions, sid)` against an in-memory map. Each `ppiav-cli finalize` is a fresh process with an empty session map. Eviction is irrelevant across CLI boundaries. The bench's `finalize` subcommand calls the same production code path as the HTTP server, but a `Verbose` sibling (added in Task 2) exposes the decoded slot vector that the standard production method discards.

## Technical Details

### New Sample field

```go
// internal/bench/bench.go
type Sample struct {
    // ...existing fields...
    PreVmHWM uint64 `json:"pre_vm_hwm"`  // RSS high-water-mark snapshot taken before the measured call
}
```

`bench.Measure` reads `readVmHWM()` once at the start of the timed block and stamps `s.PreVmHWM`. The Python aggregator reports `delta_rss_mib = (vm_hwm - pre_vm_hwm) / (1024*1024)`.

### Extended FinalizeDecryption

```go
// internal/vagent/finalize.go (extended)
//
// FinalizeDecryption: existing signature, unchanged. Drops decoded slots after Ver.
// FinalizeDecryptionVerbose: new sibling. Returns (verdict, decodedSlots, err).
// Production callers stay on FinalizeDecryption; the bench finalize subcommand uses Verbose.
// Both methods evict the session on completion — eviction lives in the shared inner path.
func (a *Agent) FinalizeDecryptionVerbose(sid SessionID, authCt *rlwe.Ciphertext, clientShare *drlwe.KeySwitchShare) (Verdict, []float64, error)
```

This avoids duplicating ~30 lines of joint-decrypt + Ver logic in the CLI subcommand, keeping bench and production on the same code path.

### State export/import API

Per-role minimal scope (the plan-review's "over-coupling" concern):

```go
// internal/vagent/state.go
type ExportedState struct {
    SID     protocol.SessionID
    SkShare *rlwe.SecretKey
    MacKey  *authenticator.Key
    // Aggregated keys are not part of Agent state — they're held by VService.
    // PK is the only shared aggregated key the Agent retains, and it's needed
    // only during the handshake, not for mac/finalize.
}

func (a *Agent) ExportState(sid protocol.SessionID) (*ExportedState, error)
func NewWithState(params protocol.Params, state *ExportedState) (*Agent, error)

// internal/vclient/state.go
type ExportedState struct {
    SID     protocol.SessionID
    SkShare *rlwe.SecretKey
    PkAgg   *rlwe.PublicKey  // needed for EncryptImage; partial-decrypt doesn't use it
}

func (c *Client) ExportState() (*ExportedState, error)
func NewWithState(params protocol.Params, state *ExportedState) (*Client, error)

// internal/vservice/state.go
type ExportedState struct {
    SID    protocol.SessionID
    Rlk    *rlwe.RelinearizationKey
    Glk    []*rlwe.GaloisKey
}

func (s *Service) ExportState(sid protocol.SessionID) (*ExportedState, error)
func NewWithState(params protocol.Params, orionDir string, state *ExportedState) (*Service, error)
```

The CRS is NOT serialized — `NewWithState` rebuilds it deterministically from `SID` via `protocol.NewSessionCRS(sid)` (which is how vclient/vagent already construct it in `New`).

### CLI subcommand surface (all under `ppiav-cli`)

```
keygen           --workdir <dir> --orion <dir>                                              --out <results.json>
encrypt          --workdir <dir> --image <img.bin>                  --out-ct <input_ct.bin> --out <results.json>
infer            --workdir <dir> --orion <dir> --in-ct <input_ct>   --out-ct <result_ct>    --out <results.json>
mac              --workdir <dir>               --in-ct <result_ct>  --out-ct <auth_ct>      --out <results.json>
partial-decrypt  --workdir <dir>               --in-ct <auth_ct>    --out-share <share>     --out <results.json>
finalize         --workdir <dir>               --in-ct <auth_ct> --in-share <share>
                 [--ref-logit <f>] --out-decoded <decoded.json>                             --out <results.json>
```

Default `--out` paths: `<workdir>/<step>.json` if omitted (eval driver always passes explicit paths).

### `decoded.json` shape (written by finalize)

```json
{
  "verdict": "accept" | "reject" | "unknown",
  "ref_logit": 2.34,
  "slots_in_s": [3, 17, 42, ...],
  "noise_per_slot": [0.0012, -0.0007, 0.0019, ...]
}
```

`noise_per_slot` is over **non-S slots only** (the slots that carry the broadcast logit `m`); `slots_in_s` is the authenticator's secret index set, retained for debugging.

### `eval_inputs.json` shape (written by extended `prepare_samples.py`)

```json
{
  "config": "logn16",
  "weights": "out/weights_fhe.pth",
  "generated_at": "2026-05-15T...",
  "images": [
    {"idx": 0, "path": "models/out/inputs/sample_0.bin", "age": 23, "label": 1, "ref_logit": 2.34},
    {"idx": 1, "path": "models/out/inputs/sample_1.bin", "age": 14, "label": 0, "ref_logit": -1.87},
    ...
  ]
}
```

Stratified: exactly 5 entries with `label=0` (minors) and 5 with `label=1` (adults).

### Aggregator outputs

`summary.md`:

- Per-step timing table (mean / p50 / p95 wall ms across 10 images for encrypt/infer/mac/partial/finalize; single keygen row with per-round breakdown)
- Per-step RSS table (mean delta_rss MiB, mean vm_hwm MiB)
- Per-message byte table from `os.Stat` on every artifact in the batch — `glk_master.bin` and `glk_full.bin` each get their own row even when identical, with a footnote that they diverge under Phase-4 hierkeys (single source of truth: the filesystem)
- Protocol FPR / FNR / accuracy line (across the 10 images)
- Noise distribution: mean / min / max / std across all (image × slot) pairs
- SNR distribution: per-image `|ref_logit| / std(noise_per_slot)`
- Network estimate table (per-message: bytes, t@1Mbps, t@10Mbps, t@100Mbps)

`plots/`:

- `e2e_timeline.png` — single horizontal Gantt bar of one mean e2e session, **compute only**, sections in protocol order (`keygen.open` → `keygen.pk` → `keygen.rlk-r1` → `keygen.rlk-r2` → `keygen.galois` → `encrypt` → `infer` → `mac` → `partial-decrypt` → `finalize`), color-coded by macro-phase (setup / inference / verify). Section width = mean wall ms for that step. Replaces the per-step bar chart — the timing table in `summary.md` already gives exact mean/p50/p95 numbers; the Gantt's job is visual proportionality
- `rss_per_step.png` — bar chart, one bar per step, mean delta_rss MiB
- `bytes_per_message.png` — bar chart, one bar per message, log y
- `noise_histogram.png` — histogram of noise across all (image × slot) pairs
- `snr_per_image.png` — strip plot of per-image SNR (10 points — a 10-bin histogram would be uninformative; strip plot reads cleanly at this N)
- `bandwidth_per_message.png` — grouped bar chart, three bars per message (1/10/100 Mbps)
- `session_timeline_10mbps.png` — companion to `e2e_timeline.png` with **compute + transfer** sections interleaved at 10 Mbps. Same color coding by macro-phase; compute and transfer sections distinguished by hatching/shade. Reads as "where time goes during one session over consumer broadband"

## What Goes Where

- **Implementation Steps** (`[ ]` checkboxes): Go and Python code changes, tests for `internal/` and the `load.py` boundary, file deletions, documentation updates, the VPS rental + run + capture + tear-down sequence per Orion methodology, results commit, final plan move.
- **Post-Completion** (no checkboxes): thesis methodology paragraph, optional refinements.

## Implementation Steps

### Task 1: Add `PreVmHWM` to bench Sample

**Files:**

- Modify: `/home/butvinm/Dev/ppiav/internal/bench/bench.go`
- Modify: `/home/butvinm/Dev/ppiav/internal/bench/bench_test.go`

- [x] add `PreVmHWM uint64 \`json:"pre_vm_hwm"\``to`Sample` struct
- [x] in `measure(...)`, call `readVmHWM()` before `start := time.Now()` and stamp `s.PreVmHWM`
- [x] write test verifying `Sample.PreVmHWM` is non-zero after Measure on Linux (skip via `runtime.GOOS != "linux"` check); also assert `PreVmHWM <= VmHWM`
- [x] run `go test ./internal/bench/...` — must pass before next task

### Task 2: Extend FinalizeDecryption to expose decoded slots

**Files:**

- Modify: `/home/butvinm/Dev/ppiav/internal/vagent/finalize.go`
- Modify: `/home/butvinm/Dev/ppiav/internal/vagent/finalize_test.go`

- [ ] add `FinalizeDecryptionVerbose(sid, authCt, clientShare) (Verdict, []float64, error)` returning the decoded plaintext vector alongside the verdict
- [ ] refactor existing `FinalizeDecryption` to call `FinalizeDecryptionVerbose` and discard the slots — keeps single source of truth for the joint-decrypt + Ver inner path
- [ ] both methods preserve the session-eviction behaviour (eviction stays in the shared inner path)
- [ ] write test verifying `FinalizeDecryptionVerbose` returns the same verdict as `FinalizeDecryption` AND a non-nil non-empty `[]float64` of length `params.CKKS.MaxSlots()`
- [ ] write test verifying noise_per_slot at non-S indices has small magnitude (e.g. < 0.1) when the input is a fresh honest authenticated ciphertext
- [ ] run `go test ./internal/vagent/...` — must pass before next task

### Task 3: VAgent state export/import

**Files:**

- Modify: `/home/butvinm/Dev/ppiav/internal/vagent/agent.go`
- Create: `/home/butvinm/Dev/ppiav/internal/vagent/state.go`
- Create: `/home/butvinm/Dev/ppiav/internal/vagent/state_test.go`

- [ ] define `ExportedState` struct: `{SID, SkShare *rlwe.SecretKey, MacKey *authenticator.Key}` (minimal — Agent's mac/finalize don't need aggregated PK/RLK/GLK; those live in VService)
- [ ] implement `(a *Agent) ExportState(sid) (*ExportedState, error)` — reads the session map, errors on unknown sid
- [ ] implement `NewWithState(params, *ExportedState) (*Agent, error)` — constructs fresh Agent, seeds session map. Rebuilds CRS from `state.SID` via `protocol.NewSessionCRS(sid)` rather than serializing
- [ ] write round-trip test at LogN=15: open a session, drive through PK + RLK + Galois handshakes, export state, build new Agent via `NewWithState`, call `BuildAuthenticatedCt` on a probe result_ct, verify the output matches the original Agent's output bit-for-bit
- [ ] run `go test ./internal/vagent/...` — must pass before next task

### Task 4: VClient state export/import

**Files:**

- Modify: `/home/butvinm/Dev/ppiav/internal/vclient/client.go`
- Create: `/home/butvinm/Dev/ppiav/internal/vclient/state.go`
- Create: `/home/butvinm/Dev/ppiav/internal/vclient/state_test.go`

- [ ] define `ExportedState`: `{SID, SkShare *rlwe.SecretKey, PkAgg *rlwe.PublicKey}` (`PkAgg` needed for `EncryptImage`; `PartialDecrypt` uses only `SkShare`)
- [ ] implement `(c *Client) ExportState() (*ExportedState, error)` and `NewWithState(params, *ExportedState) (*Client, error)`
- [ ] rebuild CRS from `state.SID` in `NewWithState`; do not serialize
- [ ] write round-trip test at LogN=15: drive through Open + PK handshake, export, build new Client, call `EncryptImage` and `PartialDecrypt` on probes, verify deterministic outputs
- [ ] run `go test ./internal/vclient/...` — must pass before next task

### Task 5: VService state export/import (NEW — required for `infer` subcommand)

**Files:**

- Modify: `/home/butvinm/Dev/ppiav/internal/vservice/service.go`
- Create: `/home/butvinm/Dev/ppiav/internal/vservice/state.go`
- Create: `/home/butvinm/Dev/ppiav/internal/vservice/state_test.go`

- [ ] define `ExportedState`: `{SID, Rlk *rlwe.RelinearizationKey, Glk []*rlwe.GaloisKey}`. Sufficient for `Infer` since Orion model is loaded separately via `--orion <dir>`
- [ ] implement `(s *Service) ExportState(sid) (*ExportedState, error)`
- [ ] implement `NewWithState(params, orionDir string, state *ExportedState) (*Service, error)` — loads Orion model the existing way, then directly seeds the session map with `sid → {rlk, glk, evaluator}` bypassing the random sid mint in `OpenSession`
- [ ] write round-trip test at LogN=15 (no Orion model — use the stub inference path if one exists; otherwise verify state seeding via `Infer` against a trivial keyset and a non-zero probe ciphertext)
- [ ] run `go test ./internal/vservice/...` — must pass before next task

### Task 6: Delete old subcommands AND rewrite `main.go` dispatch with stubs

**Files:**

- Delete: `/home/butvinm/Dev/ppiav/cmd/ppiav-cli/e2e.go`
- Delete: `/home/butvinm/Dev/ppiav/cmd/ppiav-cli/steps.go`
- Modify: `/home/butvinm/Dev/ppiav/cmd/ppiav-cli/main.go`

- [ ] delete `e2e.go` and `steps.go` (the seven old in-process bench subcommands)
- [ ] rewrite `main.go` dispatch to the six new subcommands: `keygen | encrypt | infer | mac | partial-decrypt | finalize`
- [ ] each handler is initially a stub returning `fmt.Errorf("unimplemented")` so the package compiles
- [ ] update usage/help text; remove all references to deleted subcommands
- [ ] run `go build ./... && go vet ./...` — must succeed before next task (package stays green even though subcommands are stubs)

### Task 7: Implement `ppiav-cli keygen`

**Files:**

- Create: `/home/butvinm/Dev/ppiav/cmd/ppiav-cli/keygen.go`
- Create: `/home/butvinm/Dev/ppiav/cmd/ppiav-cli/artifacts.go`

- [ ] create `artifacts.go` with helpers to write/read each artifact (sk_c, sk_a, pk, rlk, glk_master, glk_full, mac_key, sid, params, input_ct, result_ct, auth_ct, client_share) as a file at the canonical name within a workdir; helpers use existing `internal/protocol/wire.go` marshalers
- [ ] note: `artifacts.go` stays under `cmd/ppiav-cli/`; if a helper graduates to `internal/protocol/wire.go` later, that file's test suite extends accordingly
- [ ] create `keygen.go` parsing `--workdir <dir> --orion <dir> [--out <path>]`
- [ ] run bilateral keygen in-process mirroring `orchestrator.Setup`; wrap each round (`open`, `pk`, `rlk-r1`, `rlk-r2`, `galois`) in `bench.Measure`; append samples to a single `bench.Run` named "keygen"
- [ ] write artifacts to `<workdir>/{pk.bin, sk_c.bin, sk_a.bin, rlk.bin, glk_master.bin, glk_full.bin, mac_key.bin, sid.txt, params.json}` via `artifacts.go`
- [ ] do NOT record per-artifact byte sizes in metadata — the aggregator gets them from `os.Stat` (single source of truth)
- [ ] write `run` JSON to `--out` (default `<workdir>/keygen.json`)
- [ ] run `go build ./... && go vet ./...` — must succeed before next task

### Task 8: Implement VClient-side subcommands (`encrypt`, `partial-decrypt`)

**Files:**

- Create: `/home/butvinm/Dev/ppiav/cmd/ppiav-cli/encrypt.go`
- Create: `/home/butvinm/Dev/ppiav/cmd/ppiav-cli/partial_decrypt.go`

- [ ] `encrypt.go`: parse `--workdir --image --out-ct --out`; load `{sid, sk_c, pk_agg, params}` via `artifacts.go`; build `vclient.Client` via `NewWithState`; wrap `EncryptImage` in `bench.Measure`; write `--out-ct` and `--out` JSON
- [ ] `partial_decrypt.go`: parse `--workdir --in-ct --out-share --out`; load `{sid, sk_c, params}`; build Client via `NewWithState`; wrap `PartialDecrypt` in `bench.Measure`; write `--out-share` and `--out` JSON
- [ ] run `go build ./... && go vet ./...` — must succeed before next task

### Task 9: Implement VService-side subcommand (`infer`)

**Files:**

- Create: `/home/butvinm/Dev/ppiav/cmd/ppiav-cli/infer.go`

- [ ] parse `--workdir --orion --in-ct --out-ct --out`; load `{sid, rlk, glk_full, params}` via `artifacts.go`; build `vservice.Service` via `NewWithState(params, orionDir, state)`
- [ ] wrap `Infer` in `bench.Measure`; write `--out-ct` and `--out` JSON
- [ ] run `go build ./... && go vet ./...` — must succeed before next task

### Task 10: Implement VAgent-side subcommands (`mac`, `finalize`)

**Files:**

- Create: `/home/butvinm/Dev/ppiav/cmd/ppiav-cli/mac.go`
- Create: `/home/butvinm/Dev/ppiav/cmd/ppiav-cli/finalize.go`

- [ ] `mac.go`: parse `--workdir --in-ct --out-ct --out`; load `{sid, sk_a, mac_key, params}`; build `vagent.Agent` via `NewWithState`; wrap `BuildAuthenticatedCt` in `bench.Measure`; write `--out-ct` (auth_ct.bin) and `--out` JSON
- [ ] `finalize.go`: parse `--workdir --in-ct --in-share --ref-logit --out-decoded --out`; load `{sid, sk_a, mac_key, params}`; build Agent via `NewWithState`
- [ ] wrap `FinalizeDecryptionVerbose` (from Task 2) in `bench.Measure`; receive `(verdict, slots, err)`
- [ ] compute `noise_per_slot[i] = slots[i] - ref_logit` for i in non-S slots (S is the authenticator's secret index set, available from `params.Authenticator` + key.S as in the existing `verify-mac` path)
- [ ] write `decoded.json` with `{verdict, ref_logit, slots_in_s, noise_per_slot}` and `--out` JSON
- [ ] run `go build ./... && go vet ./...` — must succeed before next task

### Task 11: Extend `prepare_samples.py` for stratified batch + ref logits

**Files:**

- Modify: `/home/butvinm/Dev/ppiav/models/models/prepare_samples.py`

- [ ] add `--batch N --stratified --with-ref-logit --out-manifest <path>` flags
- [ ] in batch mode: load `out/weights_fhe.pth`, pick N stratified UTKFace test samples (N/2 minors with label=0, N/2 adults with label=1), write each as `sample_<idx>.bin`, compute the cleartext FHE-quad logit for each
- [ ] write `eval_inputs.json` to `--out-manifest` with `{config, weights, generated_at, images: [{idx, path, age, label, ref_logit}, ...]}`
- [ ] keep the existing single-sample mode intact (backward-compatible)
- [ ] no tests per `feedback_no_ml_harness_tests.md`

### Task 12: Update Python bench loader + tables for `pre_vm_hwm`

**Files:**

- Modify: `/home/butvinm/Dev/ppiav/bench/bench/load.py`
- Modify: `/home/butvinm/Dev/ppiav/bench/bench/tables.py`
- Modify: `/home/butvinm/Dev/ppiav/bench/tests/test_load.py`

- [ ] add `pre_vm_hwm: int` to `Sample` dataclass with default 0 (backward-compatible)
- [ ] in `_sample_from_dict`, read `d.get("pre_vm_hwm", 0)`
- [ ] add `delta_rss_mib` property: `max(0, (vm_hwm - pre_vm_hwm)) / 1024**2`
- [ ] update `render_tables` to add a "mean delta RSS MiB" column
- [ ] extend `bench/tests/test_load.py` with a fixture roundtrip for `pre_vm_hwm` and a presence-check for `delta_rss_mib`
- [ ] run `cd bench && uv run pytest && uv run mypy bench tests` — must pass before next task

### Task 13: Eval driver (Python orchestrator)

**Files:**

- Create: `/home/butvinm/Dev/ppiav/bench/bench/eval.py`

- [ ] implement `main(argv)` parsing `--inputs <eval_inputs.json> --orion <dir> [--batch-dir <path>]`
- [ ] create batch dir `results/phase2/eval-<UTC-timestamp>/`, mkdir `keys/`
- [ ] invoke `ppiav-cli keygen --workdir <batch>/keys --orion <orion> --out <batch>/keygen.json` via subprocess; fail fast on non-zero exit
- [ ] for each image in `eval_inputs.images`: mkdir `<batch>/img_<idx>/`; invoke encrypt → infer → mac → partial-decrypt → finalize in sequence; finalize gets `--ref-logit` from the manifest entry
- [ ] after all images: call `aggregate(<batch>)` (Task 14)
- [ ] no tests — benchmark harness

### Task 14: Aggregator (summary.md generation)

**Files:**

- Modify: `/home/butvinm/Dev/ppiav/bench/bench/eval.py`

- [ ] implement `aggregate(batch_dir: Path) -> None` reading `<batch>/keygen.json` + `<batch>/img_*/*.json` + `<batch>/img_*/decoded.json`
- [ ] compute per-step timing table (mean/p50/p95 wall ms across 10 images for non-keygen steps; keygen single row with per-round sub-rows)
- [ ] compute RSS table (mean `delta_rss_mib`, mean `vm_hwm_mib` per step)
- [ ] compute per-message byte table by walking `<batch>/keys/*` and `<batch>/img_0/*` (or all img\_\*; sizes are stable per image) with `os.stat`. Each file gets its own row; `glk_master.bin` and `glk_full.bin` both appear with a footnote about Phase-4 divergence
- [ ] compute protocol FPR / FNR / accuracy by joining `decoded.json.verdict` with `eval_inputs.json[idx].label`
- [ ] compute noise stats (mean/min/max/std) across flattened `noise_per_slot` arrays from all 10 images
- [ ] compute SNR per image (`|ref_logit| / std(noise_per_slot_i)`) — produce array of 10 values
- [ ] compute network estimate table (per-message bytes ÷ {1, 10, 100} Mbps → seconds)
- [ ] write `summary.md` with all tables
- [ ] call `plots_eval.write_plots(batch_dir, agg_data)` (Task 15)
- [ ] no tests — benchmark harness

### Task 15: Plot generation

**Files:**

- Create: `/home/butvinm/Dev/ppiav/bench/bench/plots_eval.py`

- [ ] implement `write_plots(batch_dir, agg_data)` writing 7 PNGs to `<batch>/plots/`:
  - `e2e_timeline.png` — horizontal Gantt of one mean e2e session, compute-only; sections in protocol order, color-coded by macro-phase (setup/inference/verify); section width = mean wall ms
  - `rss_per_step.png` — bar chart, mean delta_rss MiB per step
  - `bytes_per_message.png` — bar chart, log y, one bar per message
  - `noise_histogram.png` — histogram of flattened noise samples
  - `snr_per_image.png` — strip plot of 10 SNR values (one dot per image)
  - `bandwidth_per_message.png` — grouped bar chart, three bars (1/10/100 Mbps) per message
  - `session_timeline_10mbps.png` — horizontal Gantt with compute + transfer sections interleaved at 10 Mbps; same color coding as `e2e_timeline.png`; compute vs transfer distinguished by hatching/shade
- [ ] use `matplotlib` (already a dep) with `Agg` backend (headless)
- [ ] no tests — benchmark harness

### Task 16: Local sanity gate

**Files:** none — verification only

Scope: confirm everything builds and unit tests pass on the dev box. Full chain validation is deferred to the VPS run; the LogN=14 escape hatch from the previous draft of this plan is dropped because `internal/vclient.EncryptImage` requires 12288 slots (≥LogN=15) and there is no LogN=15 Orion model in tree.

- [ ] `go build ./...` — succeeds
- [ ] `go vet ./...` — clean
- [ ] `go test ./...` — all packages green (including the new tests added in Tasks 1-5 and the existing `runner_test.go` at LogN=15)
- [ ] `cd bench && uv run ruff check . && uv run mypy bench && uv run pytest` — clean
- [ ] `cd models && uv run ruff check . && uv run mypy .` — clean

### Task 17: Documentation updates

**Files:**

- Modify: `/home/butvinm/Dev/ppiav/bench/README.md`
- Modify: `/home/butvinm/Dev/ppiav/models/README.md`
- Modify: `/home/butvinm/Dev/ppiav/CLAUDE.md`
- Modify: `/home/butvinm/Dev/ppiav/README.md` (only if it documents the ppiav-cli surface)
- Modify: `/home/butvinm/Dev/ppiav/Makefile` if a bench target should be added

- [ ] `bench/README.md`: rewrite to document `python -m bench.eval --inputs ... --orion ...` workflow and the per-batch directory layout
- [ ] `models/README.md`: document the `--batch --stratified --with-ref-logit --out-manifest` flow; replace the existing `ppiav-cli e2e` example with the new pipeline (or a `python -m bench.eval` one-liner)
- [ ] `CLAUDE.md`: update Status section noting the bench redesign; replace any obsolete subcommand list
- [ ] `README.md`: scan for `ppiav-cli e2e` / other deleted subcommand mentions; replace with new flow
- [ ] `Makefile`: optionally add `make eval` chaining the prepare → eval-driver invocation

### Task 18: Rent training VPS

**Files:** none — operates against immers.cloud only

- [ ] check immers.cloud account balance is sufficient (top up if HTTP 401 surfaces)
- [ ] rent the GPU training VPS via the `vps` skill: `vps create --name ppiav-bench-eval-train --flavor rtx4090-1.8.16.40` (auto-selects the CUDA Ubuntu image because the flavor starts with `rtx`)
- [ ] **manual verify**: `openstack --os-cloud immers server show ppiav-bench-eval-train -f json | jq '.status, .addresses'` — status `ACTIVE`; note the IP
- [ ] record rental start time

### Task 19: Bootstrap training VPS + train weights

**Files:**

- Reuse: `/home/butvinm/Dev/ppiav/docs/plans/20260514-orion-integration-training-compilation/setup.sh` (already in repo)

- [ ] scp `setup.sh` to the training VPS; the script currently checks out branch `phase-1-2` — verify or update to checkout the current working branch (master if merged, else the phase-3 branch). Edit the script's `git checkout` line if needed before scp
- [ ] run `setup.sh` on the VPS; wait for "ready" output
- [ ] **manual verify** over SSH: `python -c "import torch, orion_compiler; print(torch.__version__, torch.cuda.is_available())"` — torch printed, CUDA True; `go version` shows 1.24+
- [ ] in a `nohup` session on the VPS:
  ```sh
  cd ~/ppiav/models
  uv run python -m models.utkface --target ./data/UTKFace
  uv run python -m models.train --variant fhe --data-dir ./data/UTKFace --epochs 60 --output ./out/weights_fhe.pth
  ```
- [ ] **manual verify**: `ls -la ~/ppiav/models/out/weights_fhe.pth` shows ~140 kB; training log ends with a sensible final loss

### Task 20: Capture training artifacts + tear down training VPS

**Files:**

- Create (local, gitignored): `/home/butvinm/Dev/ppiav/models/out/weights_fhe.pth`

- [ ] from local: `rsync -av ubuntu@<train-ip>:~/ppiav/models/out/weights_fhe.pth /home/butvinm/Dev/ppiav/models/out/weights_fhe.pth`
- [ ] **manual verify**: local file present, ~140 kB
- [ ] tear down: `openstack --os-cloud immers server delete ppiav-bench-eval-train --wait`
- [ ] **manual verify**: `openstack --os-cloud immers server list | grep ppiav-bench-eval-train` returns nothing
- [ ] record rental end + total billed hours

### Task 21: Rent FHE eval VPS

**Files:** none

- [ ] rent the 128 GB CPU VPS: `vps create --name ppiav-bench-eval-fhe --flavor cpu.16.128.240`
- [ ] **manual verify**: status `ACTIVE`, IP noted, ~125 GiB free RAM reported by `free -h`
- [ ] record rental start time

### Task 22: Bootstrap FHE VPS + scp local artifacts

**Files:** none on local; outputs land on the VPS

- [ ] scp `setup.sh` to the FHE VPS (same script reused from Task 19, possibly with the same branch fix)
- [ ] run `setup.sh` on the FHE VPS
- [ ] scp `models/out/weights_fhe.pth` from local to `~/ppiav/models/out/weights_fhe.pth` on the VPS (avoids re-training on the CPU box)
- [ ] **manual verify** over SSH: `python -c "import torch, orion_compiler; print('python ok')"`, `go version`, `ls -la ~/ppiav/models/out/weights_fhe.pth`, `free -h | head -2`

### Task 23: Compile model + prepare stratified batch on FHE VPS

**Files:** outputs land on the VPS

- [ ] on the VPS, in a `nohup`-wrapped block (the compile peaks at ~26 GB RSS, ~6 min wall clock at logn16 per Orion's measurements):
  ```sh
  cd ~/ppiav/models
  source ../.venv/bin/activate
  uv run python -m models.compile --variant fhe --config logn16 \
      --weights ./out/weights_fhe.pth --output ./out/logn16/model.orion
  uv run python -m models.prepare_samples --batch 10 --stratified --with-ref-logit \
      --data-dir ./data/UTKFace --out-dir ./out/inputs --out-manifest ./out/eval_inputs.json
  ```
- [ ] **manual verify**: `~/ppiav/models/out/logn16/model.orion` present (~1.75 GB); `~/ppiav/models/out/logn16/compile.json` present and valid JSON; `~/ppiav/models/out/eval_inputs.json` has exactly 10 images with `label=0` x5 and `label=1` x5

### Task 24: Run the eval pipeline on FHE VPS

**Files:** outputs at `~/ppiav/results/phase2/eval-<ts>/` on the VPS

- [ ] on the VPS, in a `nohup`-wrapped block (expected wall clock ~1 h: keygen ~3 min + 10 × (encrypt + infer + mac + partial + finalize ≈ 4-5 min each) + per-CLI Orion-load overhead):
  ```sh
  cd ~/ppiav
  source ./bench/.venv/bin/activate  # or however bench's venv is wired post-bootstrap
  nohup python -m bench.eval --inputs ./models/out/eval_inputs.json --orion ./models/out/logn16 \
      > ~/ppiav/eval.log 2>&1 &
  ```
- [ ] watch RSS via `watch -n 5 'free -h | head -2'` — must stay below 125 GiB total (logn16 peak is ~114 GB; ~10 GB headroom). If OOM risk surfaces, escalate to `cpu.96.512.640` (per Orion's contingency at `c3ae-vps-runs.md:471`)
- [ ] **manual verify** after completion: `~/ppiav/results/phase2/eval-<ts>/summary.md` exists and renders cleanly; `~/ppiav/results/phase2/eval-<ts>/plots/` has all 7 PNGs; FPR/FNR/accuracy line present; noise + SNR stats present

### Task 25: Capture results to local

**Files:**

- Create (local): `/home/butvinm/Dev/ppiav/results/phase2/eval-<ts>/summary.md` + `plots/*.png` + per-image `decoded.json`
- Optional gitignored capture: per-image `*.bin` artifacts and `keys/*.bin` (multi-GB; skip)

- [ ] from local: `rsync -av --exclude '*.bin' ubuntu@<fhe-ip>:~/ppiav/results/phase2/eval-<ts>/ /home/butvinm/Dev/ppiav/results/phase2/eval-<ts>/`
- [ ] **manual verify**: local `summary.md` + 7 PNGs + per-image `decoded.json` and timing JSONs present
- [ ] commit the captured artifacts to git on the working branch: `git add results/phase2/eval-<ts>/summary.md results/phase2/eval-<ts>/plots/*.png results/phase2/eval-<ts>/keygen.json results/phase2/eval-<ts>/img_*/*.json results/phase2/eval-<ts>/img_*/decoded.json` (specific files, never `git add .`); commit message like `bench: capture eval-<ts> results from VPS run`

### Task 26: Tear down FHE VPS

**Files:** none

- [ ] verified Task 25 succeeded (results committed locally)
- [ ] `openstack --os-cloud immers server delete ppiav-bench-eval-fhe --wait`
- [ ] **manual verify**: `openstack --os-cloud immers server list | grep ppiav-bench-eval` returns nothing
- [ ] record rental end + total billed hours; sanity-check the cost log lines up with measured durations

### Task 27: Review results + verify acceptance criteria

**Files:** none

- [ ] open `results/phase2/eval-<ts>/summary.md` and read the tables: FPR + FNR + accuracy populated; noise mean within reasonable order of magnitude (likely 10^-4 to 10^-2 absolute); SNR > 10 for most images; per-step time + RSS tables non-empty; byte table sums to a sensible total; all 7 plots open as valid PNGs
- [ ] verify all Implementation Step checkboxes 1-26 are marked `[x]`
- [ ] verify no `⚠️` blockers remain
- [ ] if any metric looks off, document in a new ➕ task with diagnosis; do NOT move to Task 28 until resolved

### Task 28: Move plan to completed/

**Files:**

- Move: this plan file → `/home/butvinm/Dev/ppiav/docs/plans/completed/20260515-bench-eval-redesign.md`

- [ ] `mkdir -p /home/butvinm/Dev/ppiav/docs/plans/completed`
- [ ] `git mv docs/plans/20260515-bench-eval-redesign.md docs/plans/completed/`
- [ ] commit with message like `docs(plans): complete bench-eval-redesign`

## Post-Completion

_Items requiring manual intervention or external systems — informational, no checkboxes_

**Thesis methodology paragraph** (write into the thesis chapter):

- **Single keygen reused across all 10 images.** This is a benchmark deviation from the protocol's normal single-use session lifecycle. The protocol's noise-flooding parameter σ_flood = 2^16 (`internal/protocol/params.go`) is calibrated assuming bounded re-use of the same secret share; the bench's q=10 PartialDecrypts is well within budget (averaging across q queries reduces effective σ by √q ≈ 3.2, leaving ~14 bits of smudging headroom in coefficient space). No key-recovery attack is plausible at this scale. The reported noise distribution characterizes "within one fixed key bundle" rather than "across freshly generated bundles" — for a single-session-per-user production deployment, the former is the more useful measurement.
- **10 stratified samples → wide FPR/FNR confidence intervals.** One flip = 20 percentage points in either FPR or FNR. Frame as proof-of-concept measurement; bump to 20 images (~40 min additional VPS time) only if reviewer feedback requires it.
- **Noise reference is the PyTorch FHE-quadratic model**, not Orion's cleartext evaluator (the `orion-v2-evaluator` package is prohibited per the repo's `feedback_orion_evaluator_python_prohibited.md` convention). Reported noise mixes CKKS evaluation noise with PyTorch-vs-circuit quantisation drift; this is consistent with how cleartext FPR/FNR is already computed by `models/eval.py`.
- **Network plot uses simple model:** bytes ÷ bandwidth, no RTT, sequential single-channel transfer at full bandwidth, no compute-transfer overlap. Likely overestimates total session time by 10-30% at high bandwidth where overlap matters; at 1 Mbps transfer dominates and the simple model is essentially exact.

**Optional refinements** (only if thesis review surfaces a need):

- Bump batch size to 20 (adds ~40 min of VPS time, halves FPR/FNR CI width).
- If Phase 4 lattigo-hierkeys lands, GLK master vs full sizes will diverge naturally — rerun the eval to capture the bandwidth improvement; the artifact pipeline already supports this since they're separate files.
- If the SNR strip plot looks too sparse, add a kernel density overlay; alternatively bump batch size to 20 for a more populated distribution.
