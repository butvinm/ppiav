# Bench redesign v2 — message-named wires, full key inventory, fine-grained per-step time+RSS, plain vs FHE accuracy

## Overview

The current bench (after the 2026-05-15 redesign at `docs/plans/completed/20260515-bench-eval-redesign.md`) already gives correct per-process peak RSS, per-party keygen sub-step granularity, and protocol verdict accuracy. Four gaps remain:

1. **Wire-size table + plot label messages by filename** (`keys/rlk.bin`, `img/result_ct.bin`). They should label by **protocol message** (`VClientGaloisShare`, `VAgentRLKRound1Share`, `VServiceResultCT`, etc.) mapped to the actors+payloads in `docs/protocol.puml`. Filenames are an artifact convention; the thesis cares about messages on the wire.
2. **Key inventory is incomplete.** Only keys that happen to land on disk in `keys/` are measured. Per-party shares (`pk_c`, `pk_a`, `rlk_c^{(1)}`, `rlk_a^{(1)}`, `rlk_c^{(2)}`, `rlk_a^{(2)}`, `gks^{master}_c`, `gks^{master}_a`) are computed in-memory and never sized. The derived agent-side `gks^{auth}` (built on every `mac` from the master bundle) and the (already-on-disk) `gks^{infer}` should both be visibly accounted for in the inventory.
3. **Per-image stages emit one timing sample each.** `encrypt` / `infer` / `mac` / `partial-decrypt` / `finalize` are opaque blocks. Keygen has per-party sub-steps; the protocol stages should follow the same pattern so the report can attribute "FHE inference compute" separately from "load eval keys", and "MAC compute" separately from "derive auth-atom keys".
4. **Accuracy table reports FHE only.** Each manifest entry has `ref_logit` (the cleartext PyTorch reference). Applying the same `m > 0` Accept/Reject rule (per `/home/butvinm/Dev/ppiav/internal/vagent/finalize.go:20-22`) gives a directly comparable plaintext verdict on the same batch. We should publish a side-by-side plain-C3AE vs FHE-C3AE accuracy / FPR / FNR comparison.

Out of scope for this plan: changing the protocol itself, adding new ciphertext artifacts, or running a separate plaintext-only evaluation pass. The plaintext baseline is derived from `ref_logit` already present in `eval_inputs.json`.

## Context (from discovery)

- **Existing bench harness** (`/home/butvinm/Dev/ppiav/internal/bench/bench.go`): `Sample` already has a `Bytes uint64` field populated by `MeasureWithSize`. Per-sub-step `Sample.Bytes` is the cheap way to capture in-memory share sizes without writing extra files to disk.
- **Existing per-party keygen instrumentation** (`/home/butvinm/Dev/ppiav/cmd/ppiav-cli/keygen.go:59-97`): `keygen` already runs each Gen/Agg as a separate `bench.Measure` and appends to one Run. Pattern to follow for `infer`, `mac`, `finalize`, `partial-decrypt`.
- **Per-image subcommands emit ONE sample each**: `encrypt.go:74`, `infer.go:86`, `mac.go:115`, `partial_decrypt.go:72`, `finalize.go:108` — each wraps the whole work in a single `bench.Measure("<stage>", ...)`. These are the call-sites to refactor for fine-grained per-step samples.
- **Verdict rule** (`/home/butvinm/Dev/ppiav/internal/vagent/finalize.go:20-22`): `m > 0 → Accept`, else `Reject`. Auth-fail produces `Unknown` on the FHE side. Plaintext has no Auth, so plaintext verdict = `ref_logit > 0 ? Accept : Reject` — no `Unknown`.
- **Aggregator and labels** (`/home/butvinm/Dev/ppiav/bench/bench/eval.py`, `/home/butvinm/Dev/ppiav/bench/bench/_labels_ru.py`, `/home/butvinm/Dev/ppiav/bench/bench/plots_eval.py`): the byte-rows currently come from `_per_message_bytes` which `os.stat`s the `keys/` and `img_0/` directories blindly. The labels module already carries per-party sub-step Russian strings — we add a message catalog alongside.
- **Protocol wire artifacts already on disk**: `keys/{pk_eval.bin, pk_top.bin, rlk.bin, gks_master.bin, gks_infer.bin, sid.txt, params.json}` + `img_<i>/{input_ct.bin, result_ct.bin, auth_ct.bin, client_share.bin}`. The aggregated `pk_eval`, `pk_top`, `rlk` are NOT on the wire (each party reconstructs them locally). `gks_master.bin` IS on the wire (`docs/protocol.puml:66`). `gks_infer.bin` is service-local derived — never transmitted.

## Development Approach

- **Testing approach**: Regular (code first, then tests). The bench is observational scaffolding around already-tested protocol code; tests focus on the new pure-Python catalog logic and plaintext classifier, not on the Go instrumentation calls (those are tested by their existing protocol-level tests).
- **No tests added to** `models/` ML pipeline files per `feedback_no_ml_harness_tests.md`. The new Python code lives in `bench/bench/` and IS test-worthy (catalog mapping, plaintext classifier).
- Atomic commits per task; never `git add .`.
- Update this plan file inline if scope changes.

## Testing Strategy

- **Unit tests (Python)**: catalog produces the expected `(party_from, party_to, label, bytes_source)` for every protocol message; plaintext classifier on a fixture batch reproduces a known confusion matrix.
- **Unit tests (Go)**: the existing pipeline test at `/home/butvinm/Dev/ppiav/cmd/ppiav-cli/pipeline_test.go` should keep passing — it asserts the e2e chain works (in-process, no CLI subprocess, no per-step JSONs). We do NOT extend it with new sub-step-name assertions: the test never invokes `runInfer` / `runMAC` / `runFinalize` and never produces `infer.json` / `mac.json` / `finalize.json`. The new sub-step Sample names are validated post-VPS-run by inspecting `summary.md` (Task 10).
- **End-to-end smoke**: run `python -m bench.eval --aggregate-only` on a committed fixture batch dir under `bench/tests/fixtures/` to validate the new summary.md sections render. **No full LogN=16 run is required for plan completion** — that runs on VPS as part of normal eval.
- No e2e UI tests (this project's e2es are the protocol smoke tests, not browser-driven).

## Progress Tracking

- mark completed items with `[x]` immediately when done
- add newly discovered tasks with ➕ prefix
- document issues/blockers with ⚠️ prefix

## Solution Overview

Five-layer change:

1. **Go instrumentation** (`cmd/ppiav-cli/*.go`): for `infer`, `mac`, `finalize`, split the single `bench.Measure(stage, ...)` into 2–4 nested `bench.Measure(stage.substep, ...)` calls following the same pattern keygen already uses. Each per-image JSON now contains multiple Samples instead of one. **In keygen.go**, switch the per-share Gen sub-step measurements from `Measure` to `MeasureWithSize` — using lattigo's O(1) `.BinarySize()` accessor inside the closure (NOT a full `MarshalBinary()` round-trip, which would inflate the wall-time reading). `partial-decrypt` is NOT split: noise flooding lives inside lattigo's `PartialDecrypt` (smudged KeySwitchShare), and there is no clean Go-side boundary between decrypt and noise-flood to put a Measure call between.
2. **Message catalog** (new `bench/bench/_messages.py`): authoritative list of protocol messages with `(message_id, sender, receiver, label_ru, bytes_source)`. `bytes_source` is either a relative file path (e.g. `keys/gks_master.bin`) OR a `Sample.Bytes` lookup (e.g. `keygen.pk.client_gen` → share size). One source of truth, imported by aggregator and plot module.
3. **Aggregator rework** (`bench/bench/eval.py`): `_per_message_bytes` becomes message-catalog-driven. Builds rows in catalog order (chronological, by phase). Two derived sections in `summary.md`:
   - **`## Per-message bytes`** keyed by message-id, now naming `VClientGaloisShare`, `VAgentRLKRound2Ack`, etc.
   - **`## Key inventory`** — every key in the system (shares, aggregated, derived-in-memory), tagged with `{on_wire | local_only | derived}` and its bytes.
4. **Sub-step propagation**: aggregator extracts per-substep Samples from each per-image JSON and pushes them into the existing per-party table (`_party_step_table_md`) so it shows e.g. `VService — infer.load_keys`, `VService — infer.exec`, `VAgent — mac.derive_auth_keys`, `VAgent — mac.compute_ct`. The Gantt timeline in `plots_eval.py` uses the same finer-grained Samples.
5. **Plain-vs-FHE accuracy block**: `eval.py` computes a second confusion matrix from `ref_logit > 0` on each manifest entry. `summary.md` gets a `## Accuracy: plain vs FHE C3AE` table with side-by-side metrics. `plots_eval.py` adds `accuracy_plain_vs_fhe.png` — a grouped-bar chart for {accuracy, FPR, FNR}.

### Granularity recommendation (the "you tell me" part)

My read after looking at the subcommands: **method-level per-party split is right almost everywhere — the exceptions are `infer` and `mac` (which need finer splits), and `partial-decrypt` (which can't be split further without lattigo-side hooks).**

Crucially: in both `infer.go` and `mac.go`, the **load + setup work currently happens OUTSIDE the `bench.Measure` block** (`infer.go:51-65`, `mac.go:51-93`). So this isn't just about reporting load cost separately — it's about reporting load cost AT ALL. Right now the bench timing for `infer` excludes `readRelinearizationKey`, `readGaloisKeys`, `readCiphertextPath`; the bench timing for `mac` excludes `readMasterKeys` (recorded only as a metadata field `read_gks_master_seconds`) and `vagent.NewWithState` (the hierkeys derivation, exposed only as `derive_gks_auth_seconds` metadata). The refactor must MOVE these loads/setups INTO the new sub-step Measure closures, not just relabel what's already measured.

- `infer.go` — currently bench-timed: `svc.Infer` only. Refactor: move `readRelinearizationKey` + `readGaloisKeys(artifactGKSInfer)` into a new `infer.load_keys` Measure (this also captures `vservice.NewWithState`'s share of work); move `readCiphertextPath` into `infer.load_input_ct`; keep `svc.Infer` in `infer.exec`; move `writeCiphertextPath` into `infer.serialize_result`. **Result: 4 nested Measures replacing 1.**
- `mac.go` — currently bench-timed: `agent.BuildAuthenticatedCt` only. Refactor: move `readMasterKeys` + `vagent.NewWithState` (where hierkeys derivation runs) into a new `mac.derive_auth_keys` Measure; keep `BuildAuthenticatedCt` in `mac.compute_ct`. The existing `derive_gks_auth_seconds` and `read_gks_master_seconds` metadata stay — they're a useful cross-check against the new Sample wall_ms. For `gks^{auth}` size: use `MeasureWithSize` only IF `agent` exposes a `DerivedAuthKeyBundle()` getter; otherwise leave Bytes=0 with a clear log line (see Technical Details).
- `finalize.go` — currently bench-timed: `FinalizeDecryption` only. Split into `finalize.final_decrypt` (the verifiable decryption + Auth verification — both happen inside the same lattigo+authchain call) + `finalize.verdict_compute` (the post-call `m > 0 ? Accept : Reject` decision). The split here is mostly bookkeeping since `verdict_compute` is sub-microsecond, but it documents the conceptual separation.
- `partial-decrypt.go` — **NOT split.** `client.PartialDecrypt(ct)` is a single lattigo call; the smudged KeySwitchShare integrates noise flooding internally. Splitting would require lattigo-side hooks (out of scope). Keep one `partial-decrypt` Sample.
- `encrypt.go` — **NOT split.** Single CKKS encrypt; not worth splitting.

If you want still-finer (e.g. layer-by-layer Orion inference timing), that's a separate plan — Orion's evaluator would need timing hooks, which is upstream-of-ppiav work.

### Message naming convention

Per the user request "messages names without cryptic things like rlk. Just say, VClientRLKRound1": I keep the crypto term (`RLK`, `PK`, `GKS`) — these are not cryptic, they are the canonical thesis abbreviations — but always prefix with the sender role and add a round/direction suffix where ambiguous. Display label in Russian for the table/plot (the thesis is Russian); the catalog uses CamelCase Python identifiers internally.

Concrete catalog (drawn from `docs/protocol.puml`). All share messages get an explicit `Share` suffix for symmetry. Tiny handshake/ack messages with no on-disk artifact use `Synthetic(estimated_bytes)` rather than implying a Sample.Bytes that doesn't exist:

| message_id                | sender → receiver | display_ru                                | bytes_source                                   |
| ------------------------- | ----------------- | ----------------------------------------- | ---------------------------------------------- |
| `VAgentSessionInit`       | VAgent → VService | "Запрос сессии (агент → сервис)"          | `Synthetic(64)` — JSON envelope                |
| `VServiceSessionResponse` | VService → VAgent | "Параметры протокола + sid"               | `keys/params.json` + `keys/sid.txt`            |
| `VAgentSessionParams`     | VAgent → VClient  | "Параметры протокола (агент → клиент)"    | mirrors above                                  |
| `VClientPKShare`          | VClient → VAgent  | "Доля pk клиента"                         | `Sample.Bytes[keygen.pk.client_gen]`           |
| `VAgentPKShare`           | VAgent → VClient  | "Доля pk агента"                          | `Sample.Bytes[keygen.pk.agent_gen]`            |
| `VClientRLKRound1Share`   | VClient → VAgent  | "Доля rlk клиента, раунд 1"               | `Sample.Bytes[keygen.rlk-r1.client_gen]`       |
| `VAgentRLKRound1Share`    | VAgent → VClient  | "Доля rlk агента, раунд 1"                | `Sample.Bytes[keygen.rlk-r1.agent_gen]`        |
| `VClientRLKRound2Share`   | VClient → VAgent  | "Доля rlk клиента, раунд 2"               | `Sample.Bytes[keygen.rlk-r2.client_gen]`       |
| `VAgentRLKRound2Ack`      | VAgent → VClient  | "Подтверждение rlk"                       | `Synthetic(32)` — JSON ack                     |
| `VClientGaloisShare`      | VClient → VAgent  | "Master доля gks клиента"                 | `Sample.Bytes[keygen.galois.client_gen]`       |
| `VAgentEvalKeyBundle`     | VAgent → VService | "rlk + gks_master → сервису"              | `keys/rlk.bin` + `keys/gks_master.bin`         |
| `VServiceKeysAck`         | VService → VAgent | "Подтверждение установки ключей"          | `Synthetic(32)` — JSON ack                     |
| `VAgentGaloisAck`         | VAgent → VClient  | "Подтверждение gks"                       | `Synthetic(32)` — JSON ack                     |
| `VClientInputCT`          | VClient → VAgent  | "Шифротекст изображения (клиент → агент)" | `img_<i>/input_ct.bin`                         |
| `VAgentInputCT`           | VAgent → VService | "Шифротекст изображения (агент → сервис)" | `img_<i>/input_ct.bin` (forwarded, same bytes) |
| `VServiceResultCT`        | VService → VAgent | "Шифротекст результата"                   | `img_<i>/result_ct.bin`                        |
| `VAgentAuthCT`            | VAgent → VClient  | "Аутентифицированный шифротекст"          | `img_<i>/auth_ct.bin`                          |
| `VClientPartialShare`     | VClient → VAgent  | "Частично расшифрованный шифротекст"      | `img_<i>/client_share.bin`                     |

Renames from the previous draft: `VClientGaloisShares` → `VClientGaloisShare` (singular, consistent), `VAgentInferenceKeys` → `VAgentEvalKeyBundle` (unambiguous — there is no `gks_infer` on this wire, only `rlk + gks_master`), `VClientRLKRound{1,2}` and `VAgentRLKRound1` get `Share` suffix, `VClientShare` → `VClientPartialShare` (less collision-prone). The `Synthetic(N)` sentinel — defined in `bench/bench/_messages.py` as a small constant per message — explicitly distinguishes "tiny estimated handshake" from "real measurement".

And the **key inventory** (separate from messages; some keys are never transmitted):

| key                                                        | location               | on_wire                     | bytes_source                         |
| ---------------------------------------------------------- | ---------------------- | --------------------------- | ------------------------------------ |
| `sk_c`                                                     | client-local           | no                          | `keys/sk_c.bin`                      |
| `sk_a`                                                     | agent-local            | no                          | `keys/sk_a.bin`                      |
| `pk_c`                                                     | share                  | yes (in `VClientPKShare`)   | `Sample.Bytes[keygen.pk.client_gen]` |
| `pk_a`                                                     | share                  | yes (in `VAgentPKShare`)    | `Sample.Bytes[keygen.pk.agent_gen]`  |
| `pk_eval` (aggregated)                                     | both parties + service | derived                     | `keys/pk_eval.bin`                   |
| `pk_top`                                                   | derived                | yes (with infer keys)       | `keys/pk_top.bin`                    |
| `rlk_c^{(1)}`, `rlk_a^{(1)}`, `rlk_c^{(2)}`, `rlk_a^{(2)}` | shares                 | yes                         | `Sample.Bytes` per substep           |
| `rlk` (aggregated)                                         | both parties + service | derived                     | `keys/rlk.bin`                       |
| `gks^{master}_c`, `gks^{master}_a`                         | shares                 | yes (master_c)              | `Sample.Bytes` per substep           |
| `gks^{master}` (aggregated)                                | agent + service        | yes (`VAgentEvalKeyBundle`) | `keys/gks_master.bin`                |
| `gks^{auth}`                                               | derived agent-local    | no                          | `Sample.Bytes[mac.derive_auth_keys]` |
| `gks^{infer}`                                              | derived service-local  | no                          | `keys/gks_infer.bin`                 |
| `mac_key`                                                  | agent-local            | no                          | `keys/mac_key.bin`                   |

## Technical Details

### Sample.Bytes semantics for shares

Important: `bench.MeasureWithSize` runs the size-returning closure **inside** the timed window (`internal/bench/bench.go:97-107`). Marshaling a multi-GB share inside that closure would inflate `wall_ms` by the marshal cost — distorting exactly the metric the per-party table reports.

Lattigo and lattigo-hierkeys structures implement `BinarySize() int` (an O(1) accessor that reports the serialized length without actually serializing). That's what we use:

```go
sample, err := bench.MeasureWithSize("keygen.pk.client_gen", func() (uint64, error) {
    sk_c, pk_c = generatePKShare(...)
    return uint64(pk_c.BinarySize()), nil
})
```

⚠️ **Caveat: not every share type may expose `BinarySize()`.** Verification order during implementation:

1. Probe each share type with a small Go test that calls `.BinarySize()` (compile-time check is enough).
2. If a type lacks `BinarySize()` but has `MarshalBinary()`: add a SIBLING measurement step (e.g. `keygen.pk.client_serialize`) that does the marshal AFTER the gen Measure ends. The gen sample carries `Bytes=0`; the serialize sample carries the actual size. This keeps gen wall_ms honest.
3. If a type has neither: record `Bytes=0` on the gen Sample, log a clear "size not measurable for <type>" line, and add an explicit `bytes_source = Unavailable("type lacks size accessor")` in `_messages.py` so the bytes table renders `—` rather than `0` for that message. Don't silently report 0.

The `gks^{auth}` size measurement (the derived agent-local bundle from `mac.derive_auth_keys`) requires `vagent` to expose a getter — see the `mac.go` checklist in Task 2 for details. If the getter can't be added cheaply, Bytes=0 + `Unavailable` is the documented fallback.

### Aggregator data flow

`bench/bench/eval.py`:

- `aggregate()` first loads `keygen.json` (Run with many Samples) plus per-image `*.json` (each now a Run with multiple Samples).
- Builds a `samples_by_name: dict[str, list[Sample]]` flat index across all Runs.
- `_messages.MESSAGES` (the catalog list) drives the per-message-bytes section. For each message, the resolver dispatches on `bytes_source` type:
  - `FilePath(rel)` → `(batch_dir / rel).stat().st_size`; if the file is missing, return `None` (renders as `—` in the table)
  - `SampleBytes(name)` → `samples_by_name[name][0].Bytes`. Keygen sub-step samples are single-valued (one Run per name) — no averaging needed
  - `Synthetic(n)` → `n` (constant)
  - `Unavailable(reason)` → `None` with reason surfaced in a footnote
  - **Per-image messages** (`VClientInputCT`, `VServiceResultCT`, `VAgentAuthCT`, `VClientPartialShare`) reference filenames under `img_<i>/`; the resolver picks `img_0/` as the canonical sample (all images produce identically-sized ciphertexts at fixed CKKS params, so averaging is unnecessary)
- Same flat index drives the per-party time+RSS table: the existing `_party_step_table_md` keeps its shape, but the iteration list comes from `_messages.STEPS` (the new step catalog) rather than the hardcoded `_PER_IMAGE_STEPS` tuple.

### Plaintext baseline

```python
def _classify_plain(manifest_by_idx: dict[int, dict[str, Any]]) -> dict[str, int | float]:
    verdicts = ["accept" if e["ref_logit"] > 0 else "reject" for e in manifest_by_idx.values()]
    labels = [int(e["label"]) for e in manifest_by_idx.values()]
    return _classify(verdicts, labels)  # reuses existing tp/tn/fp/fn/fpr/fnr/accuracy
```

No `Unknown` in the plaintext column (no Auth gate). The comparison table simply shows the plaintext column with `unknown = 0`, FHE column with whatever it is. The plot is a grouped bar (3 groups × 2 bars: plain vs FHE for accuracy / FPR / FNR).

## What Goes Where

- **Implementation Steps** (`[ ]`): Go instrumentation refactors, new Python catalog module, aggregator rework, plot updates, tests, summary.md rendering.
- **Post-Completion**: full LogN=16 VPS rerun + visual check of the new `summary.md` + plots (operator runs `make eval` on `cpu.16.128.240` with the existing `vps` skill, then `git diff` on the generated artifacts).

## Implementation Steps

### Task 1: Upgrade Orion to 2.1.5 (Go + Python compiler)

**Files:**

- Modify: `go.mod`, `go.sum`
- Modify: `models/pyproject.toml`, `models/uv.lock`

Orion shipped 2.1.5 with an optimized evaluator. Land this first so all subsequent bench instrumentation (Tasks 2–3) and the final VPS run (Task 10) report numbers from the new evaluator — otherwise we'd publish 2.1.4 timings that don't match the next release.

- [x] in `go.mod`, bump `github.com/butvinm/orion/v2 v2.1.4` → `v2.1.5`; then `go mod tidy`
- [x] in `models/pyproject.toml`, change `"orion-v2-compiler"` to `"orion-v2-compiler>=2.1.5,<3"` (pin the floor; let uv pick the latest matching patch)
- [x] `cd models && uv lock --upgrade-package orion-v2-compiler` — also re-resolves the transitive `orion-v2-lattigo` if upstream bumped it
- [x] run `go test ./...` (LogN=14 fast variants only — no `PPIAV_RUN_HEAVY=1`) to catch any API breakage in the Go evaluator path. Most likely zero changes; if anything breaks, the import surface in `internal/vservice/` is the place to fix.
- [x] run `cd models && uv run pytest && uv run ruff check . && uv run mypy models` to catch Python compiler API breakage (pytest: 0 items collected — no ML test suite per `feedback_no_ml_harness_tests.md`; ruff/mypy errors are pre-existing in `models/c3ae.py` + `models/eval.py`, unrelated to dep bump)
- [x] **compiled-model compatibility check**: read the Orion 2.1.5 release notes / CHANGELOG. If 2.1.5 changes the manifest format (`models/out/logn16/orion_manifest.json` schema or bytecode binary layout), the existing compiled model is stale — flag this and recompile via the upstream `models/compile.py` flow BEFORE Task 10. If 2.1.5 is evaluator-only ("optimized evaluator" suggests this), the existing artifact is fine; document the conclusion either way in the commit message. **Conclusion: Orion 2.1.5 is evaluator-only (PR #28: pre-encode LinearTransformations at load time, evaluator API unchanged, max_diff=0.0000 on `verify_fhe.py --tol 0.05`). Existing `models/out/logn16/` manifest + bytecode remain compatible.**
- [x] commit the dep bump as one atomic commit (`chore(deps): bump orion to 2.1.5 for optimized evaluator`)

### Task 2: Split per-image subcommands into sub-step samples (`infer` / `mac` / `finalize`)

**Files:**

- Modify: `cmd/ppiav-cli/infer.go`
- Modify: `cmd/ppiav-cli/mac.go`
- Modify: `cmd/ppiav-cli/finalize.go`
- Modify (maybe): `internal/vagent/` — add read-only accessor for `sessionState.gksAuth` if not already exposed

All three subcommands follow the same refactor pattern: take the single `bench.Measure(stage, ...)` block and split it into multiple nested closures, MOVING pre-Measure loads/setup work inside the new closures so previously-invisible setup cost is captured.

**`infer.go` — 4 sub-step samples:**

- [x] MOVE the pre-Measure loads (`readRelinearizationKey`, `readGaloisKeys(artifactGKSInfer)`, and `vservice.NewWithState`) currently at lines 51-74 INTO a new `bench.Measure("infer.load_keys", ...)` closure — the run's setup work is currently bench-invisible. Expect this to dominate at LogN=16: Orion 2.1.5 eagerly pre-encodes LinearTransformations inside `LoadModel` (PR #28), pushing `load_s` from ~13s to ~265s per call.
- [x] MOVE `readCiphertextPath(*inCt)` (line 62-65) into a new `bench.Measure("infer.load_input_ct", ...)` closure
- [x] keep `svc.Infer(sid, ct)` inside `bench.Measure("infer.exec", ...)` (the Orion-evaluator call — was previously labeled `infer`). Expect ~5.6× speedup vs 2.1.4 per PR #28.
- [x] MOVE `writeCiphertextPath` (line 100-103) into a new `bench.Measure("infer.serialize_result", ...)` closure
- [x] append all four Samples to one Run named `"infer"`; preserve existing Run.Metadata fields

**`mac.go` — 2 sub-step samples + hierkeys-derived size:**

- [x] MOVE the pre-Measure work (`readMasterKeys` at line 78 + `vagent.NewWithState` at lines 98-106, which is where hierkeys derivation runs) INTO a new `bench.MeasureWithSize("mac.derive_auth_keys", ...)` closure. Use `BinarySize()` on the derived `gks^{auth}` bundle by summing `BinarySize()` over each `*rlwe.GaloisKey` in the `[]*rlwe.GaloisKey` slice (see `/home/butvinm/Dev/ppiav/internal/vagent/agent.go:81` — `gksAuth` is a slice, not a single object)
- [x] check whether `vagent` exposes an accessor for `sessionState.gksAuth`. If not, add a minimal one in `internal/vagent/` returning the slice (read-only accessor; safe). Do NOT add a getter that triggers re-derivation. (`*rlwe.GaloisKey.BinarySize()` is confirmed available in lattigo `core/rlwe/keys.go:613`.)
- [x] keep `agent.BuildAuthenticatedCt` inside a new `bench.Measure("mac.compute_ct", ...)` closure
- [x] preserve the existing `derive_gks_auth_seconds` and `read_gks_master_seconds` Run.Metadata fields — they're now a useful cross-check against the new Sample wall_ms

**`finalize.go` — 2 sub-step samples:**

- [x] replace the single `bench.Measure("finalize", ...)` with `finalize.final_decrypt` (wraps `FinalizeDecryption` — the verifiable decryption + Auth verification, both inside one lattigo+authchain call) and `finalize.verdict_compute` (wraps the post-call `m > 0 ? Accept : Reject` decision and `buildDecodedOutput`)

**Out of scope (documented exceptions):**

- `partial-decrypt` is NOT split. `client.PartialDecrypt(ct)` is a single lattigo call wrapping decrypt + noise-flood (smudged KeySwitchShare) with no clean Go-side boundary. Splitting would require lattigo-side hooks. `partial_decrypt.go` keeps emitting one `partial-decrypt` Sample.
- `encrypt` is NOT split — single CKKS encrypt, not worth splitting.

**Verify:**

- [x] run `go test ./cmd/ppiav-cli/...` — existing in-process pipeline test must still pass before next task (no new per-step-JSON assertion; sub-step Sample names are validated post-VPS-run in Task 10)
- [x] commit as one atomic commit covering all three subcommand files (the refactor is one conceptual change: "move bench boundaries to capture setup work")

### Task 3: Add `Sample.Bytes` to keygen share sub-steps

**Files:**

- Modify: `cmd/ppiav-cli/keygen.go`

- [x] for each share-emitting sub-step in `keygen.go` (`keygen.pk.client_gen`, `keygen.pk.agent_gen`, `keygen.rlk-r1.client_gen`, `keygen.rlk-r1.agent_gen`, `keygen.rlk-r2.client_gen`, `keygen.rlk-r2.agent_gen`, `keygen.galois.client_gen`, `keygen.galois.agent_gen`), switch from `bench.Measure` to `bench.MeasureWithSize` and return `uint64(share.BinarySize())` (NOT `len(MarshalBinary())`; see Technical Details — marshal inside the closure inflates wall_ms)
- [x] aggregation sub-steps (`*.agent_agg`, `*.client_agg`, `*.service_store`) remain plain `Measure` — they don't produce a new share
- [x] for any share type lacking `BinarySize()`: emit a sibling `*.serialize` sub-step using `MarshalBinary()` and record its length there (keeps gen wall_ms honest). If the type lacks both: record `Bytes=0` + log "size not measurable for <type>" — **N/A**: all four share types in keygen (`multiparty.PublicKeyGenShare`, `RelinearizationKeyGenShare`, `GaloisKeyGenShare`, and the dual-share `VClientPKShare`/`VAgentPKShare` aggregates) expose `BinarySize()` on lattigo v6.2.0; no sibling serialize step needed.
- [x] add a Go test asserting `Sample.Bytes > 0` for each of the eight share sub-steps (or `== 0` with a recorded reason for known-unsupported types)
- [x] run `go test ./cmd/ppiav-cli/...` — must pass

### Task 4: Add `bench/bench/_messages.py` catalog + test fixture

**Files:**

- Create: `bench/bench/_messages.py`
- Create: `bench/tests/test_messages.py`
- Create: `bench/tests/fixtures/sample_batch/` (small JSON-only fixture — see contents below)

- [x] define `MESSAGES: list[Message]` covering every wire message in `docs/protocol.puml` per the catalog table in this plan
- [x] each `Message` has: `id` (str, CamelCase), `sender` ("client"|"agent"|"service"|"resource_service"), `receiver`, `label_ru`, `bytes_source` (one of: `FilePath("keys/...")`, `SampleBytes("keygen.pk.client_gen")`, `Synthetic(estimated_bytes)`, or `Unavailable(reason)`)
- [x] define `KEYS: list[KeyEntry]` with `name`, `location` (client_local | agent_local | service_local | derived_agent | derived_service | aggregated_all), `on_wire` (bool), `bytes_source`
- [x] write `resolve_message_bytes(message, batch_dir, samples_by_name) -> int | None` and `resolve_key_bytes(key, batch_dir, samples_by_name) -> int | None`; `None` for `Unavailable` and for missing files; tests cover both paths
- [x] create `bench/tests/fixtures/sample_batch/` containing: a `keygen.json` with all per-party sub-step Samples (including non-zero `Bytes` on the eight share sub-steps); per-image dirs `img_0/` through `img_3/` each with the new five JSONs (`encrypt.json` with 1 sample, `infer.json` with 4 sub-steps, `mac.json` with 2 sub-steps, `partial-decrypt.json` with 1 sample, `finalize.json` with 2 sub-steps); `eval_inputs.json` with 4 images covering both labels and both `ref_logit` signs; a few placeholder zero-byte `.bin` files where the catalog expects `FilePath` (so size resolution returns `0` rather than `None`)
- [x] write tests: every message in `MESSAGES` resolves against the fixture; every key in `KEYS` resolves; an `Unavailable` test case returns `None` gracefully; missing-file case returns `None` gracefully (delete one `.bin` from the fixture in the test)
- [x] run `cd bench && uv run pytest tests/test_messages.py` — must pass before next task

### Task 5: Rework `_per_message_bytes` + add `_key_inventory_md` in aggregator

**Files:**

- Modify: `bench/bench/eval.py`
- Modify: `bench/bench/_labels_ru.py` (add new section headers if needed)

- [x] in `eval.py`, replace `_per_message_bytes` body with a catalog-driven walk over `_messages.MESSAGES`. Return `list[tuple[message_id, label_ru, sender, receiver, bytes]]`.
- [x] build a `samples_by_name: dict[str, list[Sample]]` index in `aggregate()` covering keygen Run + every per-image Run, pass it into the resolver
- [x] add `_key_inventory_md(batch_dir, samples_by_name)` returning a markdown table with columns: key, location, on_wire, bytes, KiB, MiB
- [x] update `_bytes_table_md` to consume the new row shape (message_id + label) and render columns: `id | сообщение | отправитель | получатель | байт | КиБ | МиБ`
- [x] update `_network_table_md` similarly so bandwidth column is keyed by message_id
- [x] update `bytes.json` cache format to persist the catalog-keyed rows. Schema check is simple: if the loaded JSON's first entry has the old shape (`{"name", "bytes"}` instead of `{"message_id", "label_ru", ...}`), delete the cache file and re-stat. No version migration code — this is a single-developer bench cache, not a persisted user artifact.
- [x] add the new `## Key inventory` section to `aggregate()`'s `sections` list, between bytes and verdict accuracy
- [x] add an aggregator-level test in `bench/tests/test_eval_aggregate.py` that calls `aggregate()` on the fixture from Task 4 and asserts the resulting `summary.md` contains: each expected section header, every message_id from `MESSAGES`, every key from `KEYS`, plain + FHE accuracy columns. This is the contract test for Tasks 5–7 combined. (Task 5: section headers + message_ids + key names asserted; plain + FHE accuracy assertions deferred to Task 6 per plan.)

### Task 6: Plaintext baseline + side-by-side accuracy

**Files:**

- Modify: `bench/bench/eval.py`
- Create: `bench/tests/test_eval_accuracy.py`

(The fixture batch dir was created in Task 4.)

- [x] in `eval.py`, add `_classify_plain(manifest_by_idx)` reusing the existing `_classify` for the math (verdict = `"accept" if ref_logit > 0 else "reject"`, no `Unknown`)
- [x] add `_accuracy_compare_table_md(fhe_stats, plain_stats, n_total)` rendering a 2-column table (plain | FHE) for tp/tn/fp/fn/unknown/fpr/fnr/accuracy
- [x] replace the existing `## Protocol verdict accuracy` section with `## Accuracy: plain vs FHE C3AE` using the new comparison table (Russian section header `## Точность: C3AE открытый текст vs FHE` via `SECTION_HEADERS['accuracy_plain_vs_fhe']`)
- [x] write tests asserting: (a) plain classifier on the fixture gives the expected confusion matrix; (b) FHE classifier on the fixture gives the expected confusion matrix; (c) the rendered comparison table contains both columns
- [x] run `cd bench && uv run pytest` — must pass (50 passed; pre-existing `test_load_run_parses_all_fields` phase1/phase2 mismatch unrelated)

### Task 7: Promote per-image sub-steps into the per-party table

**Files:**

- Modify: `bench/bench/eval.py`
- Modify: `bench/bench/_labels_ru.py`

- [x] in `_labels_ru.py`, add `STEP_NAMES` entries for the new per-image sub-steps: `infer.load_keys`, `infer.load_input_ct`, `infer.exec`, `infer.serialize_result`, `mac.derive_auth_keys`, `mac.compute_ct`, `finalize.final_decrypt`, `finalize.verdict_compute` (with concise Russian labels). `partial-decrypt` keeps its single step name. `encrypt` keeps its single step name.
- [x] add the same keys to `PARTY_BY_STEP` (`infer.*` → service, `mac.*` → agent, `finalize.*` → agent, `partial-decrypt` stays client, `encrypt` stays client)
- [x] in `eval.py`, replace the hardcoded `_PER_IMAGE_STEPS` constant with `PER_IMAGE_STEPS = tuple(_messages.PER_IMAGE_STEPS)` populated from the catalog (the catalog declares: encrypt → infer.load_keys → infer.load_input_ct → infer.exec → infer.serialize_result → mac.derive_auth_keys → mac.compute_ct → partial-decrypt → finalize.final_decrypt → finalize.verdict_compute)
- [x] no legacy single-sample fallback: prior bench runs lived in `results/phase2/eval-*` and are archived. New runs always emit the sub-step shape. If reaggregating a legacy dir fails, the operator regenerates the data — simpler than carrying dead-code fallback paths.
- [x] add a test asserting `_party_step_table_md` rendered against the Task 4 fixture lists each sub-step on its own row with the correct party tag

### Task 8: Plot updates — message-named bytes, plain-vs-FHE accuracy, Gantt sub-step lanes

**Files:**

- Modify: `bench/bench/plots_eval.py`

- [ ] `bytes_per_message.png`: x-axis labels become message_id (e.g. `VClientGaloisShare`), one bar per catalog entry, log-y scale preserved. Add a small color tag for sender party.
- [ ] `bandwidth_per_message.png`: same x-axis renaming
- [ ] new `accuracy_plain_vs_fhe.png`: grouped bar chart, 3 metric groups (accuracy / FPR / FNR), 2 bars each (plain / FHE). Y range [0, 1].
- [ ] `session_timeline_10mbps.png` Gantt: draw each sub-step as its own segment on its party's lane (VService's lane shows `infer.load_keys → infer.load_input_ct → infer.exec → infer.serialize_result` as adjacent blocks; VAgent's lane shows `mac.derive_auth_keys → mac.compute_ct → ... → finalize.final_decrypt → finalize.verdict_compute`). Use the same color family for sub-steps of one parent stage so visual grouping is preserved.
- [ ] no plot tests (matplotlib output isn't unit-testable here); operator validates visually post-VPS run

### Task 9: Verify acceptance criteria

- [ ] every message in `docs/protocol.puml` maps to either a catalog `Message` entry or an explicit "out of scope (resource-service-side)" exclusion
- [ ] every key listed in the Technical Details inventory has a `KEYS` entry
- [ ] `infer`, `mac`, `finalize` each emit ≥ 2 Samples; `encrypt` and `partial-decrypt` keep emitting 1 Sample (documented exceptions)
- [ ] `summary.md` contains all sections: Per-step time+memory by party, Keygen by round, Per-message bytes, **Key inventory**, **Accuracy: plain vs FHE C3AE**, Noise + SNR, Network wire time
- [ ] run `cd bench && uv run pytest && uv run ruff check . && uv run mypy bench tests`
- [ ] run `go test ./...` **without** `PPIAV_RUN_HEAVY=1` (LogN=14 fast variants only — per `feedback_no_logn15_local.md`, LogN=15/16 tests OOM the dev box). VPS handles heavy runs.
- [ ] dry-run the aggregator on the committed fixture: `cd bench && uv run python -m bench.eval --aggregate-only tests/fixtures/sample_batch/` — inspect generated `summary.md`

### Task 10: Rent VPS, run full LogN=16 eval, sync results back

The bench-redesign changes are local-testable on fixture data through Task 9. This task is the real production run that generates the canonical `results/<ts>/summary.md` + `plots/` for thesis inclusion. It depends on the existing `vps` skill (`~/.claude/skills/vps/SKILL.md`) for instance lifecycle and on the documented prerequisite chain in `docs/plans/completed/20260514-orion-integration-training-compilation/`.

**Prerequisites (confirm before renting):**

- [ ] `models/out/weights_fhe.pth` exists locally OR is reproducible from a documented prior VPS run. If missing: run the upstream training plan first (separate from this plan) — typically `rtx4090-1.*` flavor, ~10 min training job. Do not bundle weight regeneration into this task.
- [ ] `models/out/logn16/` (the Orion-compiled manifest + circuit) exists locally OR is reproducible. If missing: run the upstream compile plan first.
- [ ] `models/out/eval_inputs.json` (stratified UTKFace sample manifest) exists OR will be produced by `models.prepare_samples` on the VPS as part of this task — confirm one or the other.
- [ ] `~/.kaggle/kaggle.json` populated (per `reference_kaggle_creds.md`) for the VPS-side UTKFace download if `models/data/UTKFace/` isn't synced from local.

**Flavor + memory envelope:**

- [ ] **Flavor: `cpu.16.128.240`** (the established default). The Q-chain growth from commit `3436bb9` is absorbed by Orion 2.1.5's evaluator optimizations + a tighter GOMEMLIMIT — operator confirmed this is sufficient on this flavor.
- [ ] **`GOMEMLIMIT=100GiB`** — forces Go's GC to keep RSS bounded under the 128 GiB box's available memory (after kernel + sshd + page cache). This is more aggressive than the previous 120 GiB; expect more GC cycles but no OOM.

**Provisioning:**

- [ ] use the `vps create` flow: `openstack --os-cloud immers server create --flavor cpu.16.128.240 --image "Ubuntu 22.04 (Aug 2024) [BIOS]" --network immers --key-name butvinm --wait ppiav-bench-v2`. Capture the IP from the JSON output.
- [ ] confirm SSH reachability: `ssh ubuntu@<IP> 'uname -a'`
- [ ] install runtime deps on the VPS (one-shot ssh): Go (matching `go.mod`'s toolchain line), `uv` for Python, `make`, `npm` (per `operational_ppiav_cli_build_embeds.md` — `cmd/ppiav-cli` transitively imports the web/ embeds, so WASM + SPAs must build first). Apt: `build-essential prettier`. Skip CUDA — eval is CPU-only.

**Sync code + artifacts:**

- [ ] from the local repo: `rsync -av --exclude '.git/' --exclude 'results/' --exclude 'models/data/' --exclude 'models/out/' /home/butvinm/Dev/ppiav/ ubuntu@<IP>:~/ppiav/` — code only
- [ ] sync the heavy artifacts separately (so a failed code-sync doesn't re-upload them): `rsync -av models/out/weights_fhe.pth ubuntu@<IP>:~/ppiav/models/out/` and `rsync -av models/out/logn16/ ubuntu@<IP>:~/ppiav/models/out/logn16/`
- [ ] sync `~/.kaggle/kaggle.json` to VPS if UTKFace download is needed there; or rsync `models/data/UTKFace/` directly if already present locally (whichever is smaller)

**Build + run:**

- [ ] on VPS: `cd ~/ppiav && make phase3` (builds WASM + SPAs + service binaries — also satisfies the `cmd/ppiav-cli` embed dependency per `operational_ppiav_cli_build_embeds.md`)
- [ ] on VPS: `go build -o bin/ppiav-cli ./cmd/ppiav-cli`
- [ ] on VPS: `cd bench && uv sync` (creates the venv per project Python convention — never the system Python)
- [ ] on VPS: `cd ~/ppiav && GOMEMLIMIT=100GiB uv run --directory bench python -m bench.eval --inputs models/out/eval_inputs.json --orion models/out/logn16` — runs keygen + the per-image chain end-to-end. Expect tens of minutes per image at LogN=16; full 10-image batch typically multi-hour. Orion 2.1.5's optimized evaluator should shorten `infer.exec` vs prior runs — track the delta in `summary.md`.
- [ ] monitor: `ssh ubuntu@<IP> 'tail -f ~/ppiav/results/<ts>/.log'` or run inside `tmux`/`screen` so the SSH session can drop without killing the job

**Sync results back + validate:**

- [ ] from local: `rsync -av ubuntu@<IP>:~/ppiav/results/<ts>/ /home/butvinm/Dev/ppiav/results/<ts>/` — pulls every per-image dir + summary.md + plots/
- [ ] locally: `cd bench && uv run python -m bench.eval --aggregate-only ../results/<ts>/` — re-renders summary.md + plots/ against the new `bench/_labels_ru.py` strings (safe to re-run as many times as label tweaks need)
- [ ] visually inspect `summary.md`:
  - [ ] every message row named (`VClient*`, `VAgent*`, `VService*`) — no raw `keys/rlk.bin`-style filenames
  - [ ] key inventory lists every share + derived key from the catalog table
  - [ ] every new per-image sub-step appears as its own row in the per-party table: `infer.load_keys`, `infer.load_input_ct`, `infer.exec`, `infer.serialize_result`, `mac.derive_auth_keys`, `mac.compute_ct`, `finalize.final_decrypt`, `finalize.verdict_compute`. `encrypt` and `partial-decrypt` each remain a single row.
  - [ ] `infer.load_keys` wall_ms is the new dominant cost (~4 minutes per image at LogN=16) — confirms the PR #28 eager-LT-encode pre-pass landed where the bench expects it
  - [ ] plain-vs-FHE accuracy: plain column matches `models/train.py`'s reported accuracy on the eval set; FHE column near plain (degradation = FHE cost)
- [ ] visually inspect `plots/`:
  - [ ] `accuracy_plain_vs_fhe.png` shows three metric groups × two bars each
  - [ ] `bytes_per_message.png`: `VAgentEvalKeyBundle` dominates; per-image messages roughly two orders of magnitude smaller than keygen wire artifacts
  - [ ] `session_timeline_10mbps.png` shows sub-step segments on each party's lane
- [ ] **memory envelope follow-up**: update `~/.claude/projects/-home-butvinm-Dev-ppiav/memory/operational_gomemlimit_logn16.md` with the actual `infer` peak RSS observed under Orion 2.1.5 + 17-prime Q chain on `cpu.16.128.240` with `GOMEMLIMIT=100GiB`. The current entry references 120 GiB / 16-prime chain / 2.1.4 evaluator — all three changed.

**Cleanup:**

- [ ] **confirm with operator before deleting the VPS** — destructive action; keep the instance around for a few hours in case rerun is needed. Then: `openstack --os-cloud immers server delete ppiav-bench-v2 --wait`
- [ ] `git add results/<ts>/summary.md results/<ts>/plots/` (NOT the per-image `.bin` files — they're large + contain secret material; `.gitignore` already excludes them). Stage explicitly; no `git add .`. Commit the new batch as a separate atomic commit before moving the plan to completed.

### Task 11: [Final] Move plan to completed

- [ ] update `CLAUDE.md` Status section if the bench description changed materially (new sections, new sub-steps, new accuracy comparison)
- [ ] move this plan to `docs/plans/completed/`

## Post-Completion

**Thesis-side follow-ups (not part of this plan):**

- update `~/Dev/ITMO/thesis/` chapter referencing the bench tables once the renamed columns + new sections are in
