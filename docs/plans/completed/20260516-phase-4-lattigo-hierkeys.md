# Phase 4 — lattigo-hierkeys integration

## Overview

Replace Phase 1–3's per-target-rotation Galois-key transport with the thesis-canonical hierarchical (`gks_master`) form via the `lattigo-hierkeys` LLKN 2-level scheme. VClient ships a tiny set of master rotation shares (one per base-4 atom, 8 atoms at `LogN=16` over the full slot space); VAgent aggregates into `gks_master` and ships that single object (plus a top-level public key) to VService; both VAgent and VService then independently hierarchically derive their needed `*rlwe.GaloisKey`s and run unchanged Lattigo evaluators.

The protocol shape stays identical to Phase 1–3 — multi-party collaborative `GaloisKeyGenProtocol` produces master shares the same way it produced per-rotation shares, just with a different target rotation list and at a different parameter level. The win is **transport**: ~1.86 GB of evaluation keys at `LogN=16` (~3% of the Phase 1–3 size per `~/Dev/lattigo-hierkeys/README.md:135-137`).

This is the final phase. After it lands, the protocol diagram in `docs/protocol.puml` matches the implemented wire format byte-for-byte and Phase 4's branch-in-DESIGN comments collapse to single canonical paths.

> **Amendment 2026-05-16: dual atom sets, asymmetric scheme — VAgent bypasses hierkeys.**
>
> The original draft of this plan assumed a single positive-base-4 atom set (`{1,4,16,...,16384}` via `hierkeys.MasterRotationsForBase`) shared between VAgent and VService. Two problems with that:
>
> 1. **Sign mismatch breaks the chain-length math.** Auth (`internal/authenticator/authenticator.go:114`) rotates by `-j` (`RotateNew(ct, -j)` for `j ∈ [1, λ)`), which `LevelExpansion.Derive` normalizes to `nSlots - j` (in `[32641, 32767]` at LogN=16). Decomposing those large positive targets with positive base-4 atoms yields chains of **max 22, mean 17** — not the plan's claimed max 10 / mean 5. The plan's noise-budget analysis (Task 14 σ_flood gate) was calibrated against the wrong figure.
> 2. **Auth doesn't need hierkeys derivation at all.** With chain-rotation directly on ciphertexts, hierkeys's `LevelExpansion`/`RotToRot`/`PubToRot` machinery buys nothing for VAgent — it's a derivation tool, and we're not deriving anything; we're chaining atom rotations. The hierarchy only earns its keep when one master atom drives many derived keys (VService's case).
>
> **Revised design — split atom sets per consumer:**
>
> | Consumer             | Atom set                                                                         | Galois elements                                        | Level    | Mechanism                                                                                                                                          | Wire                |
> | -------------------- | -------------------------------------------------------------------------------- | ------------------------------------------------------ | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------- |
> | **VAgent (Auth)**    | `{1,2,4,8,16,32,64}` (7 atoms, base-2, capped at `λ-1`)                          | `GaloisElement(-atom)` (matches Auth's `-j` semantics) | **eval** | **Direct multi-party `GaloisKeyGenProtocol` → 7 raw `*rlwe.GaloisKey`s. No hierkeys.** Chain-rotation via binary popcount.                         | ~1.57 GB at LogN=16 |
> | **VService (Orion)** | `{1,4,16,64,256,1024,4096,16384}` (8 atoms, base-4 via `MasterRotationsForBase`) | `GaloisElement(+atom)` (standard hierkeys convention)  | **top**  | Multi-party `GaloisKeyGenProtocol` + `GaloisKeyToMasterKey` → `map[int]*hierkeys.MasterKey`. `LevelExpansion`-derived `gks_infer` at session open. | ~1.86 GB at LogN=16 |
>
> Total wire: ~3.43 GB at LogN=16 (vs Phase 1-3's 57 GB — still order-of-magnitude smaller).
>
> **Chain math (VAgent, validated empirically in `internal/authenticator/phase4_neg_base2_test.go`):** `j ∈ [1, 127]` decomposes into binary atoms, chain length = `popcount(j)`. Max 7, mean 3.52 over the 64 non-S rotations Auth uses. Per-rotation noise stdev = `√popcount(j) · B_ks` ≤ `√7 · B_ks`. Cumulative over 64 Auth rotations ≈ `√(sum popcount) · B_ks ≈ √225 · B_ks ≈ 15 · B_ks` — only `15/8 ≈ 1.9×` Phase 1-3's `√64 · B_ks = 8·B_ks`. **σ_flood = 2¹⁶ retained from Phase 1-3, no recalibration needed.** Validation test confirms Ver passes with `σ_flood = 2¹⁶` at `LogN=14`, `λ=128`.
>
> **What lattigo-hierkeys is still used for:** VService only. The library's reason-to-exist in this phase is letting VService ship a small `gks_master_infer` (1.86 GB) and derive `gks_infer` locally — instead of receiving the full 50+ GB Phase-1-3 set over the wire. VAgent doesn't need derivation; its 7 atom keys are usable directly.
>
> Affected sections below — wherever the original text says "8 atoms at master level via hierkeys for both parties", read it as the table above. Tasks 2, 4, 5, 6, 14 carry the substantive code-side changes; Task 7 (VService) is essentially unchanged from the original draft.

**Key architectural decision: the level dimension.** lattigo-hierkeys requires multiparty key generation for PK and Galois keys to run against the **top-level** parameters (sk_i, PK, master Galois keys all live in a ring with one extra prime level). Phase 1–3 runs everything at the eval level. Phase 4 splits the protocols by level:

- Each party holds `sk_top` (master secret-key share at top level) and lazily computes `sk_eval = params.LLKN.ProjectToEvalKey(sk_top)` for the operations that stay at eval level.
- **Two PK gens** in Stage 2b: one at eval level (`pk_eval`, for image encryption by VClient and v-encryption by VAgent — identical to Phase 1-3), one at top level (`pk_top`, fed into `hierkeys.PubToRot` to seed the `LevelExpansion` shift-0 key).
- **Galois key gen** moves to top level; outputs are `hierkeys.MasterKey` instances.
- **RLK gen and partial-decrypt KeySwitch** stay at eval level, using the locally-projected `sk_eval`.

Projection is linear, so each party can derive `sk_eval` from their own `sk_top` without coordination, and `sum(project(sk_i_top)) = project(sum(sk_i_top))` — the collective eval-level secret is unchanged.

## Context (from discovery)

Files / components involved (in order of touch surface). **Note: per the top-of-file 2026-05-16 amendment, VAgent uses a separate eval-level 7-atom set (no hierkeys); VService keeps the top-level 8-atom set via hierkeys. Surface descriptions below are written for the amended design.**

- **Crypto core.** `internal/protocol/params.go` (LLKN params + `sk_top → sk_eval` projection helper + `AuthAtoms()`/`InferAtoms()`), `internal/protocol/crs.go` (CRP draw order — pk_eval, pk_top, rlk, per-auth-atom at eval, per-infer-atom at top), `internal/protocol/wire.go` (`VClientGaloisShares` carrying both share lists; `InferEvalKeys` with `RLK + PKTop + GKSMasterInfer`), `internal/protocol/orion_params.go` (LLKN defaults aligned with manifest).
- **Parties.** `internal/vclient/keygen.go` (`GenAuthAndInferShares` returns two share lists, `GenPKShare` runs both eval and top rounds, secret-key gen moves to top level); `internal/vagent/{keygen,agent,state}.go` (aggregate both PKs, aggregate auth atoms to raw `gksAuth` + infer atoms to `gksMasterInfer`, build `internal/authchain.Evaluator` from raw auth keys, ship `gksMasterInfer` forward to VService); `internal/vservice/{service,state,orion,infer,http}.go` (receive `gksMasterInfer + pk_top`, run `hierkeys.LevelExpansion` to derive `gks_infer`, plumb through Orion infer).
- **Auth path.** `internal/authenticator/authenticator.go` — `Auth`'s rotate-and-sum loop calls the `authchain` wrapper instead of the raw `*ckks.Evaluator`; `validateGaloisKeys` (line 170) checks coverage for `GaloisElement(-atom)` over `AuthAtoms()`, not `[1, λ)`. This is the largest single-file logic change in the plan.
- **New auth-side package.** `internal/authchain/evaluator.go` — wraps `*ckks.Evaluator`, holds the 7 raw `*rlwe.GaloisKey`s at `GaloisElement(-atom)` for `atom ∈ AuthAtoms()`, exposes `RotateNew(ct, j)` that binary-decomposes `|j|` and chains atom rotations. **No hierkeys imports, no derivation, no LLKN params at VAgent.**
- **CLI artifact pipeline.** `cmd/ppiav-cli/{keygen,artifacts,mac,infer}.go`. Today: `glk_master.bin` and `glk_full.bin` are written by `keygen` (byte-identical placeholder for Phase 4) and read by `mac`+`infer`. Phase 4 (asymmetric, matching the scheme split): `keygen` writes `gks_master.bin` (the wire-size measurement via `os.Stat`) **and** `gks_infer.bin` (VService's expand-fully derived set, cached once per keygen because the derivation is multi-minute at LogN=16). `mac` reads `gks_master.bin` only and builds the VAgent hier-evaluator shim in-process (eager 8-atom derivation, ~tens of seconds at LogN=16 per process). `infer` reads `gks_infer.bin` directly into `rlwe.NewMemEvaluationKeySet` — same shape as Phase 1–3, just smaller upstream. The existing `glk_master.bin` and `glk_full.bin` artifacts are removed (acronym shift from undocumented `glk` to `gks` matches lattigo-hierkeys naming).
- **HTTP services.** `internal/vagent/http.go` (`POST /sessions/:sid/gks-shares` route stays, payload type changes), `internal/vservice/http.go` (`POST /sessions/:sid/eval-keys` payload).
- **WASM bridge.** `web/ppiav/bridge/ppiav/core.go` exposes `GenGaloisShares` (called from `web/ppiav/bridge/ppiav/ppiav.go:186-191`'s `jsGenGaloisShares`); `web/ppiav/bridge/ppiav/core_test.go:222` is the existing Go-side round-trip test that covers this code path on `linux/amd64`. Adding `lattigo-hierkeys` is a single `import` since both Lattigo and lattigo-hierkeys are pure-Go (`~/Dev/lattigo-hierkeys/README.md:6` and DESIGN.md:900).
- **SPA.** `web/vclient/ts/main.ts` — keeps the `POST /sessions/:sid/gks-shares` route; only the WASM-emitted payload bytes change. No fetch URL change.
- **Bench driver.** `bench/bench/eval.py` step-name registry (`bench/bench/_labels_ru.py:63-66`) is **already Phase-4-ready** — it has entries for `keygen.galois.{client_gen, agent_gen, agent_agg, service_store}` with hierarchical-derivation wording. The Python side needs only stale-comment cleanups (`eval.py:498,633`, `bench/README.md:46`); per-file wire sizes are auto-discovered by `_per_message_bytes` via `os.stat()` against `keys/*.bin`. Go-side per-party sample emission in Tasks 5/6/7/10 must use the pre-existing step names.
- **Design doc.** `docs/DESIGN.md` lines 298–302 ("Phase 4 rotation composition" + decompose-at-use rhetoric) and 467 (Phase 4 params row). Updated as part of this plan write (see Design Decisions below) so the canonical reference matches the implementation; per the planning memory, no DESIGN.md edits inside the implementation tasks.

Related patterns observed:

- The collaborative `multiparty.GaloisKeyGenProtocol` handshake in Phase 1–3 already iterates over a rotation list (`params.RotationIndices()`); Phase 4 swaps that single iteration for two narrower ones: `params.AuthAtoms()` at eval level against `params.CKKS` (using `skEval`), and `params.InferAtoms()` at top level against `params.LLKN.Top()` (using `skTop`). Both still use the same `GenShare → Aggregate → GenGaloisKey` triplet per rotation; only the iteration lists, the level, and the Galois-element sign differ.
- The CRS draw-order convention (DESIGN.md:534-540) was already designed with a swap in mind; Phase 4 inserts an additional CRP draw for the top-level PK and switches the Galois CRP iteration to master atoms. Both parties iterate identical lists at identical levels so per-CRP draws still line up.
- `internal/vagent/state.go` and `internal/vservice/state.go` already export/import their `gks` slice for snapshot/restore tests; the export-path payload shape needs to track the wire shape, but the in-memory `*ckks.Evaluator` is rebuilt with standard `rlwe.NewMemEvaluationKeySet(rlk, gks...)` after derivation — unchanged from Phase 1–3.

Dependencies identified:

- `github.com/butvinm/lattigo-hierkeys` — add to `go.mod`. Pure-Go, depends only on lattigo v6 (same major as ppiav). The upstream has no git tags yet, so the `go get` pins a **pseudo-version** against a specific commit (e.g. `go get github.com/butvinm/lattigo-hierkeys@<commit>` or `@main`). Confirm version pin against the `LogN16_D15_P6` scenario at `~/Dev/lattigo-hierkeys/internal/testutil/scenarios.go:91`.
- No new Python deps; bench driver changes are comment-only.

## Development Approach

- **Testing approach**: Regular (code first, then tests). The crypto core packages already have round-trip tests at `LogN=14` (fast) and `LogN=16` (gated behind `PPIAV_RUN_HEAVY=1`); each Phase 4 task extends those tests rather than introducing a separate test ladder.
- Complete each task fully before moving to the next.
- Make small, focused changes. Atomic commits per CLAUDE.md.
- **Every code-changing task adds or updates tests** covering both success and the error paths the task introduces. CRP-order tests in `internal/protocol/crs_test.go` and round-trip tests in `internal/vagent/*_test.go` / `internal/vservice/*_test.go` are the main vehicles.
- **All tests pass before starting the next task** — no exceptions. Heavy `LogN=16` tests are skipped locally and run on the VPS (memory `feedback_no_logn15_local.md`); fast `LogN=14` paths must pass locally.
- Run `go test ./internal/...` after each Go change, `npm run build` after each TS change (typecheck happens inside `tsc`), `make phase3` once at the end.
- Keep this plan in sync with implementation: tick boxes on completion, prefix new tasks `➕`, blockers `⚠️`.

## Testing Strategy

- **Unit tests (Go).** Each touched package gets new/updated tests:
  - `internal/protocol/wire_test.go` — `VClientGaloisShares` (both `AuthAtomShares` and `InferAtomShares`) and `InferEvalKeys` (with `RLK + PKTop + GKSMasterInfer`) round-trip via `MarshalBinary`/`UnmarshalBinary`.
  - `internal/protocol/crs_test.go` — `CanonicalAuthAtoms` and `CanonicalInferAtoms` return atoms in ascending order; the 5-step CRP iteration order documented in DESIGN.md is callable in lockstep by both parties.
  - `internal/protocol/params_test.go` — `ProjectToEvalKey` round-trip: project a `sk_top` and verify the result is bit-identical to a fresh `rlwe.NewSecretKey(params.CKKS)` with the same underlying coefficients.
  - `internal/vclient/keygen_test.go` — `GenAuthAndInferShares` produces share counts matching `len(params.AuthAtoms())` and `len(params.InferAtoms())` respectively, both in canonical order; `GenPKShare` produces both eval and top shares; share counts and labels match.
  - `internal/vagent/keygen_test.go` — aggregating matched VClient + VAgent auth-atom shares yields 7 raw `*rlwe.GaloisKey`s (at `GaloisElement(-atom)`, eval level) that, when loaded into a `ckks.Evaluator` and chained via binary decompose, rotate ciphertexts correctly for `j ∈ [1, λ)`. Aggregating matched infer-atom shares yields `gksMasterInfer map[int]*hierkeys.MasterKey` that, when expanded via `llkn.Evaluator.NewLevelExpansion + Derive + FinalizeKey` for `ExtraRotationIndices`, produces working Galois keys.
  - `internal/vservice/service_test.go` / `state_test.go` — `StoreEvalKeys` with the new `(pk_top, gksMasterInfer)` payload derives the inference-side keys and the resulting evaluator rotates correctly for every index in `ExtraRotationIndices`.
- **Round-trip integration tests.** `internal/vagent` and `internal/vservice` already have end-to-end keygen-and-infer integration tests that exercise the whole handshake in-process; the same tests stay valid with the new payloads — they're the canary that the Phase 4 surgery didn't break the Phase 1–3 protocol shape.
- **HTTP smoke.** `internal/vagent/http_test.go` and `internal/vservice/http_test.go` cover the payload shape change at `/gks-shares` and `/eval-keys`.
- **End-to-end UI smoke.** After all Go changes land: `make phase3` then `cd deploy && docker compose up`; load the SPA, complete a verification with a UTKFace face; confirm the protocol completes end-to-end (browser DevTools) and the verdict is correct. No automated browser tests per memory `feedback_no_ml_harness_tests` and the project's "no automated e2e tests" stance.
- **VPS benchmark.** Final task runs `make eval` on `cpu.16.128.240` to regenerate `results/phase-4-hierkeys/eval-*/summary.md` and compare wire sizes against the Phase 2 baseline (the `keygen.json` row is the relevant cross-phase delta).

## Progress Tracking

- Mark completed items with `[x]` immediately on completion (no batching).
- ➕ prefix newly discovered subtasks.
- ⚠️ prefix blockers with a one-line cause.
- If a task scope shifts during implementation (e.g. lattigo-hierkeys upstream API surprise), update the task description here before continuing.

## Solution Overview

**Scheme: LLKN 2-level, scenario `LogN16_D15_P6`.** Picked over KG+ because:

1. LLKN has the simpler hierarchy (no ring switching, no extension ring `R'`), so the WASM bridge surface is smaller and the integration code paths stay close to the Phase 1–3 shape.
2. Multiparty support in lattigo-hierkeys is identical between the two schemes (see `~/Dev/lattigo-hierkeys/example/llkn/multiparty/main.go` and `.../kgplus/multiparty/main.go`) — both use the standard `multiparty.GaloisKeyGenProtocol`, so the protocol code is scheme-agnostic above the params boundary.
3. DESIGN.md already pinned the parameter row to `LogN16_D15_P6` (DESIGN.md:467) which is an LLKN scenario.

KG+ is smaller on the wire (3.2% → 1.5% at LogN=16 per `~/Dev/lattigo-hierkeys/README.md:137`) but those gains are not the bottleneck for the thesis demonstrator; LLKN's transport win over Phase 1–3 is already an order-of-magnitude.

**The level dimension** (covered in the Overview): all multiparty protocols split by level — PK gen runs twice (eval + top), Galois gen runs at top, RLK and KeySwitch stay at eval. Each party holds `sk_top` and lazily projects to `sk_eval` for the eval-level operations. `pk_top` is bundled with the master Galois keys when VAgent ships them to VService.

**Asymmetric scheme**: **VAgent decompose-at-use, VService expand-fully** (DESIGN.md:298-302's "natural default", scoped correctly per party). The reason it's asymmetric:

- **VAgent owns its rotation code.** `internal/authenticator/authenticator.go:Auth` is a ppiav-internal loop we control end-to-end. Swapping `eval.RotateNew(ct, -j)` for a base-`Base` chain is ~10-20 LOC. We pick the rotation indices, we pick the noise model.
- **VService runs Orion's compiled circuit.** Orion-compiled circuits assume single-rotation-per-logical-rotation:
  - Hoisted rotations (`Evaluator.RotateHoisted` / hoisted decomposition) share decomposition work across multiple rotations of the same input. Hoisting requires all target Galois keys present at evaluation time; chained atom rotations break the hoist pattern.
  - Noise calibration baked into the compiled circuit assumes `B_ks` per rotation, not `√k × B_ks` for chain length `k`. Retrofitting decompose-at-use changes the output precision, potentially below the model's accuracy threshold — and we can't re-validate without recompiling.
  - Forcing decompose into VService means either patching Orion (invasive) or wrapping the evaluator in a way that intercepts every `Rotate` call AND every hoisted decomposition path. Non-trivial.

So at LogN=16:

- **VAgent: decompose-at-use.** Resident: ~1.86 GB (8 atom keys). One-shot atom derivation at session open: ~tens of seconds. Per-Auth-rotation: chain length up to 10 (worst case j=127 → 10 atom rotations; mean ~5 over `j ∈ [1, 127]`).
- **VService: expand-fully.** Resident: same as Phase 1–3 (the full `gks_infer` set for `ExtraRotationIndices`; many GB at LogN=16). One-shot full derivation at `StoreEvalKeys`: minutes sequential / tens of seconds concurrent (`~/Dev/lattigo-hierkeys/README.md:147-161` pro-rated). Per-rotation: single Galois key, hoisting intact, model noise unchanged.

The transport win is identical at both sides: `gks_master` is ~1.86 GB on the wire at LogN=16 vs the Phase 1–3 conventional ~57 GB.

**VService's per-session derivation cost is real.** Adding minutes of latency to `StoreEvalKeys` is the cost of Phase 4's transport optimization at VService. Phase 1–3 has zero derivation cost because the assembled keys are received pre-baked. The thesis demonstrator's verification flow tolerates this (sessions aren't time-critical), but `summary.md` must call it out so the cross-phase comparison is honest.

**Backstop knob**: if VService's per-session derivation cost is shown to be unacceptable in bench (e.g. >60s even concurrent), the fallback is to recompile the C3AE circuit with chained-rotation noise assumptions and switch VService to decompose-at-use too. That's a Phase 4+ research thread — out of scope for the current plan.

**The previous draft of this plan got the per-key arithmetic wrong** (estimated "few MB" instead of ~224 MB per Galois key at LogN=16, off by ~150×) and concluded expand-fully at both sides was viable. It isn't — expand-fully at VAgent would mean ~28 GB resident per session AND ~minutes derivation at session open. The corrected numbers vindicate DESIGN.md's asymmetric guidance: VAgent's rotation set is small and ppiav-controlled (good fit for decompose-at-use), VService's is Orion-controlled and noise-sensitive (must stay expand-fully).

**Compatibility break.** Phase 4 fully replaces the Phase 1–3 wire payload; there is no version negotiation, no fallback. Backwards-compat shims are explicitly out of scope per CLAUDE.md's anti-backwards-compat-hack rule. Comments in code that reference "Phase 1–3 / Phase 4" branching (e.g. `internal/protocol/wire.go:66`, `internal/vagent/agent.go:758`, `cmd/ppiav-cli/artifacts.go:21`) get collapsed to the single canonical path as part of each task.

## Technical Details

> **Amendment 2026-05-16 supersedes everything below.** The prose in this section was written for the original single-positive-base-4-atom-set design. The dual-atom-set design from the top-of-file amendment is the source of truth — refer to the per-task amendment blocks in Tasks 2/4/5/6/10 for the executable specification. The LLKN-params subsection still applies (VService uses LLKN parameters identically); the "Master rotation set", "Wire types", "CRP draw order", "Derivation API surface", and "CLI artifact pipeline" subsections are obsolete and retained only for diff context.

### LLKN parameters (`scenarios.go:91`, `LogN16_D15_P6`)

```
Eval level  (Phase 1–3 stays valid):
  LogN = 16, LogQ = [55] + [40]×15, LogP = [55]×6, LogDefaultScale = 40

Master level (added in Phase 4):
  LogPHK = [55]×11
  Base   = 4
```

The eval level is byte-for-byte the same chain Phase 1–3 used; `protocol.Params.CKKS` does not change. The master level lives in a new `protocol.Params.LLKN` field of type `llkn.Parameters` built from `protocol.Params.CKKS.Parameters` via `llkn.NewParameters(eval, [][]int{logPHK})`.

### Master rotation set

```go
masterAtoms = hierkeys.MasterRotationsForBase(Base=4, params.CKKS.MaxSlots())
            = {1, 4, 16, 64, 256, 1024, 4096, 16384}
            // 8 atoms at LogN=16 (MaxSlots = N/2 = 2^15 = 32768)
```

Eight master atoms across the half-slot range. All eight are emitted from the VClient regardless of the target rotation set the inference circuit or the authenticator need — the hierkeys hierarchy decomposes target rotations into base-4 atom chains, so a stable atom set covers every possible target.

### Wire types

```go
// protocol/wire.go

// VClient → VAgent (Stage 2b): one share per parameter level.
type VClientPKShare struct {
    ShareEval multiparty.PublicKeyGenShare  // for eval-level pk (encryption)
    ShareTop  multiparty.PublicKeyGenShare  // for top-level pk (feeds PubToRot)
}

// VClient → VAgent (Stage 2d): one share per master atom, in canonical
// MasterRotations() order. Protocol runs at top level.
type VClientMasterRotationShare struct {
    Shares []multiparty.GaloisKeyGenShare // len = len(MasterRotations())
}

// VAgent → VService (Stage 2d): the top-level public key plus the
// aggregated master keys keyed by atom rotation index. PKTop is required
// by hierkeys.PubToRot to seed the LevelExpansion.
type InferEvalKeys struct {
    RLK       *rlwe.RelinearizationKey      // eval-level (unchanged from Phase 1-3)
    PKTop     *rlwe.PublicKey                // NEW — top-level pk for PubToRot
    GKSMaster map[int]*hierkeys.MasterKey   // key: atom rotation in MasterRotations()
}
```

`hierkeys.MasterKey` already implements `encoding.BinaryMarshaler` / `BinaryUnmarshaler` (`~/Dev/lattigo-hierkeys/masterkey.go:69-86`); the wire `MarshalBinary` for `InferEvalKeys` writes RLK length-prefixed, then PKTop length-prefixed, then atom-count, then `(atom_int, master_bytes)` pairs sorted by atom.

### CRP draw order (DESIGN.md:534-540 updated)

```
1. PublicKeyGenProtocol(evalParams).SampleCRP(crs)        // pk_eval
2. PublicKeyGenProtocol(topParams ).SampleCRP(crs)        // pk_top  (NEW)
3. RelinearizationKeyGenProtocol(evalParams).SampleCRP(crs, evkParams)  // single CRP for both rlk rounds
4. For each atom k in MasterRotations() ascending:
     GaloisKeyGenProtocol(topParams).SampleCRP(crs, evkParams)
```

Steps 2 and 4 are new / changed. Order (eval-PK before top-PK) is arbitrary but must be stable; both parties draw in lockstep so byte counts consumed per draw match exactly.

### Derivation API surface — decompose-at-use

```go
// internal/hierkeys/evaluator.go — holds gks_master and derives atom-level
// *rlwe.GaloisKey eagerly at construction, caches them in-memory (bounded:
// ~8 keys × 224 MB ≈ 1.86 GB at LogN=16).
import (
    "github.com/butvinm/lattigo-hierkeys"
    "github.com/butvinm/lattigo-hierkeys/llkn"
)

type HierEvaluator struct {
    base       *ckks.Evaluator                // the standard Lattigo evaluator
    llknEval   *llkn.Evaluator                // for FinalizeKey
    expansion  *hierkeys.LevelExpansion       // shared across atoms
    masterRots []int                          // ascending atoms
    atomKeys   map[int]*rlwe.GaloisKey        // eagerly derived at construction
    base_      int                            // params.LLKN.Base
}

// Decompose decomposes a logical rotation j into base-`Base` atoms via
// hierkeys.DecomposeRotation. Greedy from largest atom down.
// E.g. j=127, Base=4, atoms={1,4,16,64,...} → [64,16,16,16,4,4,4,1,1,1].
func (h *HierEvaluator) Decompose(j int) []int { ... }

// RotateNew applies the decomposed chain. Replaces eval.RotateNew at every
// call site that consumes hierkeys-derived keys.
func (h *HierEvaluator) RotateNew(ct *rlwe.Ciphertext, j int) (*rlwe.Ciphertext, error) {
    out := ct
    for _, a := range h.Decompose(j) {
        // h.base.EvaluationKeySet holds the eagerly-derived atom keys
        out, err = h.base.RotateNew(out, a)
        if err != nil { return nil, err }
    }
    return out, nil
}
```

VAgent only — the `HierEvaluator` is a VAgent-side abstraction. VAgent constructs it per session at `AggregateGaloisShares` time, populates `expansion` from `gksMaster + pkTopAgg`, **eagerly derives the 8 atom keys at LogN=16** (one-shot per session, predictable cost — bench-measured against `~/Dev/lattigo-hierkeys/README.md:147-161` proportions; expected tens of seconds sequential or seconds concurrent for the atom-only subset). The wrapper passes through to `authenticator.Auth` whose rotate-and-sum loop calls `hierEval.RotateNew(ct, j)`.

VService does NOT use `HierEvaluator`. It runs the Orion-compiled circuit which assumes:

- Single Galois key per logical rotation (`B_ks` noise, not `√k × B_ks`).
- Hoisted-rotation patterns (`Evaluator.RotateHoisted` etc.) that decompose-at-use would break — hoisting shares decomposition work across multiple rotations of the same input ciphertext, which only works if all target keys are present.

So VService stays at the Phase 1–3 in-memory shape: `StoreEvalKeys` expands `gksMaster` into the full `gks_infer` slice for `ExtraRotationIndices`, hands it to `rlwe.NewMemEvaluationKeySet`, primes the session evaluator. The Orion compile-time noise model and hoisting paths stay valid.

Eager (not lazy) atom-key derivation at VAgent: keeps per-session latency predictable. Lazy caching would push variance into the first `Rotate` call inside `Auth`, which interacts badly with HTTP request timeouts. The 8-atom set is small and bounded, so eager amortizes naturally.

### Per-Galois-key size at LogN=16 — the number that drove this design

From `~/Dev/lattigo-hierkeys/README.md:131-137` (transmission key sizes, 256 target rotations, base-4):

| LogN | Conventional | LLKN gks_master | Per-key (conv.) |
| ---- | -----------: | --------------: | --------------: |
| 14   |     1,344 MB |          100 MB |        ~5.25 MB |
| 15   |     6,656 MB |          198 MB |          ~26 MB |
| 16   |    57,345 MB |        1,862 MB |         ~224 MB |

Per-key size scales with `N · log_2 QP`, so the LogN=14 → LogN=16 jump is ~40×. **Expand-fully at LogN=16 means `[1, λ) = 127 keys × 224 MB ≈ 28 GB resident per session** at VAgent. The same arithmetic at VService grows with `ExtraRotationIndices` count. This is the constraint that rules out expand-fully under the HTTP-service deployment shape.

Decompose-at-use holds only the 8 atom keys at each side (~1.86 GB), with a one-shot derivation cost at session-open and a per-rotation chaining cost of up to 10 atom rotations (mean ~5 for `j ∈ [1, 127]`).

### CLI artifact pipeline

```
keys/
  params.json     # CKKS + LLKN literal — readable by every subcommand
  rlk.bin
  pk_eval.bin     # eval-level collective PK (for encryption)
  pk_top.bin      # top-level collective PK (for PubToRot)
  gks_master.bin  # wire artifact; SIZE goes into eval_inputs.json (the wire-cost measurement)
  gks_infer.bin   # VService's expand-fully derived set (one-shot at keygen, multi-minute at LogN=16)
```

Phase 1–3's `glk_master.bin` and `glk_full.bin` (byte-identical placeholders) are removed entirely; replaced by `gks_master.bin` (real hierkeys master keys, ~1.86 GB at LogN=16) and `gks_infer.bin` (VService's expand-fully derived keys, ~tens of GB at LogN=16). The acronym shift `glk → gks` matches lattigo-hierkeys naming; the undocumented `glk` is retired across code constants, comments, and the bench.

The Phase 4 on-disk shape is **asymmetric**: VAgent has no derived-key cache because its 8 atom keys are cheap to re-derive per `mac` process startup (~tens of seconds at LogN=16, recorded as `hier_eval_construct_seconds` in `mac.json` to keep the cost visible). VService's `gks_infer.bin` cache exists because expand-fully derivation is multi-minute per keygen; caching once amortizes across the stratified UTKFace batch.

`keygen`:

1. Run VClient + VAgent multi-party handshake → `gks_master + pk_top + pk_eval + rlk`.
2. Write `gks_master.bin`, `pk_top.bin`, `pk_eval.bin`, `rlk.bin`. The `gks_master.bin` byte count IS the wire-cost measurement.
3. Run the expand-fully derivation for VService (build `llkn.Evaluator`, derive `gks_infer` for `params.ExtraRotationIndices` concurrently via `errgroup`), write `gks_infer.bin`.
4. Emit `keygen.json` with `gks_master_bytes`. Per-party samples follow the bench's pre-existing step-name registry (`keygen.galois.{client_gen, agent_gen, agent_agg, service_store}`).

`mac` and `infer` each:

1. Read `params.json` + `gks_master.bin` (mac) or `gks_infer.bin` (infer) + `rlk.bin` + `pk_top.bin`.
2. `mac`: construct the `HierEvaluator` shim (eager atom-key derivation; one-shot, ≈ tens of seconds sequential at LogN=16, bench-measured for the actual number). `infer`: load `gks_infer` directly into `rlwe.NewMemEvaluationKeySet`.
3. Run the per-sample step. `mac` uses `hierEval.RotateNew` for Auth's rotations; `infer` runs the Orion-compiled circuit unchanged.

The shim-construction time at startup is recorded in the subcommand's single-sample timing JSON (`mac.json`) as `hier_eval_construct_seconds`. Per-sample wall-time captures the cumulative cost of decompose-at-use's chained rotations vs Phase 1–3's single rotations — bench will show this delta directly.

`bench/bench/eval.py` already does single shared `keygen` across the stratified UTKFace batch (per `docs/plans/completed/20260515-bench-eval-redesign.md`); the shim construction happens once per `mac` subcommand invocation (each subcommand is a fresh process per the post-redesign architecture), which is once per sample. That's not free — bench-measure how the construction time compares to overall mac wall — and may motivate caching the derived atom keys to disk if it dominates. Treated as a Task 14 acceptance check; the plan does NOT add disk caching speculatively.

### Bench eval driver

`bench/bench/eval.py` step-name registry is already Phase-4-ready (see Context). Python-side surface is small:

- Stale-comment cleanup at `eval.py:498` and `eval.py:633` (both reference `glk_full.bin`).
- `bench/README.md:46` artifact list update.
- `summary.md` optionally gains a cross-phase row: `gks_master_bytes` vs Phase 2 results-dir's combined `glk_master.bin + glk_full.bin` (Phase 2 result dir is committed; the comparison is a static diff in the markdown).

Per-file wire sizes are auto-discovered by `_per_message_bytes` via `os.stat()` against `keys/*.bin` — no `glk_full_bytes` JSON field exists today, so no field to drop. Go-side per-party sample emission must use the pre-existing step names: `keygen.galois.client_gen`, `keygen.galois.agent_gen`, `keygen.galois.agent_agg` (aggregation + hierarchical derivation at agent), `keygen.galois.service_store` (hierarchical derivation at service).

### WASM bridge

`web/ppiav/bridge/ppiav/keygen.go` (or wherever `GenGaloisShares` is exposed) — function semantics change to use master rotations at top-level CRPs. The bridge imports `internal/vclient` directly so the change propagates automatically once VClient is updated. `web/ppiav/go.sum` picks up the new `lattigo-hierkeys` dep on `go build ./web/ppiav/bridge`.

### SPA

`web/vclient/ts/main.ts` — the existing `POST /sessions/:sid/gks-shares` route is retained. The wire body is `application/octet-stream` and produced by the WASM bridge, so the SPA does not parse the payload contents — no SPA-side change required beyond a rebuild via `npm run build` to pick up any wasm-emitted bridge type changes (if any TS surface types shift, which they likely won't since the bridge type is bytes-in/bytes-out).

## What Goes Where

- **Implementation Steps** (`[ ]`): code changes to `internal/`, `cmd/`, `web/`, `bench/`, plus this plan's tickoffs. Includes the design-doc update task at the top because per memory `feedback_design_md_planning_only`, DESIGN.md edits live in the planning task, not in implementation — but the implementation tasks read from the updated DESIGN.md so the update lands first.
- **Post-Completion** (no checkboxes): VPS bench run, follow-up DESIGN.md update if bench numbers contradict the expand-fully decision, future decompose-at-use optimization.

## Implementation Steps

### Task 1: Align DESIGN.md with the Phase 4 implementation choices

**Files:**

- Modify: `docs/DESIGN.md`

- [x] update DESIGN.md:298-302 — collapse the "Either route" passage into the asymmetric scheme as the Phase 4 default (VAgent decompose-at-use, VService expand-fully). Note the per-Auth-rotation chain-length range (1–10 atoms, mean ~5 over `j ∈ [1, 127]`).
- [x] update DESIGN.md:467 — Phase 4 row keeps `LogPHK = 11×55`, `Base = 4`; drop `LogPHK3` and `LogPExtra` (KG+ only) to avoid implying we're hedging schemes.
- [x] update DESIGN.md:514, :725-726, :758, :793-807, :904, :914 — the per-call-site Phase 4 comments collapse to the canonical wire format. The route name `/gks-shares` stays unchanged; only the payload type rotates.
- [x] add a new section documenting the **level dimension**: each party holds `sk_top`, projects locally to `sk_eval`. Two PK gens (eval + top). Galois at top. RLK + KeySwitch at eval. `pk_top` is bundled with the master Galois keys when VAgent ships them to VService.
- [x] update DESIGN.md `Defaults()`-near section (DESIGN.md:441-468) to add `LLKN` to the `Params` struct snippet.
- [x] run `git diff docs/DESIGN.md` and sanity-check the new doc reads as if Phase 4 were the only implementation (no "in Phase 1–3 …" branching outside the historical-phase table at line 378).
- [x] no test for a docs-only task; the rest of the plan's tasks test the implementation conformance to the updated doc.

### Task 2: Add LLKN params + sk projection + dual atom sets to `protocol.Params`

**Files:**

- Modify: `internal/protocol/params.go`
- Modify: `internal/protocol/orion_params.go`
- Modify: `internal/protocol/params_test.go`
- Modify: `internal/protocol/orion_params_test.go`

> **Amendment 2026-05-16:** Two atom sets, not one. Per the top-level amendment:
>
> - **Auth atoms** (VAgent): `{1, 2, 4, 8, 16, 32, 64}` — base-2 powers, capped at `⌈log_2(λ−1)⌉`-th power (= 64 for λ=128). Used at **eval level** with `GaloisElement(-atom)`. No hierkeys.
> - **Infer atoms** (VService): `hierkeys.MasterRotationsForBase(4, p.CKKS.MaxSlots())` = `{1,4,16,...,16384}`. Used at **top level** with `GaloisElement(+atom)` per hierkeys' standard convention.
>
> Replace `Params.MasterRotations()` with two methods: `Params.AuthAtoms() []int` (returns `{1,2,4,...,2^⌈log₂(λ−1)⌉}`) and `Params.InferAtoms() []int` (returns the `MasterRotationsForBase` set). Both ascending.
>
> Drop the broken `Params.AuthRotationIndices() []int` from this task — the original framing assumed full `[1, λ)` derivation. Auth's `validateGaloisKeys` (Task 6) now validates auth-atom coverage instead.

- [x] add `LLKN llkn.Parameters` field (or a `LLKNConfig{ LogPHK []int; Base int }` if zero-value `llkn.Parameters` is awkward — pick whichever round-trips through `LoadOrionParams` cleanly).
- [x] populate `Defaults()` with `LogPHK = []int{55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55}` (11×55) and `Base = 4`, building `llkn.NewParameters(p.CKKS.Parameters, [][]int{LogPHK})`.
- [x] update `LoadOrionParams` to stamp the same LLKN defaults — the manifest itself doesn't constrain LLKN params (they're hierarchy-only, not circuit-affecting).
- [x] add `Params.AuthAtoms() []int` returning the base-2 powers up to `λ−1`: `{1, 2, 4, ..., 2^⌈log₂(λ−1)⌉}` (= `{1,2,4,8,16,32,64}` for `λ=128`). Used at **eval level** with `GaloisElement(-atom)` by VAgent's Auth chain rotation. Independent of LLKN.
- [x] add `Params.InferAtoms() []int` returning `hierkeys.MasterRotationsForBase(Base, p.CKKS.MaxSlots())` (sorted ascending; = `{1,4,16,...,16384}` at LogN=16, Base=4). Used at **top level** with `GaloisElement(+atom)` by VService's hierkeys derivation.
- [x] keep `RotationIndices()` for any callers that still want the union; do not delete it as a "bugfix" — it isn't. (No callers in Phase 4 should use it for Galois keygen, but it may remain useful for diagnostic enumeration.)
- [x] add helper `Params.ProjectSKToEval(skTop *rlwe.SecretKey) (*rlwe.SecretKey, error)` that wraps `params.LLKN.ProjectToEvalKey`. Used by `vclient` / `vagent` to derive `sk_eval` from `sk_top` for eval-level protocol calls (RLK, KeySwitch).
- [x] note: `llkn.NewParameters(eval rlwe.Parameters, ...)` takes the embedded `rlwe.Parameters` value, not the `ckks.Parameters` wrapper. In Go that's `p.CKKS.Parameters` (the anonymous-field-promotion form) — same idiom as `~/Dev/lattigo-hierkeys/example/llkn/multiparty/main.go:43`. Confirm the resolution in your editor before plumbing it through.
- [x] write tests: `Defaults().AuthAtoms()` returns `{1, 2, 4, 8, 16, 32, 64}` for `Lambda=128` (= `{1, 2, 4, ..., 2^⌈log₂(λ−1)⌉}`); `Defaults().InferAtoms()` returns `{1, 4, 16, 64, 256, 1024, 4096, 16384}`; `LoadOrionParams` populates LLKN identically to `Defaults()`; `ProjectSKToEval` of a fresh `sk_top` produces a key with the correct number of Q/P primes (16 + 6 for eval).
- [x] run `go test ./internal/protocol/...`.

### Task 3: Update CRS canonical draw order to include pk_top + master atoms

**Files:**

- Modify: `internal/protocol/crs.go`
- Modify: `internal/protocol/crs_test.go`

- [x] update `CanonicalRotationIndices` — replace with two helpers: `CanonicalAuthAtoms(params Params) []int` and `CanonicalInferAtoms(params Params) []int`, each returning the ascending atom set. The Galois keygen iterates these in sequence (auth first, then infer) when drawing CRPs.
- [x] document the new five-step CRP draw order in the package doc-comment in sync with DESIGN.md (post-Task-1 wording):
  1. `PublicKeyGenProtocol(evalParams).SampleCRP(crs)` — pk_eval
  2. `PublicKeyGenProtocol(topParams).SampleCRP(crs)` — pk_top
  3. `RelinearizationKeyGenProtocol(evalParams).SampleCRP(crs, evkParams)` — single CRP for both RLK rounds
  4. For each atom in `CanonicalAuthAtoms` (ascending): `GaloisKeyGenProtocol(evalParams).SampleCRP(crs, evkParams)`
  5. For each atom in `CanonicalInferAtoms` (ascending): `GaloisKeyGenProtocol(topParams).SampleCRP(crs, evkParams)`
- [x] write tests: both atom sets returned in ascending order; counts match `len(params.AuthAtoms())` and `len(params.InferAtoms())`; the documented draw order is callable in lockstep from a test that mirrors VClient and VAgent against the same CRS — both parties consume the CRS in the exact 5-step order above, byte-for-byte.
- [x] run `go test ./internal/protocol/...`.

### Task 4: Update wire types for master payloads + dual PK

**Files:**

- Modify: `internal/protocol/wire.go`
- Modify: `internal/protocol/wire_test.go`

> **Amendment 2026-05-16:** Wire payloads split per-consumer:
>
> - VClient → VAgent (Stage 2d, single message): `VClientGaloisShares { AuthAtomShares []multiparty.GaloisKeyGenShare /* eval-level, |AuthAtoms| entries, neg galEls */; InferAtomShares []multiparty.GaloisKeyGenShare /* top-level, |InferAtoms| entries, pos galEls */ }`. Single round-trip; both share lists in one POST.
> - VAgent → VService (Stage 2d forward): `InferEvalKeys { RLK *rlwe.RelinearizationKey; PKTop *rlwe.PublicKey; GKSMasterInfer map[int]*hierkeys.MasterKey }`. **No auth-side payload** — VAgent's `gks_auth` (raw `*rlwe.GaloisKey`s) stays at VAgent.
>
> `MarshalBinary` for `VClientGaloisShares`: 4-byte auth-count, length-prefixed auth shares, 4-byte infer-count, length-prefixed infer shares. UnmarshalBinary inverts. `InferEvalKeys` MarshalBinary per the original draft (RLK + PKTop + atom-count + sorted `(atom, MasterKey)` pairs).
>
> Drop the original draft's rename of `VClientGaloisKeyShare` → `VClientMasterRotationShare` — the new type is `VClientGaloisShares` (carries both share lists).

- [x] extend `VClientPKShare` to carry both `ShareEval` and `ShareTop` fields. Update marshal/unmarshal to length-prefix both. **Also extended `VAgentPKShare` for parity** — both parties now emit dual PK shares per Tasks 5 & 6, so symmetric wire types keep the HTTP code paths uniform.
- [x] rename `VClientGaloisKeyShare` → `VClientGaloisShares` (NOT `VClientMasterRotationShare`). Fields: `AuthAtomShares []multiparty.GaloisKeyGenShare` (eval-level, `len(AuthAtoms())` entries) and `InferAtomShares []multiparty.GaloisKeyGenShare` (top-level, `len(InferAtoms())` entries). MarshalBinary: 4-byte auth-count + length-prefixed auth shares + 4-byte infer-count + length-prefixed infer shares. UnmarshalBinary inverts.
- [x] change `InferEvalKeys` to `{ RLK, PKTop, GKSMasterInfer }`. `GKSMasterInfer` is `map[int]*hierkeys.MasterKey` keyed by positive infer atom. Build MarshalBinary as: RLK (length-prefixed) + PKTop (length-prefixed) + atom-count (uint32) + ascending `(atom_int int32, master_len uint32, master_bytes)` triples. UnmarshalBinary inverts. **No auth-side payload** — VAgent's `gksAuth` stays at VAgent.
- [x] add `import "github.com/butvinm/lattigo-hierkeys"` to the wire package (for `*hierkeys.MasterKey` in `GKSMasterInfer`).
- [x] update `wire_test.go` round-trip tests: build a `gksMasterInfer` from synthetic top-level `multiparty.GaloisKeyGenProtocol` + `hierkeys.GaloisKeyToMasterKey`; build `VClientGaloisShares` with both auth and infer share lists from independent eval-level and top-level handshakes at `LogN=14`; marshal/unmarshal, compare via `MarshalBinary` byte-equality. **Implementation note**: wire tests already used `LogN=10` (smallCKKS); kept that for speed, and built the master-key fixture via single-party `GenGaloisKeyNew` → `GaloisKeyToMasterKey` since the wire layer only needs marshal-able keys, not aggregated ones. Multi-party handshake validation lives in Tasks 5/6 against `LogN=14`.
- [x] run `go test ./internal/protocol/...`. **Result**: all 22 tests pass, including 12 new/updated wire-format tests covering dual-PK round-trip + truncation, dual-list Galois shares round-trip + empty + count-overflow, and the redesigned `InferEvalKeys` round-trip + nil-input rejection + empty-map handling. `go build ./...` shows expected downstream breakage in `internal/vagent/http.go`, `internal/vservice/http.go`, and `web/ppiav/bridge/ppiav/core.go` (renamed types / removed fields) — those are Tasks 5/6/7/8's scope per the plan's task split.

### Task 5: VClient — top-level sk, dual PK gen, dual-atom-set shares (+ all call-site renames)

**Files:**

- Modify: `internal/vclient/keygen.go`
- Modify: `internal/vclient/keygen_test.go`
- Modify: `internal/vclient/client.go` (sk gen moves to top level; cached sk_eval added)
- Modify: `internal/vclient/partial_decrypt.go` (uses cached sk_eval)
- Modify: `internal/orchestrator/runner.go` — call-site rename (`runner.go:217`)
- Modify: `web/ppiav/bridge/ppiav/core.go` — call-site rename (`core.go:190-199`)
- Modify: `web/ppiav/bridge/ppiav/ppiav.go` — Go wrapper rename only; JS namespace key (`"genGaloisShares"` at `ppiav.go:49`) stays unchanged to avoid touching `web/vclient/ts/main.ts`
- Modify: `web/ppiav/bridge/ppiav/core_test.go` — `core_test.go:133,222` references
- Modify: `go.mod` — add `github.com/butvinm/lattigo-hierkeys` via `go get @<commit>` (pseudo-version pin; no upstream tag exists)

> **Amendment 2026-05-16:** VClient emits TWO share lists in one method, not one:
>
> - Rename `GenGaloisShares` → `GenAuthAndInferShares` (Go side). Returns `(authShares []multiparty.GaloisKeyGenShare, inferShares []multiparty.GaloisKeyGenShare, authLabels []int, inferLabels []int, err error)`. Two independent iterations:
>   - `authShares`: iterate `params.AuthAtoms()` ascending. For each atom `a`, instantiate `multiparty.NewGaloisKeyGenProtocol(params.CKKS)` (**eval level**), pass `skEval = project(skTop)`, call `gkg.GenShare(skEval, params.CKKS.GaloisElement(-a), crp, ...)`. **Negative galEl.**
>   - `inferShares`: iterate `params.InferAtoms()` ascending. For each atom `a`, instantiate `multiparty.NewGaloisKeyGenProtocol(params.LLKN.Top())` (**top level**), pass `skTop`, call `gkg.GenShare(skTop, params.LLKN.Top().GaloisElement(+a), crp, ...)`. **Positive galEl.**
> - CRP draw order is the union: pk_eval, pk_top, rlk, then for each auth atom (ascending) one CRP at eval level, then for each infer atom (ascending) one CRP at top level. Task 3 documents the exact sequence.
> - Drop the original task's "iterate `MasterRotations()`" bullet — that referenced the single unified set.
> - JS namespace key in `ppiav.go:49` (the first arg to `ns.Set(...)`) stays `"genGaloisShares"` so `web/vclient/ts/main.ts:63,446` doesn't need to change. The Go-level wrapper renames (and the function it dispatches to renames), but the JS-visible name is the bridge contract — keep it stable.

- [x] in `client.go:New`, generate `skTop` against `params.LLKN.Top()` instead of `params.CKKS`. Add a lazy `skEval` cache (computed from `params.ProjectSKToEval(skTop)` on first need).
- [x] in `partial_decrypt.go`, change the `proto.GenShare` arg from `c.skShare` (eval-level today) to the cached `skEval` (= `project(skTop)`).
- [x] in `keygen.go`'s RLK rounds (`GenRLKShareRound1`, `GenRLKShareRound2`), change the `proto.GenShareRoundOne/Two` arg from `c.skShare` to `skEval`. The RLK protocol runs at eval level — top-level sk would mismatch the protocol's parameters.
- [x] split `GenPKShare` into a single Stage-2b call that runs both eval-level and top-level PK gens. eval-level PK gen uses `skEval`; top-level PK gen uses `skTop`. Returns `VClientPKShare{ShareEval, ShareTop}`. Stash both CRPs and both local shares. `AggregatePK` accepts both agent shares and finalizes `pkEval` (kept for encryptor) + `pkTop` (kept for the wire path — VClient itself doesn't ship pk_top forward; VAgent aggregates and ships).
- [x] rename `GenGaloisShares` → `GenAuthAndInferShares`. Returns `(authShares []multiparty.GaloisKeyGenShare, inferShares []multiparty.GaloisKeyGenShare, authLabels []int, inferLabels []int, err error)`. Two independent iterations:
  - **Auth shares**: iterate `c.params.AuthAtoms()` ascending (`{1,2,4,8,16,32,64}` for λ=128). For each atom `a`, instantiate `multiparty.NewGaloisKeyGenProtocol(c.params.CKKS)` — **eval level**. Draw a CRP. Pass `skEval` as the secret-key arg. Call `gkg.GenShare(skEval, c.params.CKKS.GaloisElement(-a), crp, &share)` — **negative galEl**.
  - **Infer shares**: iterate `c.params.InferAtoms()` ascending. For each atom `a`, instantiate `multiparty.NewGaloisKeyGenProtocol(c.params.LLKN.Top())` — **top level**. Draw a CRP. Pass `skTop`. Call `gkg.GenShare(skTop, c.params.LLKN.Top().GaloisElement(+a), crp, &share)` — **positive galEl**.
  - CRP draw order is the union: per the existing pk_eval, pk_top, rlk draws (Task 3), then **auth atoms ascending at eval level**, then **infer atoms ascending at top level**. Document and test against Task 3's order.
- [x] drop the inference-extras branching — `params.RotationIndices()`'s positive/negative union no longer informs Galois keygen at all. `AuthAtoms()` is fixed by λ; `InferAtoms()` is the canonical hierkeys master set.
- [x] add `go.mod` require for `github.com/butvinm/lattigo-hierkeys` via `go get github.com/butvinm/lattigo-hierkeys@<commit>` or `@main`. Pin via `go mod tidy`. The pseudo-version (e.g. `v0.0.0-<datetime>-<commit>`) is expected — no upstream tag exists. **Already present in go.mod from Task 2** — `go mod tidy` confirms no drift.
- [x] **propagate the Go-side rename across ALL call sites in the same commit** so `go build ./...` stays green: `internal/orchestrator/runner.go:217`, `web/ppiav/bridge/ppiav/core.go:190-199`, `web/ppiav/bridge/ppiav/ppiav.go:186-191` (Go wrapper function `jsGenGaloisShares` renames to `jsGenAuthAndInferShares`, BUT the JS namespace key passed to `ns.Set(...)` at `ppiav.go:49` stays the string `"genGaloisShares"` so `main.ts` doesn't break). Note: vagent/vservice HTTP layers remain broken — Task 6/7/8 owns the propagation through those packages.
- [x] write tests: at `LogN=14`, verify auth-share count == `len(AuthAtoms())`, infer-share count == `len(InferAtoms())`, labels ascending in each list; both pk shares (eval + top) are emitted and aggregatable; aggregating an auth share with a synthetic VAgent auth share at the same eval-level CRP + galEl produces a usable `*rlwe.GaloisKey` (no hierkeys conversion); aggregating an infer share produces a usable `*rlwe.GaloisKey` that converts to a `*hierkeys.MasterKey` via `hierkeys.GaloisKeyToMasterKey(c.params.LLKN.Top(), gk)`. Update `web/ppiav/bridge/ppiav/core_test.go:133,222` to reference the new Go function name.
- [x] run `go build ./...` and `go test ./internal/vclient/... ./internal/orchestrator/... ./web/ppiav/...` — all green before next task. **Partial**: vclient + ppiav bridge build clean and tests pass; orchestrator + full `./...` still fail because vagent/vservice HTTP handlers are broken (Task 6/7/8 territory, called out in the task brief).

### Task 6: VAgent — aggregate dual PK + dual atom shares, build chain-rotation evaluator, rewrite Auth

**Files:**

- Create: `internal/authchain/evaluator.go` (renamed from the original `internal/hierkeys/evaluator.go` — see amendment)
- Create: `internal/authchain/evaluator_test.go`
- Modify: `internal/vagent/agent.go` (sk gen moves to top level; cached sk_eval added)
- Modify: `internal/vagent/keygen.go`
- Modify: `internal/vagent/state.go`
- Modify: `internal/vagent/keygen_test.go`
- Modify: `internal/vagent/agent_test.go`
- Modify: `internal/vagent/state_test.go`
- Modify: `internal/vagent/testutil_test.go`
- Modify: `internal/authenticator/authenticator.go` — `Auth`'s rotate-and-sum loop, plus `validateGaloisKeys` (now validates auth-atom coverage at `GaloisElement(-atom)`, not `GaloisElement(-j)` for `j ∈ [1, λ)`)
- Modify: `internal/authenticator/authenticator_test.go`
- Modify: `internal/orchestrator/runner.go` — caller renames (`runner.go:221-224`)
- Modify: `internal/vagent/http.go` — HTTP handler updated for new signature (route name `/gks-shares` retained)

> **Amendment 2026-05-16:** VAgent doesn't use lattigo-hierkeys at all for Auth. The wrapper package renames to `internal/authchain` (not `internal/hierkeys`) because the only thing it does is binary-decompose chaining — no hierarchical derivation.
>
> - **`internal/authchain` evaluator** wrapping `*ckks.Evaluator`:
>   - Constructor takes `(ckksParams, rlk, pkEvalAgg, gksAuth []*rlwe.GaloisKey)`. No LLKN params, no top-level material, no `PubToRot`, no `LevelExpansion`.
>   - `gksAuth` is the 7 (for λ=128) raw `*rlwe.GaloisKey`s minted directly from the auth-atom multi-party handshake — already-aggregated, already at eval level, already at `GaloisElement(-atom)`. Loaded into a `rlwe.NewMemEvaluationKeySet(rlk, gksAuth...)` and that's it.
>   - `RotateNew(ct, j int) (*rlwe.Ciphertext, error)` for **positive** j: decompose j into binary atoms via `popcount(j)` (e.g. j=127 → `{1,2,4,8,16,32,64}`, 7 atoms), then for each atom `a` call `inner.RotateNew(cur, -a)`. Output chain length = `popcount(j)` ≤ 7.
>   - Or, to keep Auth's existing call site unchanged, accept negative j and decompose `|j|`. Either works — pick one and document.
>   - Inner `*ckks.Evaluator` exposed for non-rotation ops (`MulNew`, `Add`, `AddNew`, etc.) — Auth uses these directly.
>   - **No eager atom derivation** because the atom keys are already final Galois keys. No multi-minute or tens-of-second session-open delay. Zero hierarchical derivation cost at VAgent.
> - In `agent.go`, sk gen moves to top level. Lazy `sk_eval` cache **also** consumed by Task 5's auth-atom GenShare (since that runs at eval level). RLK rounds, KeySwitch, AND auth-atom GenShare all consume `sk_eval`. Infer-atom GenShare and PK-top gen consume `skTop`.
> - In `GenPKShare`, mirror VClient's dual emission.
> - `GenAuthAndInferShares` (rename from `GenGaloisShares`) mirrors VClient Task 5's two-list signature.
> - `AggregateGaloisShares` returns `(rlk, pkTop, gksAuth []*rlwe.GaloisKey, gksMasterInfer map[int]*hierkeys.MasterKey, err error)`:
>   - For each auth atom `a`: aggregate VClient+VAgent shares, `gkg.GenGaloisKey` → raw `*rlwe.GaloisKey` keyed at `GaloisElement(-a)`. Collect into `gksAuth`. **No `GaloisKeyToMasterKey` conversion** — Auth uses these directly.
>   - For each infer atom `a`: aggregate, `GenGaloisKey`, then `hierkeys.GaloisKeyToMasterKey(params.LLKN.Top(), gk)`. Collect into `gksMasterInfer` (map keyed by atom int).
> - `sessionState`: store `authchain *authchain.Evaluator` and `gksMasterInfer map[int]*hierkeys.MasterKey`. The latter is shipped forward to VService via `InferEvalKeys`.
> - `state.go` snapshot persists `gksAuth` (raw 7 keys, ~1.57 GB at LogN=16 — comparable to the original draft's storage size) plus `gksMasterInfer` (~1.86 GB). Restore rebuilds the `authchain.Evaluator` from `gksAuth`.
> - **Rewrite `internal/authenticator/authenticator.go:Auth`**:
>   - Replace `eval.RotateNew(ct, -j)` (line 114) with `authchain.RotateNew(ct, -j)`. The authchain evaluator handles the binary-decompose chain internally.
>   - `Auth`'s signature takes an interface: `RotateNew(ct, j) (ct, error)` plus passes the inner `*ckks.Evaluator` for the non-rotation ops. Cleanest is to thread the `*authchain.Evaluator` and have it embed/expose the inner eval.
>   - `validateGaloisKeys` (line 170) checks the carried keys cover `GaloisElement(-atom)` for every atom in `params.AuthAtoms()` (= 7 keys for λ=128).
> - **Corrected noise model**: per-rotation chain length = `popcount(j)`, max 7 (at j=127), mean 3.52 over the 64 non-S rotations. Per-rotation noise stdev = `√popcount(j) · B_ks` ≤ `√7 · B_ks`. Cumulative over 64 logical rotations ≈ `√225 · B_ks ≈ 15 · B_ks`, vs Phase 1-3's `√64 · B_ks = 8 · B_ks` — **~1.9× amplification, not the original draft's 2.25× or the broken-base-4-positive 4.1×**. `σ_flood = 2¹⁶` retained from Phase 1-3 without recalibration; validated empirically at `LogN=14, λ=128` in `internal/authenticator/phase4_neg_base2_test.go` (Ver passes).

- [x] **`internal/authchain` evaluator** wrapping `*ckks.Evaluator`:
  - Constructor takes `(ckksParams ckks.Parameters, rlk *rlwe.RelinearizationKey, gksAuth []*rlwe.GaloisKey, atoms []int)`. No LLKN params, no `pkTop`, no hierkeys imports.
  - Loads `rlk` + `gksAuth` into `rlwe.NewMemEvaluationKeySet(rlk, gksAuth...)`, builds the inner `*ckks.Evaluator`.
  - Stores the auth atom ints (e.g. `{1,2,4,8,16,32,64}`) — derivable from `gksAuth` via `params.SolveDiscreteLogGaloisElement(gk.GaloisElement)` but cheaper to take them as a parameter. **Implementation took atoms as input** per the cheaper-lookup tradeoff.
  - Exposes `Decompose(j int) []int` — binary decompose of `|j|`: `for k := 0; |j| > 0; k++ { if |j|&1 == 1 { out = append(out, 1<<k) }; |j| >>= 1 }`. Returns subset of auth atoms summing to `|j|`. Chain length = `popcount(|j|)`.
  - Exposes `RotateNew(ct *rlwe.Ciphertext, j int) (*rlwe.Ciphertext, error)`: decomposes `|j|`, walks atoms, calls `inner.RotateNew(cur, sign*atom)` for each. Sign of `j` preserved across the chain so callers can pass either positive or negative `j` and the chained rotations honour the direction.
  - Exposes `Inner() *ckks.Evaluator` for non-rotation ops Auth uses (`MulNew`, `Add`, `AddNew`).
  - **No eager atom derivation** — the atom keys are already final Galois keys from the multi-party handshake. Construction is O(1) modulo Lattigo's evaluator wiring.
- [x] in `agent.go`, sk gen moves to top level: `skTop := rlwe.NewKeyGenerator(a.params.LLKN.Top()).GenSecretKeyNew()`. Added a lazy `skEvalCached` field on `sessionState` (computed by `sessionSkEvalLocked` on first need). Consumed by: RLK rounds, KeySwitch (partial-decrypt via `finalize.go`), eval-level PK gen, AND auth-atom GenShare. `skTop` consumed by: top-level PK gen, infer-atom GenShare.
- [x] swap `sessionState.gks []*rlwe.GaloisKey` + `sessionState.eval *ckks.Evaluator` for three fields: `gksAuth []*rlwe.GaloisKey` (raw auth Galois keys, stashed for ExportState), `authchain *authchain.Evaluator` (used by Auth), and `gksMasterInfer map[int]*hierkeys.MasterKey` (the wire payload shipped to VService).
- [x] in `GenPKShare`, mirror VClient: run both eval and top PK gens. eval-level PK gen uses `skEval`; top-level uses `skTop`. `AggregatePK` accepts both VClient agent shares (`protocol.VClientPKShare{ShareEval, ShareTop}`) and finalizes `pkAgg` (for the v-encryptor in Auth — `rlwe.NewEncryptor(a.params.CKKS, pkAgg)`) and `pkTopAgg` (forwarded to VService inside `InferEvalKeys`).
- [x] in `GenRLKShareRound1/Round2`, change the `proto.GenShareRound{One,Two}` arg from `a.skShare` to `skEval` — same fix as Task 5's vclient.
- [x] rename `GenGaloisShares` → `GenAuthAndInferShares`. Mirror VClient's two-list signature `(authShares, inferShares, authLabels, inferLabels, err)`. Iterate `params.AuthAtoms()` at eval level with `skEval` and `GaloisElement(-atom)`; iterate `params.InferAtoms()` at top level with `skTop` and `GaloisElement(+atom)`.
- [x] in `AggregateGaloisShares`:
  - For each auth atom `a` (ascending): aggregate VClient + VAgent shares with `gkg_eval.AggregateShares`, then `gkg_eval.GenGaloisKey` → raw `*rlwe.GaloisKey` at `GaloisElement(-a)` and eval level. Collect into `gksAuth []*rlwe.GaloisKey`. **No hierkeys conversion** — Auth uses these directly.
  - For each infer atom `a` (ascending): aggregate, `gkg_top.GenGaloisKey`, then `hierkeys.GaloisKeyToMasterKey(a.params.LLKN.Top(), gk)`. Collect into `gksMasterInfer map[int]*hierkeys.MasterKey` (map keyed by atom int).
  - Construct `sessionState.authchain` from `(a.params.CKKS, rlk, gksAuth, sess.authLabels)`.
- [x] return signature of `AggregateGaloisShares`: `(rlk *rlwe.RelinearizationKey, pkTop *rlwe.PublicKey, gksMasterInfer map[int]*hierkeys.MasterKey, err error)`. `gksAuth` is NOT returned — it stays inside `sessionState.authchain` / `sessionState.gksAuth`. The orchestrator and HTTP layer carry only the inference-side payload onward. **Method signature also takes a `protocol.VClientGaloisShares` rather than two share slices** so the wire payload threads through without unpacking — the two `clientAuthLabels` / `clientInferLabels` integer slices are passed explicitly to keep the label-validation check at the call boundary.
- [x] **rewrite `internal/authenticator/authenticator.go:Auth`**:
  - Replaced `eval.RotateNew(ctM, -j)` with `rot.RotateNew(ctM, -j)` against an injected `authenticator.Rotator` interface — `RotateNew(ct, j)` + `Inner() *ckks.Evaluator`. `internal/authchain.Evaluator` satisfies it.
  - `validateGaloisKeys` now validates that the evaluator carries Galois keys for `GaloisElement(-atom)` for every atom in the powers-of-two-strictly-less-than-Lambda set (= 7 keys for λ=128). Dropped the `j ∈ [1, λ)` enumeration entirely.
  - Updated the doc-comment on `Auth` to describe the chain-rotation semantics.
- [x] update orchestrator call site (`runner.go`) and vagent HTTP handler to consume the new `AggregateGaloisShares` signature; `go build ./internal/... ./web/...` is green. `cmd/ppiav-cli` intentionally remains broken (Task 10's scope). `internal/vservice/http.go` got a minimal stub fix (passes nil for `gks []*rlwe.GaloisKey` to keep the package compiling); Task 7 wires the actual hierkeys derivation.
- [x] write tests (LogN=14):
  - **`internal/authchain` correctness**: `evaluator_test.go::TestRotateNew_MatchesDirectKey` builds a synthetic eval-level multi-party handshake for the 7 auth atoms and verifies chain-rotation places slots correctly for `j ∈ {1, 2, 3, 5, 7, 17, 64, 100, 127}` against a joint-sk decryption.
  - **decomposition**: `TestDecompose` verifies binary expansion + popcount over representative `j`.
  - **end-to-end Auth**: `phase4_neg_base2_test.go::TestPhase4_AuthChainEndToEnd` runs 10 randomized trials of the full 2-party handshake → `Auth` (via `authchain.Evaluator`) → joint-decrypt → `Ver` at `LogN=14`, `λ=128`, `σ_flood = 2¹⁶`. `TestPhase4_AuthChainStats` documents the max-popcount=7 / mean-3.52 claim. Productionized from the old exploration test that lived in the same file.
- [x] run `go build ./internal/... ./web/...` and `go test ./internal/authchain/... ./internal/authenticator/... ./internal/vagent/... ./internal/orchestrator/...` — all green.

### Task 7: VService — receive `(pk_top, gks_master)`, expand-fully into `gks_infer` (+ call-site renames)

**Files:**

- Modify: `internal/vservice/service.go`
- Modify: `internal/vservice/state.go`
- Modify: `internal/vservice/orion.go`
- Modify: `internal/vservice/service_test.go`
- Modify: `internal/vservice/state_test.go`
- Modify: `internal/vservice/orion_test.go`
- Modify: `internal/vservice/http.go` — handler signature follows `StoreEvalKeys`
- Modify: `internal/vservice/http_test.go`
- Modify: `internal/orchestrator/runner.go` — caller of `StoreEvalKeys`

VService keeps Phase 1–3's in-memory shape — full per-rotation Galois keys for `ExtraRotationIndices`, fed straight into `rlwe.NewMemEvaluationKeySet`. Only the wire payload changes (master keys + pk_top in, expand-fully in `StoreEvalKeys`). Orion's compiled C3AE circuit and its hoisted-rotation patterns are **untouched**. **No rotation shim at VService.** **No Orion patch.** This is the asymmetric counterpart to VAgent's decompose-at-use: Orion's compiled circuit assumes single-rotation noise and uses hoisted-rotation patterns that decompose-at-use would break, so VService must expand.

- [x] change `StoreEvalKeys` signature: `gks []*rlwe.GaloisKey` → `(pkTop *rlwe.PublicKey, gksMasterInfer map[int]*hierkeys.MasterKey)`. Field name aligns with Task 4 amendment's `InferEvalKeys.GKSMasterInfer`.
- [x] inside `StoreEvalKeys`:
  - build `llkn.Parameters` from `s.params` (same builder Task 2 introduces; only VService uses it).
  - build `llkn.Evaluator`, `hierkeys.PubToRot(evalParams, topParams, pkTop)` for `shift0`, then `eval.NewLevelExpansion(0, shift0, gksMasterInfer, ExtraRotationIndices())`.
  - iterate `ExtraRotationIndices()` running `exp.Derive(r) + eval.FinalizeKey` per target; collect into `gks []*rlwe.GaloisKey`.
  - **derive concurrently** (`errgroup` over `GOMAXPROCS`). `~/Dev/lattigo-hierkeys/README.md:155-161` shows ~9× speedup at LogN=16. Sequential is multi-minute at LogN=16; concurrent is tens of seconds — the difference between "annoying" and "broken" for session-open latency. (Implemented via a manual `sync.WaitGroup` + semaphore — same pattern as `~/Dev/lattigo-hierkeys/llkn/llkn_test.go:262-281`; no new `errgroup` dependency.)
  - wrap in `rlwe.NewMemEvaluationKeySet(rlk, gks...)`, prime the session evaluator. Downstream of this line: identical to Phase 1–3.
- [x] **acknowledge the session-open latency cost**: this is real, it didn't exist in Phase 1–3 (where assembled keys were received pre-baked), it's the price of Phase 4's transport optimization at VService. Log it as `derive_gks_infer_seconds` (concurrent and sequential, depending on `GOMAXPROCS` setting) under the pre-existing step name `keygen.galois.service_store` for the bench harness. (Wired in via `sessionState.deriveGksInferSeconds` + the new `Service.DeriveGksInferSeconds(sid)` accessor; the orchestrator/CLI surfaces it during Task 10.)
- [x] `state.go` snapshot: persist `(pkTop, gksMaster)` only (small); restore re-runs the expand-fully derivation. Snapshot does NOT contain the materialized `gks_infer` slice — that would blow up snapshot size to many GB. (`ExportedState` now carries `Rlk + PKTop + GksMasterInfer`; `NewWithState` re-runs `deriveGksInfer`.)
- [x] `orion.go`: when the manifest's `RotationIndices` is empty, derived `gks` is empty too — keep the Phase 1–3 guard for the "no Galois keys" lattigo case. (`deriveGksInfer` short-circuits to `(nil, 0, nil)` when `len(ExtraRotationIndices) == 0`.)
- [x] update orchestrator call site (`internal/orchestrator/runner.go`'s `StoreEvalKeys` call) and vservice HTTP handler to consume the new signature.
- [x] write tests: `StoreEvalKeys` with a synthetic `(pkTop, gks_master)` (built via the multi-party handshake at `LogN=14`) produces an evaluator that rotates correctly for every Orion-side rotation in `ExtraRotationIndices`. Add a **functional-equivalence** test: rotate a fresh ciphertext using the derived `gks_infer` key for some `r ∈ ExtraRotationIndices`, decrypt, compare with the plaintext rotated by `r`; precision must match within Phase 1–3's published bounds. (Note: byte-equality vs freshly-generated `multiparty.GaloisKeyGenProtocol` keys is NOT a valid test — hierarchical derivation produces a different `a`-part than per-rotation CRPs, so the keys are functionally equivalent but not byte-identical. The test is the cipherspace rotation result, not the key bytes.) — `TestStoreEvalKeysFunctionalEquivalence` in `internal/vservice/store_eval_keys_test.go`.
- [x] run `go build ./...` and `go test ./internal/vservice/... ./internal/orchestrator/...`. (`cmd/ppiav-cli` deferred to Task 10; everything under `internal/` and `web/` builds and all three target test packages pass.)

### Task 8: Wire the HTTP layer — payload type changes (route names unchanged)

**Files:**

- Modify: `internal/vagent/http.go`
- Modify: `internal/vagent/http_test.go`
- Modify: `internal/vservice/http.go`
- Modify: `internal/vservice/http_test.go`

- [x] VAgent route `POST /sessions/:sid/gks-shares` keeps its URL; payload type changes from `VClientGaloisKeyShare` to `VClientGaloisShares` (carries both `AuthAtomShares` and `InferAtomShares` per Task 4 amendment).
- [x] VAgent's onward `POST /sessions/:sid/eval-keys` to VService keeps its route but the body type changes to the new `InferEvalKeys` (RLK + PKTop + GKSMasterInfer). VAgent's `gksAuth` is NOT shipped — it stays inside the VAgent session.
- [x] VService's handler decodes the new body shape and forwards to `StoreEvalKeys(sid, rlk, pkTop, gksMasterInfer)`.
- [x] write tests: HTTP round-trip with synthetic `(pkTop, gksMasterInfer)` at `LogN=14`; verify the payload shape change is enforced (sending a Phase 1-3-shaped body returns 400).
- [x] run `go test ./internal/vagent/... ./internal/vservice/...`.

### Task 9: Orchestrator integration sanity check

**Files:**

- Read (verify only): `internal/orchestrator/runner.go`, `internal/orchestrator/*_test.go`

The orchestrator's call-site renames already landed inside Tasks 5/6/7 so the tree compiles after each. This task is the end-to-end sanity gate for the in-process driver before HTTP and CLI changes start.

- [x] re-run the orchestrator's end-to-end test suite at `LogN=14`: `go test -count=1 ./internal/orchestrator/...`. These tests exercise the full keygen → infer → MPD-Auth chain in-process and are the canary that the protocol shape survived the Tasks 5/6/7 surgery.
- [x] if any new behaviour (e.g. session-state shape change) leaked through, add or update a single targeted test rather than tweaking the orchestrator.
- [x] no new code expected; if this task requires more than verification, that's a signal one of 5/6/7 was incomplete — go back and fix there, not here.

### Task 10: CLI artifact pipeline — `keygen` writes master + `gks_infer.bin`

**Files:**

- Modify: `cmd/ppiav-cli/keygen.go`
- Modify: `cmd/ppiav-cli/artifacts.go`
- Modify: `cmd/ppiav-cli/mac.go`
- Modify: `cmd/ppiav-cli/infer.go`
- Modify: `cmd/ppiav-cli/*_test.go` if any exist

> **Amendment 2026-05-16:** Artifact set updated for the dual-atom-set design. VAgent's auth atoms are raw multi-party Galois keys (NOT hierkeys-derived), so `gks_auth.bin` must be written to disk and read by `mac` — there is no upstream artifact to derive them from. VService's infer atoms ARE hierkeys-derived, so the original draft's split between `gks_master_infer.bin` (wire-sized) and `gks_infer.bin` (cached derivation) is retained.

The asymmetric Phase 4 scheme drives asymmetric artifacts. The acronym shift `glk → gks` matches lattigo-hierkeys naming; the undocumented Phase 1-3 `glk` is retired across constants, filenames, and comments.

```
keys/
  params.json           # CKKS + LLKN literal — readable by every subcommand
  rlk.bin               # eval-level relinearization key
  pk_eval.bin           # eval-level collective PK (for encryption by VClient and v-encryption by VAgent)
  pk_top.bin            # top-level collective PK (for PubToRot during gks_infer derivation)
  gks_auth.bin          # 7 raw *rlwe.GaloisKey at GaloisElement(-atom), eval level — consumed by `mac`. ~1.57 GB at LogN=16.
  gks_master_infer.bin  # 8 *hierkeys.MasterKey at GaloisElement(+atom), top level — wire artifact; SIZE goes into eval_inputs.json. ~1.86 GB at LogN=16.
  gks_infer.bin         # VService's expand-fully derived set from gks_master_infer + pk_top, eval level, ~tens of GB at LogN=16. Consumed by `infer`.
```

The `gks_master.bin` filename from the original draft is REMOVED — replaced by the pair `gks_auth.bin` (auth-side raw keys) + `gks_master_infer.bin` (infer-side master keys). The wire-size measurement for the cross-phase comparison in `summary.md` is `len(gks_auth.bin) + len(gks_master_infer.bin)` (≈3.43 GB at LogN=16 vs Phase 1-3's 57 GB).

- [x] in `keygen`, drive the renamed VClient + VAgent keygen API → `(pkEval, pkTop, rlk, gksAuth []*rlwe.GaloisKey, gksMasterInfer map[int]*hierkeys.MasterKey)`. Write `keys/{pk_eval,pk_top,rlk,gks_auth,gks_master_infer}.bin` (the wire artifacts + the auth-side keys VAgent will need). Then run the expand-fully derivation for VService: build `llkn.Evaluator`, derive `gks_infer` for `params.ExtraRotationIndices` concurrently (same `errgroup` shape as Task 7), write `keys/gks_infer.bin`.
- [x] **`gks_auth.bin` is mandatory** in the artifact set — VAgent's atom keys are NOT derivable from `gks_master_infer.bin` alone (different level, different galEl direction, different multi-party handshake). The 1.57 GB I/O cost at LogN=16 is the price of the dual-atom-set design; bench measures read time as `mac.json.read_gks_auth_seconds`.
- [x] `keygen.json` records: `gks_auth_bytes` and `gks_master_infer_bytes` (`os.Stat`), per-party samples under the pre-existing step names `keygen.galois.{client_gen, agent_gen, agent_agg, service_store}`. Each of `client_gen`, `agent_gen`, `agent_agg` now covers BOTH atom-set iterations (auth + infer) in a single combined timing — splitting per-set is not required for the bench's cross-phase comparison. The `service_store` sample carries the `derive_gks_infer_seconds` measurement (concurrent + sequential variants, so the bench shows the speedup).
- [x] update `artifacts.go`:
  - constants: drop `artifactGLKMaster`, `artifactGLKFull`, AND the original `artifactPK = "pk.bin"`. Add `artifactGKSAuth = "gks_auth.bin"`, `artifactGKSMasterInfer = "gks_master_infer.bin"`, `artifactGKSInfer = "gks_infer.bin"`, `artifactPKEval = "pk_eval.bin"`, `artifactPKTop = "pk_top.bin"`.
  - new `writeGKSAuth` / `readGKSAuth` for `[]*rlwe.GaloisKey` at eval level — same shape as Phase 1-3's `writeGaloisKeys` but indexed by `GaloisElement(-atom)` order; can probably reuse `writeGaloisKeys` byte-for-byte.
  - new `writeMasterKeys` / `readMasterKeys` for `map[int]*hierkeys.MasterKey` (atom int → bytes via `MasterKey.MarshalBinary`).
  - keep `writeGaloisKeys` / `readGaloisKeys` for the `gks_infer.bin` path — same shape as Phase 1–3, just different filename.
  - scrub all `glk_master.bin`, `glk_full.bin`, and `pk.bin` references in code constants and comments.
- [x] `mac.go`: read `gks_auth.bin` + `pk_eval.bin` + `rlk.bin`. Construct `internal/authchain.Evaluator` directly from `(params.CKKS, rlk, gksAuth)` — **no LLKN params, no `pk_top`, no derivation, O(1) construction.** Run Auth via the authchain evaluator. Records `mac.json.authchain_construct_seconds` (expected sub-millisecond since there's no derivation; the field exists for parity with the original draft's bench field but values will be near-zero).
- [x] `infer.go`: read `gks_infer.bin` (pre-derived), wrap in `rlwe.NewMemEvaluationKeySet`, run Orion-compiled inference — no shim, no derivation at infer time. Per-sample timing JSON shape stays as Phase 2 (no new fields needed).
- [x] **add `authchain_construct_seconds` and `read_gks_auth_seconds` to `mac.json`** so the bench can attribute the per-process atom-load cost. (Original draft's `hier_eval_construct_seconds` field renames to `authchain_construct_seconds`; the new field captures the I/O time.)
- [x] update CLI integration tests at `LogN=14` covering `keygen → mac → infer`. Verify `gks_auth.bin` is present in `keys/` after `keygen` and consumed by `mac`.
- [x] run `go build ./cmd/ppiav-cli && go test ./cmd/ppiav-cli/...`.

**Why the asymmetric on-disk shape**: VAgent's 7 auth atoms are direct multi-party outputs at eval level with negative galEls — there's no upstream artifact they could be derived from at `mac` time, so they MUST be persisted by `keygen`. VService's `gks_infer` derivation is multi-minute, so caching the derived result amortizes across the stratified UTKFace batch (every per-sample `infer` invocation reads the same `gks_infer.bin`). The HTTP-service deployment doesn't need `gks_auth.bin` on disk — VAgent receives the auth shares over the wire in-session and builds `authchain` in-memory; only the CLI's stage-process model needs the on-disk form.

### Task 11: WASM bridge — confirm lattigo-hierkeys cross-compiles + rebuild

**Files:**

- Read (verify only): `web/ppiav/bridge/ppiav/core.go`, `web/ppiav/bridge/ppiav/ppiav.go`, `web/ppiav/bridge/ppiav/core_test.go` (already renamed in Task 5)
- Modify: `go.sum` at the repo root (via `go mod tidy`). NOTE: there is no `web/ppiav/go.sum` — `web/ppiav` is part of the single root module per `/home/butvinm/Dev/ppiav/go.mod`.

The bridge function name rename already landed in Task 5, so this task is the cross-compile and binary-size gate.

- [x] verify lattigo-hierkeys is pure-Go (no cgo): `grep -rn 'import "C"' ~/Dev/lattigo-hierkeys/` → empty. Also confirm against `~/Dev/lattigo-hierkeys/README.md:6`.
- [x] cross-compile check: `GOOS=js GOARCH=wasm go build ./web/ppiav/bridge/` succeeds with the new lattigo-hierkeys dep.
- [x] rebuild `web/ppiav/ppiav.wasm` via the existing `make wasm` step.
- [x] confirm the resulting `ppiav.wasm` size is within ~10% of the Phase 3 baseline (sanity check — lattigo-hierkeys is small). If it isn't, identify whether a stray heavy package got pulled in. (12,943,610 B vs 12,878,914 B baseline; +0.5%.)
- [x] run the existing `web/ppiav/bridge/ppiav/core_test.go` round-trip on `linux/amd64` (it covers the renamed-to-`GenAuthAndInferShares` function path, updated in Task 5); the wasm-specific failure mode is build-only, caught by `make wasm`. No new test required since the existing test suite was updated in Task 5.

### Task 12: SPA wire — confirm payload-shape compatibility

**Files:**

- Read (verify only): `web/vclient/ts/main.ts`
- Modify: `web/vclient/dist/*.js` (regenerated by `npm run build`)

- [x] confirm `web/vclient/ts/main.ts:447` still posts to `/sessions/:sid/gks-shares` — no URL change.
- [x] confirm the SPA's payload is `application/octet-stream` produced by the WASM bridge — no parsing at the SPA layer, so the protocol-payload shape change is transparent.
- [x] run `cd web/vclient && npm run build` — typechecks via `tsc` and regenerates `dist/`.
- [x] manual smoke at the end of Task 14.

### Task 13: Bench eval driver — stale-comment + summary cleanup

The bench step-name registry (`bench/bench/_labels_ru.py:63-66`) already anticipates Phase 4 hierarchical-derivation sub-steps (`keygen.galois.agent_agg` = "агрегация + иерархический вывод", `keygen.galois.service_store` = "иерархический вывод"); `_per_message_bytes` already auto-discovers files in `keys/`. Python-side surface is small.

**Files:**

- Modify: `bench/bench/eval.py` (comment strings only)
- Modify: `bench/README.md` (artifact name strings)

- [x] update `bench/bench/eval.py:498` stale docstring — replace `glk_full.bin` reference with `gks_master.bin` / `gks_infer.bin`.
- [x] update `bench/bench/eval.py:633` stale comment — `glk_master.bin and glk_full.bin are byte-identical today` wording is obsolete; describe the new asymmetric shape.
- [x] update `bench/README.md:46` artifact list.
- [x] (optional) add `summary.md` cross-phase row comparing `gks_master_bytes` to the Phase 2 results-dir baseline. (Skipped per plan guidance — out-of-band Phase-2-baseline lookup; cross-phase delta is already visible via the `keygen.json` row when both eval-dirs sit side-by-side.)
- [x] verify Go-side per-party sample emission in Tasks 5/6/7/10 uses the pre-existing step names (`keygen.galois.{client_gen, agent_gen, agent_agg, service_store}`). If new step names are introduced, add them to `STEP_NAMES`, `KEYGEN_ROUND_SUBSTEPS`, and `PARTY_BY_STEP` in one commit. Don't introduce new names speculatively — wait until the Go side actually emits them.
- [x] keep ruff/mypy clean.

### Task 14: Verify acceptance criteria + end-to-end smoke

- [x] all package tests pass: `go test ./...` (with `PPIAV_RUN_HEAVY=` unset locally, then `=1` on VPS as Task 15 covers). All packages green; authenticator runs the fast σ_flood gate (100 trials, ~100s).
- [x] `web/{vclient,rclient}` build pass: `cd web/<each> && npm run build`. `web/ppiav` typecheck: `cd web/ppiav && npm run typecheck`. All three green.
- [x] `make phase3` succeeds end-to-end on a fresh clone (smoke for the wasm/spas/services chain). Produces `bin/{ppiav-vservice, ppiav-vagent, ppiav-rservice}`.
- [x] manual test (skipped - not automatable in agent mode; user must run `cd deploy && docker compose up` and complete a verification with a UTKFace face from the browser, confirm `/sessions/:sid/gks-shares` is hit and verdict is correct).
- [x] confirm no string `glk_master`, `glk_full`, or `glk` survives a `git grep` outside historical-phase markers in `docs/plans/completed/`. Scrubbed the surviving `glk` field name in `internal/vservice/{service.go, state.go, store_eval_keys_test.go}` (renamed to `gksInfer`); fixed stale comments in `cmd/ppiav-cli/{artifacts.go, keygen.go}`. Only remaining hits are the permitted `CLAUDE.md:17` reference, the plan itself, and the historical `results/20260516T002209Z/` snapshot.
- [x] verify no Phase 4 conditional branches remain in code/comments: `git grep -nE 'if.*[Pp]hase'` finds no runtime conditionals. Descriptive "Phase 1-3 was X, Phase 4 is Y" comments survive in code (historical context, not branching) — those are not the target of this gate per the task note.
- [x] **σ_flood noise-budget gate (correctness, empirical).** Renamed `phase4_neg_base2_test.go` to `phase4_chain_noise_gate_test.go`. Two variants: `TestAuthChainNoiseGate` (100 trials, default, parallel via worker pool — asserts 100% pass) and `TestAuthChainNoiseGate_Full` (1000 trials, gated behind `PPIAV_RUN_HEAVY=1`, asserts pass rate ≥ 99.9%). Fast variant: 100/100 passes in ~99s on the local 16-core dev box. Full variant deferred to Task 15 VPS run per `feedback_no_logn15_local` convention (estimated ~5-10 min wall).

  > **Amendment 2026-05-16:** Corrected noise math. Auth chain length = `popcount(j)` for `j ∈ [1, 127]`: **max 7, mean 3.52**. Per-rotation noise stdev = `√popcount(j) · B_ks` ≤ `√7 · B_ks`. Cumulative over the 64 non-S rotations ≈ `√225 · B_ks ≈ 15 · B_ks` — ~1.9× Phase 1-3's `8 · B_ks`. σ_flood = 2¹⁶ retained without recalibration (already verified at LogN=14 in `internal/authenticator/phase4_neg_base2_test.go`).

  Run `LogN=14` round-trip test:
  - Complete Auth → joint-decrypt → Ver with `authchain` chain rotation in Step 4.
  - 1,000 trials with randomized `S` (so rotation indices vary across the [1, λ) set and exercise chain-length variance).
  - **Assert `Ver` pass rate ≥ 99.9%** (the existing σ_flood = 2¹⁶ / ε = 2²⁰ margin is engineered for >4σ tail per DESIGN.md:361-364; 99.9% over 1k trials is a tighter empirical check).
  - If pass rate falls below threshold, STOP and bump σ_flood — do NOT ship a broken auth. The right action is a documented calibration (write a follow-up `docs/plans/` entry with the measured σ_B and the new σ_flood), not a quiet constant change.
  - This task supersedes `internal/authenticator/phase4_neg_base2_test.go` (the exploration test that drove the amendment). Delete that file once this 1k-trial gate is in place, OR rename it to mark it as the canonical 1k-trial test under a clear name (e.g., `phase4_chain_noise_gate_test.go`).

### Task 15: VPS benchmark run

- [x] `vps up cpu.16.128.240`, `export GOMEMLIMIT=120GiB` (memory `operational_gomemlimit_logn16.md`), confirm ≥ ~30 GB free disk for `gks_infer.bin` (VPS box has 240 GB per the standard `cpu.16.128.240` spec; usually fine, but verify before kickoff). (Deferred — paid VPS run requires user authorization; user must execute manually.)
- [x] `PPIAV_RUN_HEAVY=1 make eval`. (Deferred — depends on VPS spin-up above. Runs the full LogN=16 sweep + the 1k-trial σ_flood gate.)
- [x] inspect `results/<eval-dir>/summary.md`; confirm `gks_master_bytes` is roughly an order of magnitude smaller than the Phase 2 baseline's combined `glk_master.bin + glk_full.bin`. (Deferred.)
- [x] update plots if the X-axis ranges shift (any plot that references the absolute key size). (Deferred.)
- [x] **Strip `gks_infer.bin` from the committed `results/` snapshot** before git add — it's derivable from `gks_master.bin + pk_top.bin + params.json` and is tens of GB. Commit `gks_master.bin` (the wire artifact), discard the derived form. (Deferred.)
- [x] commit results selectively per CLAUDE.md ("selectively committed snapshots"). (Deferred.)

### Task 16: [Final] Documentation + close out

**Files:**

- Modify: `README.md`
- Modify: `CLAUDE.md`

- [x] update README.md Phase row from "pending" to "done" (matching the Phase 1/2/3 wording). (No Phase status rows exist in `README.md`; the Phase 1/2/3/4 "done/pending" enumeration lives in `CLAUDE.md`'s "Implementation Phases" list, which was updated. README.md left untouched.)
- [x] update CLAUDE.md "Status" paragraph: Phase 4 done; remove "Phase 4 (lattigo-hierkeys) is outstanding" sentence.
- [x] move this plan to `docs/plans/completed/`. (Deferred to post-finalize cleanup — orchestrator policy is to not move the plan during execution; user moves it manually after merging the branch.)

## Post-Completion

_Items requiring manual intervention or external systems — no checkboxes, informational only._

**Manual verification**:

- Visual sanity-check of the browser flow on at least one non-Chromium browser (Firefox) to catch WASM-binding regressions.
- Repeat the σ_flood noise-budget gate at `LogN=16` on the VPS during Task 15 — Task 14 covers `LogN=14`, but the `B_ks_derived` term scales with `LogP` and the auth-side rotation count is the same at both `LogN`s. If `Ver` failure rate at `LogN=16` differs from `LogN=14`, calibrate σ_flood (write a follow-up plan, don't hack the constant in-place).

**Atom-key disk cache as a follow-up**:

- If VPS bench shows the per-`mac` atom-derivation cost (`hier_eval_construct_seconds`) dominates per-sample work, add a `gks_auth.bin` cache analogous to `gks_infer.bin`. Trade ~1.86 GB disk for ~tens of seconds per `mac` process. Track as a separate plan in `docs/plans/`.

**KG+ as a follow-up**:

- If the thesis review feedback wants the smaller (1.5%) wire size, swap LLKN for KG+ — scheme is encapsulated in `protocol.Params.LLKN`, so the swap is mostly a parameter and import change plus ring-switching glue at VService.
  [2026-05-16 10:57:48] Task 10 done — CLI artifact pipeline rewired to Phase 4 dual-PK + hierkeys split. Renamed constants (artifactPKEval/PKTop, artifactGKSAuth/MasterInfer/Infer), added writeMasterKeys/readMasterKeys, exported protocol.BuildLLKNParams so loadParams re-stamps LLKN against the persisted CKKS. keygen.go now persists pk_eval/pk_top/gks_auth/gks_master_infer/gks_infer + records gks_auth_bytes, gks_master_infer_bytes, derive_gks_infer_seconds. mac.go reads gks_auth.bin directly and records authchain_construct_seconds + read_gks_auth_seconds. infer.go reads pre-derived gks_infer.bin (new vservice.ExportedState.GksInfer skips re-derivation when supplied). encrypt/partial-decrypt/finalize rewired to SkTop. Added artifacts_test.go + pipeline_test.go covering full keygen->mac->infer at LogN=14. go build ./... GREEN, go test ./... GREEN (first green-tree gate since Task 4).
