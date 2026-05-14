# ppiav

Privacy-Preserving Image Attribute Verification — bachelor's thesis prototype demonstrating FHE-based facial attribute verification with CKKS (via Lattigo and Orion).

See [`docs/DESIGN.md`](docs/DESIGN.md) for the full architecture.

**Phase 1 status:** complete — CKKS scaffolding, synthetic `x²` circuit, in-process protocol, benchmark CLI emitting JSON, Python plotting and tables.

**Phase 2 status:** complete — Orion-compiled C3AE inference swaps in for `x²` when the CLI is pointed at an Orion build directory via `--orion`. Output JSON shifts to `results/phase2/`.

## Quick start — Phase 2 (Orion-compiled C3AE)

Phase 2 requires Orion's compiled C3AE model. Both `logn15` and `logn16` configs are buildable in-tree via the training pipeline under `models/`. See `models/README.md` for the full build steps.

```sh
# Prerequisite: confirm Orion's compiled model + reference input exist.
# These are produced by the in-tree training pipeline under models/.
ls ./models/out/logn15/model.orion
ls ./models/out/inputs/sample_0.bin

# Full §3 protocol against C3AE inference. Output lands in results/phase2/.
go run ./cmd/ppiav-cli e2e \
    --orion ./models/out/logn15 \
    --image ./models/out/inputs/sample_0.bin \
    --n 5

# Per-step benchmarks against the C3AE profile.
ORION=./models/out/logn15
IMG=./models/out/inputs/sample_0.bin
go run ./cmd/ppiav-cli keygen         --orion "$ORION" --n 5
go run ./cmd/ppiav-cli encrypt-image  --orion "$ORION" --image "$IMG" --n 5
go run ./cmd/ppiav-cli infer          --orion "$ORION" --image "$IMG" --n 5
go run ./cmd/ppiav-cli mac            --orion "$ORION" --n 5
go run ./cmd/ppiav-cli decrypt-result --orion "$ORION" --n 5
go run ./cmd/ppiav-cli verify-mac     --orion "$ORION" --n 5

# Render Markdown tables and PNG plots from results/phase2/.
cd bench && uv run python -m bench.tables ../results/phase2
cd bench && uv run python -m bench.plot   ../results/phase2
```

### Preparing your own input image

`models/prepare_samples.py` implements the 5-step preprocessing pipeline from `docs/DESIGN.md` §`internal/vclient` and writes a 12288-float64 `.bin` ready to feed the CLI:

```sh
cd models && uv run python -m models.prepare_samples --idx 0 --data-dir ./data/UTKFace --out-dir ./out/inputs
go run ./cmd/ppiav-cli e2e \
    --orion ./models/out/logn15 \
    --image ./models/out/inputs/sample_0.bin --n 1
```

## Failure modes

Coverage status for the failure-mode taxonomy spelled out in [`docs/DESIGN.md`](docs/DESIGN.md#failure-modes). The Phase-1+2 prototype runs entirely in-process, so anything HTTP-shaped is deferred to Phase 3.

| ID  | Trigger                             | Phase-1+2 coverage                                                                                                                                                                                                                                                                                                                                                 |
| --- | ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| F1  | `Ver` returns false                 | Covered — `internal/authenticator/authenticator_test.go` (`TestVerRejectsTamperedSlot`, `TestVerRejectsTamperedValueSlot`) and orchestrator mock-reject `internal/orchestrator/runner_test.go` (`TestRunnerRejectsNegativeLogit`). Manual end-to-end tamper drill lives in `docs/plans/completed/20260514-phase-1-2-multiparty-ckks-and-c3ae.md` §Post-Completion. |
| F2  | Malformed wire input                | TODO — deferred to Phase 3. The in-process runner passes wire types by value; no `BinaryMarshaler` path is exercised yet. Round-trip tests under `internal/protocol/wire_test.go` are skipped placeholders.                                                                                                                                                        |
| F3  | Inference error                     | TODO — deferred to Phase 3 (VService is in-process, errors propagate as Go returns; no HTTP transport).                                                                                                                                                                                                                                                            |
| F4a | VService unreachable, Stage 1 setup | TODO — deferred to Phase 3 (HTTP transport).                                                                                                                                                                                                                                                                                                                       |
| F4b | VService unreachable, Stages 2–3    | Covered — `internal/orchestrator/runner_test.go` (`TestRunnerF4bDenyByDefault`) pins deny-by-default via `rservice.CheckAccess(sid) == VerdictUnknown`.                                                                                                                                                                                                            |

## Tests

```sh
# Go unit suite — fast. Covers every internal package including the
# in-process orchestrator's keygen → infer → verify chain.
go test ./...

# Python suite — bench/ post-processing.
cd bench && uv run pytest && uv run ruff check . && uv run mypy bench tests

# Python suite — models/ preprocessing pipeline.
cd models && uv run pytest && uv run ruff check . && uv run mypy models tests
```

End-to-end runs against full `LogN=16` parameters and the Phase-2 Orion path are **manual verification** — see `docs/plans/completed/20260514-phase-1-2-multiparty-ckks-and-c3ae.md` §Post-Completion for the acceptance walkthrough. Noise / σ-calibration is a post-Phase-4 follow-up per `docs/DESIGN.md` §`ε and σ_flood`.

## Repo layout

See `docs/DESIGN.md` §7. Phase 1+2 implement `internal/{protocol, authenticator, vclient, vagent, vservice, rservice, orchestrator, bench}`, `cmd/ppiav-cli`, the Python `bench/` post-processing project, and the Python `models/` preprocessing project. Phases 3–4 are deferred (see `docs/DESIGN.md` §4).
