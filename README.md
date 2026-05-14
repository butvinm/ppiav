# ppiav

Privacy-Preserving Image Attribute Verification — bachelor's thesis prototype demonstrating FHE-based facial attribute verification with CKKS (via Lattigo and Orion).

See [`docs/DESIGN.md`](docs/DESIGN.md) for the full architecture.

**Phase 1 status:** complete — CKKS scaffolding, synthetic `x²` circuit, in-process protocol, benchmark CLI emitting JSON, Python plotting and tables.

**Phase 2 status:** complete — Orion-compiled C3AE inference swaps in for `x²` when the CLI is pointed at an Orion build directory via `--orion`. Output JSON shifts to `results/phase2/`.

## Quick start — Phase 1 (synthetic `x²`)

```sh
# Run the full §3 protocol in-process (5 iterations) and emit JSON.
go run ./cmd/ppiav-cli e2e --image cmd/ppiav-cli/testdata/synthetic.bin --n 5

# Per-step benchmarks (each writes to results/phase1/<step>.json).
go run ./cmd/ppiav-cli keygen --n 5
go run ./cmd/ppiav-cli encrypt-image --image cmd/ppiav-cli/testdata/synthetic.bin --n 5
go run ./cmd/ppiav-cli infer --n 5
go run ./cmd/ppiav-cli mac --n 5
go run ./cmd/ppiav-cli decrypt-result --n 5
go run ./cmd/ppiav-cli verify-mac --n 5

# Render Markdown summary tables to stdout.
cd bench && uv run python -m bench.tables ../results/phase1

# Render PNG plots into ../results/phase1/plots/.
cd bench && uv run python -m bench.plot ../results/phase1
```

## Quick start — Phase 2 (Orion-compiled C3AE)

Phase 2 requires Orion's compiled C3AE model. The plan references `logn16` as canonical, but only `logn15/model.orion` is materialised on disk today — use `logn15` until a `logn16` build lands. See `docs/plans/20260514-phase-1-2-multiparty-ckks-and-c3ae.md` §Task 14 for the deviation note.

```sh
# Prerequisite: confirm Orion's compiled model + reference input exist.
ls ~/Dev/orion/examples/c3ae-demo/out/logn15/model.orion
ls ~/Dev/orion/examples/c3ae-demo/out/inputs/sample_test.bin

# Full §3 protocol against C3AE inference. Output lands in results/phase2/.
go run ./cmd/ppiav-cli e2e \
    --orion ~/Dev/orion/examples/c3ae-demo/out/logn15 \
    --image ~/Dev/orion/examples/c3ae-demo/out/inputs/sample_test.bin \
    --n 5

# Per-step benchmarks against the C3AE profile.
ORION=~/Dev/orion/examples/c3ae-demo/out/logn15
IMG=~/Dev/orion/examples/c3ae-demo/out/inputs/sample_test.bin
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
cd models && uv run python -m models.prepare_samples --in path/to/face.jpg --out /tmp/face.bin
go run ./cmd/ppiav-cli e2e \
    --orion ~/Dev/orion/examples/c3ae-demo/out/logn15 \
    --image /tmp/face.bin --n 1
```

## Failure modes

Coverage status for the failure-mode taxonomy spelled out in [`docs/DESIGN.md`](docs/DESIGN.md#failure-modes). The Phase-1+2 prototype runs entirely in-process, so anything HTTP-shaped is deferred to Phase 3.

| ID  | Trigger                             | Phase-1+2 coverage                                                                                                                                                                                                                                                                                                                                       |
| --- | ----------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| F1  | `Ver` returns false                 | Covered — `internal/authenticator/authenticator_test.go` (`TestVerRejectsTamperedSlot`, `TestVerRejectsTamperedValueSlot`) and orchestrator mock-reject `internal/orchestrator/runner_test.go` (`TestRunnerRejectsNegativeLogit`). Manual end-to-end tamper drill lives in `docs/plans/20260514-phase-1-2-multiparty-ckks-and-c3ae.md` §Post-Completion. |
| F2  | Malformed wire input                | TODO — deferred to Phase 3. The in-process runner passes wire types by value; no `BinaryMarshaler` path is exercised yet. Round-trip tests under `internal/protocol/wire_test.go` are skipped placeholders.                                                                                                                                              |
| F3  | Inference error                     | TODO — deferred to Phase 3 (VService is in-process, errors propagate as Go returns; no HTTP transport).                                                                                                                                                                                                                                                  |
| F4a | VService unreachable, Stage 1 setup | TODO — deferred to Phase 3 (HTTP transport).                                                                                                                                                                                                                                                                                                             |
| F4b | VService unreachable, Stages 2–3    | Covered — `internal/orchestrator/runner_test.go` (`TestRunnerF4bDenyByDefault`) pins deny-by-default via `rservice.CheckAccess(sid) == VerdictUnknown`.                                                                                                                                                                                                  |

## Tests

```sh
# Default unit suite — fast.
go test ./...

# Integration suite — full §3 protocol e2e in one test.
go test -tags=integration ./...

# Noise-budget validation — slow (~90s, 100 keygens).
# Load-bearing for DESIGN.md §3.6 forge bound.
go test -tags=noise ./internal/protocol/...

# Python suite.
cd bench && uv run pytest && uv run ruff check . && uv run mypy bench tests
```

## Repo layout

See `docs/DESIGN.md` §7. Phase 1 implements `internal/{protocol, ckks, vclient, vagent, vservice, rservice, bench}`, `cmd/ppiav-cli`, and `bench/`. Phases 2–4 are deferred (see `docs/DESIGN.md` §4).
