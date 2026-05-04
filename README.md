# ppiav

Privacy-Preserving Image Attribute Verification — bachelor's thesis prototype demonstrating FHE-based facial attribute verification with CKKS (via Lattigo and Orion).

See [`docs/DESIGN.md`](docs/DESIGN.md) for the full architecture.

**Phase 1 status:** complete — CKKS scaffolding, synthetic `x²` circuit, in-process protocol, benchmark CLI emitting JSON, Python plotting and tables.

## Quick start

```sh
# Run the full §3 protocol in-process (5 iterations) and emit JSON.
go run ./cmd/ppiav-cli e2e --n 5

# Per-step benchmarks (each writes to results/phase1/<step>.json).
for step in keygen encrypt-image infer mac decrypt-result verify-mac; do
    go run ./cmd/ppiav-cli "$step" --n 5
done

# Render Markdown summary tables to stdout.
cd bench && uv run python -m bench.tables ../results/phase1

# Render PNG plots into ../results/phase1/plots/.
cd bench && uv run python -m bench.plot ../results/phase1
```

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
