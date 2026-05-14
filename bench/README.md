# bench/

Post-processing for `internal/bench` JSON output: Markdown summary tables
and per-stage PNG bar plots.

The Go harness writes one JSON `Run` per invocation to `results/phaseN/`
(see `internal/bench/bench.go`). This Python project reads those files
and aggregates them by `Sample.name` (the stage label).

## Quick start

```sh
cd bench
uv sync                                       # create venv + install deps
uv run pytest                                 # run unit tests
uv run ruff check .                           # lint
uv run mypy bench tests                       # strict type-check

uv run python -m bench.tables ../results/phase1   # Markdown table to stdout
uv run python -m bench.plot   ../results/phase1   # PNGs → ../results/phase1/plots/
```

## Layout

- `bench/load.py` — parse `Run`/`Sample` JSON into dataclasses.
- `bench/tables.py` — `render_tables(runs)` + `__main__`.
- `bench/plot.py` — `write_plots(runs, out_dir)` + `__main__`.
- `tests/fixtures/sample_run.json` — committed schema example.
