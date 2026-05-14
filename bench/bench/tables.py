"""Markdown summary tables for bench JSON output.

Usage: `python -m bench.tables <dir>` prints one table aggregating samples
across every *.json in <dir>, grouped by Sample.name (the stage label).
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np

from bench.load import Run, Sample, load_dir


def _collect_by_stage(runs: list[Run]) -> dict[str, list[Sample]]:
    out: dict[str, list[Sample]] = {}
    for run in runs:
        for s in run.samples:
            out.setdefault(s.name, []).append(s)
    return out


def render_tables(runs: list[Run]) -> str:
    """Return a Markdown table summarising bench samples per stage.

    Columns: stage, n, mean wall ms, p50 ms, p95 ms, mean heap inuse MiB.
    Stages are listed in ascending order of mean wall time so the hot spots
    surface at the bottom — quick visual scan.
    """
    by_stage = _collect_by_stage(runs)
    if not by_stage:
        return "_(no samples)_\n"

    rows: list[tuple[str, int, float, float, float, float]] = []
    for stage, samples in by_stage.items():
        walls_ms = np.array([s.wall_ms for s in samples], dtype=np.float64)
        heap_mib = np.array([s.heap_delta_mib for s in samples], dtype=np.float64)
        rows.append(
            (
                stage,
                len(samples),
                float(walls_ms.mean()),
                float(np.percentile(walls_ms, 50)),
                float(np.percentile(walls_ms, 95)),
                float(heap_mib.mean()),
            )
        )
    rows.sort(key=lambda r: r[2])

    header = "| stage | n | mean ms | p50 ms | p95 ms | mean heap MiB |"
    sep = "|---|---:|---:|---:|---:|---:|"
    lines = [header, sep]
    for stage, n, mean_ms, p50, p95, heap in rows:
        lines.append(
            f"| {stage} | {n} | {mean_ms:.2f} | {p50:.2f} | {p95:.2f} | {heap:.1f} |"
        )
    return "\n".join(lines) + "\n"


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {argv[0]} <dir>", file=sys.stderr)
        return 2
    directory = Path(argv[1])
    if not directory.is_dir():
        print(f"{directory}: not a directory", file=sys.stderr)
        return 2
    runs = load_dir(directory)
    if not runs:
        print(f"{directory}: no *.json files", file=sys.stderr)
        return 1
    print(render_tables(runs), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
