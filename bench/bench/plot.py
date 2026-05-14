"""Per-stage PNG bar plots for bench JSON output.

Usage: `python -m bench.plot <dir>` writes <dir>/plots/<stage>.png — one
PNG per Sample.name, x = concatenated sample index, y = wall ms.
"""

from __future__ import annotations

import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # headless

import matplotlib.pyplot as plt

from bench.load import Run, Sample, load_dir


def _collect_by_stage(runs: list[Run]) -> dict[str, list[Sample]]:
    out: dict[str, list[Sample]] = {}
    for run in runs:
        for s in run.samples:
            out.setdefault(s.name, []).append(s)
    return out


def write_plots(runs: list[Run], out_dir: Path) -> list[Path]:
    """Write one PNG per stage. Returns the list of paths written."""
    by_stage = _collect_by_stage(runs)
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for stage, samples in by_stage.items():
        walls_ms = [s.wall_ms for s in samples]
        xs = list(range(len(walls_ms)))
        fig, ax = plt.subplots(figsize=(8, 4))
        ax.bar(xs, walls_ms)
        ax.set_title(f"{stage} — wall time per sample")
        ax.set_xlabel("sample index")
        ax.set_ylabel("wall (ms)")
        path = out_dir / f"{stage}.png"
        fig.tight_layout()
        fig.savefig(path, dpi=120)
        plt.close(fig)
        written.append(path)
    return written


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
    out_dir = directory / "plots"
    paths = write_plots(runs, out_dir)
    for p in paths:
        print(p)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
