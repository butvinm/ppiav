"""Load bench JSON files written by internal/bench (Go).

The on-disk schema mirrors `internal/bench/bench.go` Sample / Run structs.
Field names use the Go `json` struct tags (lowercased with underscores).
`wall` is reported as nanoseconds (Go `time.Duration` JSON-encodes as int64 ns).
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Sample:
    name: str
    iter: int
    wall: int  # nanoseconds
    heap_alloc: int
    heap_inuse: int
    sys: int
    alloc_delta: int
    num_gc: int
    pause_ns: int
    vm_hwm: int
    bytes: int
    pre_vm_hwm: int = 0  # default 0 for backward-compat with older JSONs

    @property
    def wall_ms(self) -> float:
        return self.wall / 1_000_000.0

    @property
    def heap_delta_mib(self) -> float:
        """Heap-inuse reported alongside this sample, in MiB.

        The Go harness reports the post-call HeapInuse — there is no separate
        before-snapshot in the wire shape — so this is best read as the
        steady-state heap footprint after the operation, not a delta.
        """
        return self.heap_inuse / (1024.0 * 1024.0)

    @property
    def delta_rss_mib(self) -> float:
        """RSS attributable to this op vs. startup baseline, in MiB.

        Older JSONs without `pre_vm_hwm` default to 0; clamped at 0 to
        avoid negative values when vm_hwm < pre_vm_hwm is somehow recorded.
        """
        return max(0, self.vm_hwm - self.pre_vm_hwm) / (1024.0 * 1024.0)


@dataclass
class Run:
    name: str
    phase: str
    started: str
    go_version: str
    goos: str
    goarch: str
    num_cpu: int
    samples: list[Sample]
    metadata: dict[str, Any] = field(default_factory=dict)
    source: Path | None = None


def _sample_from_dict(d: dict[str, Any]) -> Sample:
    return Sample(
        name=str(d["name"]),
        iter=int(d["iter"]),
        wall=int(d["wall"]),
        heap_alloc=int(d["heap_alloc"]),
        heap_inuse=int(d["heap_inuse"]),
        sys=int(d["sys"]),
        alloc_delta=int(d["alloc_delta"]),
        num_gc=int(d["num_gc"]),
        pause_ns=int(d["pause_ns"]),
        vm_hwm=int(d["vm_hwm"]),
        bytes=int(d["bytes"]),
        pre_vm_hwm=int(d.get("pre_vm_hwm", 0)),
    )


def load_run(path: Path) -> Run:
    """Parse a single bench JSON file. Raises ValueError on empty samples."""
    with path.open("r", encoding="utf-8") as f:
        raw: dict[str, Any] = json.load(f)
    samples_raw = raw.get("samples") or []
    if not samples_raw:
        raise ValueError(f"{path}: run has no samples")
    samples = [_sample_from_dict(s) for s in samples_raw]
    metadata_raw = raw.get("metadata")
    metadata: dict[str, Any] = dict(metadata_raw) if metadata_raw else {}
    return Run(
        name=str(raw["name"]),
        phase=str(raw["phase"]),
        started=str(raw["started"]),
        go_version=str(raw["go_version"]),
        goos=str(raw["goos"]),
        goarch=str(raw["goarch"]),
        num_cpu=int(raw["num_cpu"]),
        samples=samples,
        metadata=metadata,
        source=path,
    )


def load_dir(directory: Path) -> list[Run]:
    """Load every *.json in `directory`, sorted by filename for determinism."""
    paths = sorted(p for p in directory.glob("*.json") if p.is_file())
    return [load_run(p) for p in paths]


def iter_per_image_run_jsons(img_dir: Path) -> Iterator[Path]:
    """Yield bench Run JSONs in an `img_<idx>/` dir, skipping decoded.json.

    `decoded.json` is the verdict + noise payload, not a bench.Run — every
    caller iterating per-image JSONs must skip it.
    """
    for json_path in sorted(img_dir.glob("*.json")):
        if json_path.name == "decoded.json":
            continue
        yield json_path
