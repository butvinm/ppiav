"""Tests for bench.load: schema parsing + dir scanning."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bench.load import load_dir, load_run

FIXTURE = Path(__file__).parent / "fixtures" / "sample_run.json"


def test_load_run_parses_all_fields() -> None:
    run = load_run(FIXTURE)
    assert run.name == "e2e"
    assert run.phase == "phase1"
    assert run.go_version == "go1.23.0"
    assert run.goos == "linux"
    assert run.goarch == "amd64"
    assert run.num_cpu == 8
    assert run.metadata["accepts"] == 2
    assert len(run.samples) == 3
    assert run.source == FIXTURE


def test_load_run_sample_fields() -> None:
    run = load_run(FIXTURE)
    s0 = run.samples[0]
    assert s0.name == "open"
    assert s0.iter == 0
    assert s0.wall == 1_500_000
    assert s0.heap_alloc == 12_345_678
    assert s0.heap_inuse == 16_777_216
    assert s0.sys == 67_108_864
    assert s0.alloc_delta == 8192
    assert s0.num_gc == 0
    assert s0.pause_ns == 0
    assert s0.vm_hwm == 134_217_728
    assert s0.bytes == 0


def test_sample_wall_ms_and_heap_mib_derived() -> None:
    run = load_run(FIXTURE)
    s0 = run.samples[0]
    assert s0.wall_ms == pytest.approx(1.5)
    assert s0.heap_delta_mib == pytest.approx(16.0)


def test_sample_pre_vm_hwm_defaults_zero_when_absent() -> None:
    """Old phase1 JSONs without `pre_vm_hwm` must still parse with default 0."""
    run = load_run(FIXTURE)
    s0 = run.samples[0]
    assert s0.pre_vm_hwm == 0
    # delta_rss_mib falls back to vm_hwm in MiB when pre_vm_hwm is absent.
    assert s0.delta_rss_mib == pytest.approx(s0.vm_hwm / (1024.0 * 1024.0))


def test_sample_pre_vm_hwm_roundtrip(tmp_path: Path) -> None:
    """New artifact-pipeline JSONs carry `pre_vm_hwm`; loader must round-trip it."""
    raw = json.loads(FIXTURE.read_text())
    # Stamp a realistic pre_vm_hwm: smaller than vm_hwm by ~32 MiB.
    raw["samples"][0]["pre_vm_hwm"] = 100_663_296  # 96 MiB
    raw["samples"][0]["vm_hwm"] = 134_217_728  # 128 MiB
    fp = tmp_path / "with_pre_hwm.json"
    fp.write_text(json.dumps(raw))
    run = load_run(fp)
    s0 = run.samples[0]
    assert s0.pre_vm_hwm == 100_663_296
    assert s0.vm_hwm == 134_217_728
    assert s0.delta_rss_mib == pytest.approx(32.0)


def test_sample_delta_rss_mib_clamps_at_zero(tmp_path: Path) -> None:
    """If vm_hwm < pre_vm_hwm somehow lands on disk, clamp at 0 not negative."""
    raw = json.loads(FIXTURE.read_text())
    raw["samples"][0]["pre_vm_hwm"] = raw["samples"][0]["vm_hwm"] + 1
    fp = tmp_path / "neg_delta.json"
    fp.write_text(json.dumps(raw))
    run = load_run(fp)
    assert run.samples[0].delta_rss_mib == 0.0


def test_load_run_rejects_empty_samples(tmp_path: Path) -> None:
    bad = tmp_path / "empty.json"
    raw = json.loads(FIXTURE.read_text())
    raw["samples"] = []
    bad.write_text(json.dumps(raw))
    with pytest.raises(ValueError, match="no samples"):
        load_run(bad)


def test_load_dir_returns_sorted_runs(tmp_path: Path) -> None:
    # Copy fixture twice with deterministic names.
    a = tmp_path / "a.json"
    b = tmp_path / "b.json"
    a.write_text(FIXTURE.read_text())
    b.write_text(FIXTURE.read_text())
    (tmp_path / "ignored.txt").write_text("not json")
    runs = load_dir(tmp_path)
    assert [r.source.name for r in runs if r.source is not None] == ["a.json", "b.json"]


def test_load_dir_empty(tmp_path: Path) -> None:
    assert load_dir(tmp_path) == []
