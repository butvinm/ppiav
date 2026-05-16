"""Integration test for ``bench.eval.aggregate`` on the committed fixture batch.

This is the contract test for Tasks 5-7 combined per the plan:

- Task 5 (this task): assert every section header, every message_id in MESSAGES,
  and every key name in KEYS appears in the rendered ``summary.md``.
- Task 6 (future): asserts the plain + FHE accuracy columns.
- Task 7 (future): asserts the per-image sub-steps land in the per-party table.

The fixture lives at ``bench/tests/fixtures/sample_batch/`` and was authored in
Task 4 specifically for this driver: keygen.json with per-party sub-steps, four
per-image dirs with the post-Task-2 sub-step JSONs, decoded.json with verdict
labels, and placeholder zero-byte ``.bin`` files where the catalog expects
FilePath sources.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from bench._messages import KEYS, MESSAGES
from bench.eval import aggregate

FIXTURE_SRC = Path(__file__).parent / "fixtures" / "sample_batch"


@pytest.fixture
def batch_dir(tmp_path: Path) -> Path:
    """Copy the read-only fixture into a tmp dir so aggregate can write outputs."""
    dst = tmp_path / "sample_batch"
    shutil.copytree(FIXTURE_SRC, dst)
    return dst


def _read_summary(batch_dir: Path) -> str:
    return (batch_dir / "summary.md").read_text(encoding="utf-8")


def test_aggregate_writes_summary(batch_dir: Path) -> None:
    aggregate(batch_dir)
    assert (batch_dir / "summary.md").is_file()


def test_aggregate_contains_section_headers(batch_dir: Path) -> None:
    aggregate(batch_dir)
    summary = _read_summary(batch_dir)
    # Section headers — Russian-language per project convention. Use the same
    # strings from _labels_ru.SECTION_HEADERS so a label rename here would
    # require updating both sides.
    from bench._labels_ru import SECTION_HEADERS

    assert f"## {SECTION_HEADERS['per_message_bytes']}" in summary
    assert f"## {SECTION_HEADERS['key_inventory']}" in summary
    assert f"## {SECTION_HEADERS['network_wire_time']}" in summary
    assert f"## {SECTION_HEADERS['accuracy_plain_vs_fhe']}" in summary


def test_aggregate_accuracy_section_has_plain_and_fhe_columns(batch_dir: Path) -> None:
    """The Task-6 plain-vs-FHE table must include both column headers + metric rows."""
    from bench._labels_ru import ACCURACY_METRIC_NAMES, TABLE_HEADERS

    aggregate(batch_dir)
    summary = _read_summary(batch_dir)
    assert TABLE_HEADERS["plain_column"] in summary
    assert TABLE_HEADERS["fhe_column"] in summary
    # Sanity-check that the canonical metric rows appear at least once.
    for key in ("tp", "tn", "fp", "fn", "unknown", "fpr", "fnr", "accuracy"):
        assert ACCURACY_METRIC_NAMES[key] in summary, (
            f"metric row {key!r} ({ACCURACY_METRIC_NAMES[key]!r}) missing from summary.md"
        )


def test_aggregate_per_message_section_lists_every_message_id(batch_dir: Path) -> None:
    """Every catalog Message.id must appear in summary.md (renders in the bytes table)."""
    aggregate(batch_dir)
    summary = _read_summary(batch_dir)
    for msg in MESSAGES:
        assert msg.id in summary, f"message_id {msg.id!r} missing from summary.md"


def test_aggregate_key_inventory_section_lists_every_key(batch_dir: Path) -> None:
    """Every catalog KeyEntry.name must appear in summary.md (renders in the inventory)."""
    aggregate(batch_dir)
    summary = _read_summary(batch_dir)
    for key in KEYS:
        assert key.name in summary, f"key name {key.name!r} missing from summary.md"


def test_party_step_table_lists_each_substep_with_party(batch_dir: Path) -> None:
    """Every per-image sub-step renders as its own row with its assigned party tag."""
    from bench._labels_ru import PARTY_BY_STEP, PARTY_NAMES, STEP_NAMES
    from bench._messages import PER_IMAGE_STEPS
    from bench.eval import (
        _load_keygen_run,
        _load_step_runs,
        _party_step_table_md,
    )

    img_dirs = sorted(
        (
            (int(p.name.removeprefix("img_")), p)
            for p in batch_dir.iterdir()
            if p.is_dir() and p.name.startswith("img_")
        ),
        key=lambda t: t[0],
    )
    keygen_run = _load_keygen_run(batch_dir)
    per_image = _load_step_runs(img_dirs)

    table = _party_step_table_md(keygen_run, per_image)
    for step in PER_IMAGE_STEPS:
        assert per_image.get(step), f"fixture is missing samples for sub-step {step!r}"
        label = STEP_NAMES[step]
        party = PARTY_NAMES[PARTY_BY_STEP[step]]
        assert label in table, f"sub-step label {label!r} missing from per-party table"
        # Confirm the label appears on a row alongside its party tag — guards
        # against the label leaking onto the wrong row.
        for line in table.splitlines():
            if label in line:
                assert party in line, (
                    f"sub-step {step!r} row does not carry its party tag {party!r}: {line!r}"
                )
                break


def test_key_inventory_renders_on_wire_flags_correctly(batch_dir: Path) -> None:
    """on_wire flag + location strings render exactly per the labels module."""
    from bench._labels_ru import KEY_LOCATION_NAMES, TABLE_HEADERS
    from bench.eval import _key_inventory_md, _key_inventory_rows

    rows = _key_inventory_rows(batch_dir, {})
    table = _key_inventory_md(rows)

    def _row_for(key_name: str) -> str:
        for line in table.splitlines():
            cells = [c.strip() for c in line.strip("|").split("|")]
            if cells and cells[0] == key_name:
                return line
        raise AssertionError(f"key {key_name!r} missing from inventory table")

    # gks^master is on the wire as the catalog aggregate — must carry the yes label.
    assert TABLE_HEADERS["on_wire_yes"] in _row_for("gks^master")
    # gks^master_a (agent's master share) is local-only — must carry the no label.
    assert TABLE_HEADERS["on_wire_no"] in _row_for("gks^master_a")
    # sk_c is client-local — its location must carry the client-local label.
    assert KEY_LOCATION_NAMES["client_local"] in _row_for("sk_c")


def test_network_table_bandwidth_arithmetic() -> None:
    """Bandwidth column must compute seconds = bytes * 8 / (mbps * 1e6).

    Synthesizes a single row (1 MB, 8 Mbps) and asserts the rendered cell is
    "1.00 s" — a regression that swapped bits<->bytes (factor of 8) would land
    on "0.13 s" or "8.00 s" and fail loudly.
    """
    from bench.eval import _network_table_md

    rows = [("ProbeMsg", "проба", "client", "agent", 1_000_000)]
    table = _network_table_md(rows)
    # _BANDWIDTHS_MBPS is (1, 10, 100); 10 Mbps -> 1e6 / 1.25e6 = 0.80s.
    # We synthesize for 1 Mbps which yields 1e6 / 1.25e5 = 8.00s.
    # The header is "t @ 1 Mbps", so the value lands on the same row.
    line = next(line for line in table.splitlines() if "ProbeMsg" in line)
    cells = [c.strip() for c in line.strip("|").split("|")]
    # cells = [id, bytes, t@1Mbps, t@10Mbps, t@100Mbps]
    assert cells[1] == "1000000"
    assert cells[2] == "8.00 s"
    assert cells[3] == "800.0 ms"
    assert cells[4] == "80.0 ms"


def test_load_step_runs_rejects_unknown_sample_name(tmp_path: Path) -> None:
    """An unknown Sample.name in a per-image JSON must surface as a loud error.

    Guards against silent regression where a stale single-block ``Sample.name
    == "infer"`` from a partially-regenerated batch lands under a non-catalog
    bucket key and disappears from every downstream table.
    """
    from bench.eval import _load_step_runs

    img_dir = tmp_path / "img_0"
    img_dir.mkdir()
    # Write the five per-stage files. Four are valid; infer.json carries the
    # legacy single-block "infer" name (not in PER_IMAGE_STEPS post-redesign).
    _write_run(img_dir / "encrypt.json", "encrypt", ["encrypt"])
    _write_run(img_dir / "mac.json", "mac", ["mac.derive_auth_keys"])
    _write_run(
        img_dir / "partial-decrypt.json", "partial-decrypt", ["partial-decrypt"]
    )
    _write_run(img_dir / "finalize.json", "finalize", ["finalize.final_decrypt"])
    _write_run(img_dir / "infer.json", "infer", ["infer"])
    with pytest.raises(ValueError, match="unknown sample name"):
        _load_step_runs([(0, img_dir)])


def _write_run(path: Path, run_name: str, sample_names: list[str]) -> None:
    """Helper: write a bench.Run JSON shell with the given sample names.

    Mirrors the on-disk schema produced by ``internal/bench`` so ``load_run``
    can parse it. Required envelope fields default to neutral values.
    """
    import json

    base = {
        "name": run_name,
        "phase": "phase2",
        "started": "2026-05-16T12:00:00Z",
        "go_version": "go1.23.0",
        "goos": "linux",
        "goarch": "amd64",
        "num_cpu": 1,
        "samples": [
            {
                "name": sample_name,
                "iter": 0,
                "wall": 0,
                "heap_alloc": 0,
                "heap_inuse": 0,
                "sys": 0,
                "alloc_delta": 0,
                "num_gc": 0,
                "pause_ns": 0,
                "vm_hwm": 0,
                "bytes": 0,
                "pre_vm_hwm": 0,
            }
            for sample_name in sample_names
        ],
        "metadata": {},
    }
    path.write_text(json.dumps(base), encoding="utf-8")


