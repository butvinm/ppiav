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


def test_aggregate_writes_bytes_cache(batch_dir: Path) -> None:
    """First aggregate run writes bytes.json with catalog-keyed entries."""
    import json

    aggregate(batch_dir)
    cache = batch_dir / "bytes.json"
    assert cache.is_file()
    with cache.open("r", encoding="utf-8") as f:
        data = json.load(f)
    assert isinstance(data, list)
    assert data, "bytes.json should not be empty after a successful aggregate"
    # New schema sentinel — the row carries message_id, not the old "name" field.
    assert "message_id" in data[0]
    assert "name" not in data[0]


def test_aggregate_drops_old_shape_cache(batch_dir: Path) -> None:
    """An existing bytes.json with the old {name, bytes} shape must be deleted.

    This exercises the no-migration cache-shape check: if the on-disk cache
    predates Task 5, we drop it rather than carrying compat code.
    """
    import json

    cache = batch_dir / "bytes.json"
    # Strip every .bin so the resolver has nothing fresh to write; the old
    # cache would otherwise be overwritten before the shape check runs.
    for path in batch_dir.rglob("*.bin"):
        path.unlink()
    cache.write_text(
        json.dumps([{"name": "keys/legacy.bin", "bytes": 999}]),
        encoding="utf-8",
    )

    aggregate(batch_dir)

    # Cache file should have been removed by the shape check (no fresh writes
    # this round because every .bin is gone and Sample.Bytes is the only
    # remaining real source — still some SampleBytes resolve, so file may be
    # re-written in NEW shape). Either it's gone OR rewritten in new shape.
    if cache.is_file():
        with cache.open("r", encoding="utf-8") as f:
            data = json.load(f)
        assert "message_id" in data[0], "bytes.json should not retain the legacy shape"
