"""Tests for the plain-vs-FHE accuracy comparison helpers in ``bench.eval``.

The fixture batch at ``bench/tests/fixtures/sample_batch/`` has four images
covering both labels and both ``ref_logit`` signs, with FHE verdicts aligned
to the cleartext side. We assert both classifiers reproduce the expected
confusion matrix on the fixture, and that the rendered comparison table
carries both columns + every metric row.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from bench._labels_ru import ACCURACY_METRIC_NAMES, TABLE_HEADERS
from bench.eval import _accuracy_compare_table_md, _classify, _classify_plain

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "sample_batch"


def _load_manifest_by_idx() -> dict[int, dict[str, Any]]:
    with (FIXTURE_DIR / "eval_inputs.json").open("r", encoding="utf-8") as f:
        data: dict[str, Any] = json.load(f)
    by_idx: dict[int, dict[str, Any]] = {}
    for entry in data.get("images", []):
        by_idx[int(entry["idx"])] = entry
    return by_idx


def _load_fhe_verdicts(
    manifest_by_idx: dict[int, dict[str, Any]],
) -> tuple[list[str], list[int]]:
    verdicts: list[str] = []
    labels: list[int] = []
    for idx in sorted(manifest_by_idx):
        with (FIXTURE_DIR / f"img_{idx}" / "decoded.json").open("r", encoding="utf-8") as f:
            decoded = json.load(f)
        verdicts.append(str(decoded["verdict"]))
        labels.append(int(manifest_by_idx[idx]["label"]))
    return verdicts, labels


def test_classify_plain_on_fixture() -> None:
    """Plaintext classifier reads ``ref_logit`` sign for accept/reject.

    The fixture's four images split 2 positives (idx 0, 2: ``ref_logit > 0``,
    label=1) and 2 negatives (idx 1, 3: ``ref_logit < 0``, label=0). All four
    align, so plain gives 2 TP, 2 TN, 0 FP, 0 FN, 0 unknown, accuracy=1.0.
    """
    manifest = _load_manifest_by_idx()
    stats = _classify_plain(manifest)
    assert stats["tp"] == 2
    assert stats["tn"] == 2
    assert stats["fp"] == 0
    assert stats["fn"] == 0
    assert stats["unknown"] == 0
    assert stats["fpr"] == 0.0
    assert stats["fnr"] == 0.0
    assert stats["accuracy"] == 1.0


def test_classify_fhe_on_fixture() -> None:
    """FHE classifier reads ``verdict`` from each ``decoded.json``.

    The fixture's FHE verdicts mirror the cleartext signs (no Auth fail), so
    the confusion matrix matches the plain side exactly.
    """
    manifest = _load_manifest_by_idx()
    verdicts, labels = _load_fhe_verdicts(manifest)
    stats = _classify(verdicts, labels)
    assert stats["tp"] == 2
    assert stats["tn"] == 2
    assert stats["fp"] == 0
    assert stats["fn"] == 0
    assert stats["unknown"] == 0
    assert stats["accuracy"] == 1.0


def test_accuracy_compare_table_contains_both_columns_and_all_rows() -> None:
    """Rendered table must carry both column headers + each metric row."""
    manifest = _load_manifest_by_idx()
    plain_stats = _classify_plain(manifest)
    verdicts, labels = _load_fhe_verdicts(manifest)
    fhe_stats = _classify(verdicts, labels)

    table = _accuracy_compare_table_md(fhe_stats, plain_stats, len(manifest))

    # Both column headers in the header row.
    assert TABLE_HEADERS["plain_column"] in table
    assert TABLE_HEADERS["fhe_column"] in table
    assert TABLE_HEADERS["metric"] in table

    # Every metric row label is present.
    for key in ("samples", "tp", "tn", "fp", "fn", "unknown", "fpr", "fnr", "accuracy"):
        label = ACCURACY_METRIC_NAMES[key]
        assert label in table, f"missing metric row {key!r} ({label})"


def test_classify_plain_empty_manifest() -> None:
    """Empty manifest must produce all-zero stats without a divide-by-zero."""
    stats = _classify_plain({})
    assert stats["tp"] == 0
    assert stats["tn"] == 0
    assert stats["fp"] == 0
    assert stats["fn"] == 0
    assert stats["unknown"] == 0
    assert stats["fpr"] == 0.0
    assert stats["fnr"] == 0.0
    assert stats["accuracy"] == 0.0


def test_classify_plain_ref_logit_zero_is_reject() -> None:
    """ref_logit == 0 must classify as reject (verdict rule is strict >0).

    The fixture uses one entry: ref_logit=0.0, label=0 -> verdict=reject ->
    a single true-negative.
    """
    manifest: dict[int, dict[str, Any]] = {0: {"label": 0, "ref_logit": 0.0}}
    stats = _classify_plain(manifest)
    assert stats["tn"] == 1
    assert stats["tp"] == 0
    assert stats["fp"] == 0
    assert stats["fn"] == 0


def test_classify_plain_missing_ref_logit_defaults_to_reject() -> None:
    """A manifest entry without ref_logit falls through to the .get default (0.0).

    Documents the current strict contract: missing key -> default reject. If
    upstream tightens this to strict-required, this test goes red and the
    contract must be re-decided explicitly.
    """
    manifest: dict[int, dict[str, Any]] = {0: {"label": 0}}
    stats = _classify_plain(manifest)
    assert stats["tn"] == 1


def test_accuracy_compare_table_plain_unknown_is_zero() -> None:
    """Plaintext column never reports ``unknown`` — no Auth gate exists there.

    Synthesize an FHE-side stats dict with a non-zero unknown to verify the
    table renders both columns independently (the plain ``unknown`` row stays
    0 regardless of the FHE side).
    """
    plain_stats: dict[str, int | float] = {
        "tp": 1,
        "tn": 1,
        "fp": 0,
        "fn": 0,
        "unknown": 0,
        "fpr": 0.0,
        "fnr": 0.0,
        "accuracy": 1.0,
    }
    fhe_stats: dict[str, int | float] = {
        "tp": 1,
        "tn": 0,
        "fp": 0,
        "fn": 0,
        "unknown": 1,
        "fpr": 0.0,
        "fnr": 0.0,
        "accuracy": 1.0,
    }
    table = _accuracy_compare_table_md(fhe_stats, plain_stats, 2)
    # Plain unknown row must render 0 on the plain side.
    unknown_label = ACCURACY_METRIC_NAMES["unknown"]
    line = next(line for line in table.splitlines() if line.startswith(f"| {unknown_label} "))
    cells = [c.strip() for c in line.strip("|").split("|")]
    # cells = [metric_label, plain_col, fhe_col]
    assert cells[1] == "0"
    assert cells[2] == "1"
