"""Unit tests for bench.eval pure-Python helpers.

We only test the deterministic post-processing helpers (`_classify`,
`_noise_stats`, `_snr_per_image`); the subprocess-driven `_run_step` /
`run_pipeline` paths are exercised end-to-end on the VPS and have no useful
unit-test surface.
"""

from __future__ import annotations

import math
from pathlib import Path

import pytest

from bench.eval import _classify, _noise_stats, _snr_per_image


def test_classify_all_correct() -> None:
    stats = _classify(["accept", "reject", "accept", "reject"], [1, 0, 1, 0])
    assert stats["tp"] == 2
    assert stats["tn"] == 2
    assert stats["fp"] == 0
    assert stats["fn"] == 0
    assert stats["unknown"] == 0
    assert stats["fpr"] == 0.0
    assert stats["fnr"] == 0.0
    assert stats["accuracy"] == 1.0


def test_classify_all_wrong() -> None:
    # Label=1 + predict=reject => fn; label=0 + predict=accept => fp.
    stats = _classify(["reject", "accept", "reject", "accept"], [1, 0, 1, 0])
    assert stats["tp"] == 0
    assert stats["tn"] == 0
    assert stats["fp"] == 2
    assert stats["fn"] == 2
    assert stats["fpr"] == 1.0
    assert stats["fnr"] == 1.0
    assert stats["accuracy"] == 0.0


def test_classify_unknown_excluded_from_rates() -> None:
    stats = _classify(["unknown", "accept", "reject"], [1, 1, 0])
    assert stats["unknown"] == 1
    assert stats["tp"] == 1
    assert stats["tn"] == 1
    # Decided=2, accuracy over decided only.
    assert stats["accuracy"] == 1.0


def test_classify_empty_division_guards() -> None:
    # No positives -> FNR must default to 0.0 not raise ZeroDivisionError.
    stats = _classify(["reject"], [0])
    assert stats["fnr"] == 0.0
    # No negatives -> FPR must default to 0.0.
    stats = _classify(["accept"], [1])
    assert stats["fpr"] == 0.0


def test_classify_length_mismatch_raises() -> None:
    with pytest.raises(ValueError, match="length mismatch"):
        _classify(["accept", "reject"], [1])


def test_noise_stats_empty() -> None:
    s = _noise_stats([])
    assert s == {"n": 0, "mean": 0.0, "min": 0.0, "max": 0.0, "std": 0.0}


def test_noise_stats_basic() -> None:
    s = _noise_stats([-1.0, 0.0, 1.0])
    assert s["n"] == 3
    assert s["mean"] == pytest.approx(0.0)
    assert s["min"] == -1.0
    assert s["max"] == 1.0
    # pstdev of {-1, 0, 1} = sqrt(2/3).
    assert s["std"] == pytest.approx(math.sqrt(2.0 / 3.0))


def test_snr_per_image_handles_zero_std() -> None:
    # Single-element noise -> std==0 -> SNR sentinel = inf.
    img_dirs: list[tuple[int, Path]] = [(0, Path("/tmp/img_0"))]
    decoded = {0: {"ref_logit": 0.5, "noise_per_slot": [0.01]}}
    snr = _snr_per_image(img_dirs, decoded)
    assert len(snr) == 1
    idx, snr_v, ref_abs = snr[0]
    assert idx == 0
    assert math.isinf(snr_v)
    assert ref_abs == pytest.approx(0.5)


def test_snr_per_image_skips_missing_or_empty() -> None:
    img_dirs: list[tuple[int, Path]] = [(0, Path("/tmp/img_0")), (1, Path("/tmp/img_1"))]
    decoded = {0: {"ref_logit": 0.5, "noise_per_slot": []}}  # empty noise -> skipped
    snr = _snr_per_image(img_dirs, decoded)
    assert snr == []


def test_snr_per_image_computes_ratio() -> None:
    img_dirs: list[tuple[int, Path]] = [(0, Path("/tmp/img_0"))]
    decoded = {0: {"ref_logit": 1.0, "noise_per_slot": [-1.0, 1.0]}}
    snr = _snr_per_image(img_dirs, decoded)
    # pstdev of [-1, 1] = 1.0 -> SNR = 1/1 = 1.0.
    assert snr[0][1] == pytest.approx(1.0)
