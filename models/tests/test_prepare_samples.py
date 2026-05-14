"""Tests for ``models.prepare_samples``.

Covers:
- Pure function path: shape, dtype, value range against a committed gradient.
- Byte-exact match against the committed golden ``sample.bin``.
- CLI path: ``python -m models.prepare_samples`` produces the same bytes.
- Cross-check vs Orion's reference (xfail — different source image, kept as
  a regression guard for future investigation).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import numpy as np
import pytest

from models.prepare_samples import BIN_BYTES, TENSOR_LEN, prepare_sample

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"
SAMPLE_PNG = FIXTURE_DIR / "sample.png"
SAMPLE_BIN = FIXTURE_DIR / "sample.bin"

ORION_SAMPLES_DIR = Path.home() / "Dev/orion/examples/c3ae-demo/data/samples"
ORION_REFERENCE_BIN = (
    Path.home() / "Dev/orion/examples/c3ae-demo/out/inputs/sample_test.bin"
)


def test_prepare_sample_shape_and_range() -> None:
    arr = prepare_sample(SAMPLE_PNG)
    assert arr.shape == (TENSOR_LEN,)
    assert arr.dtype == np.float64
    # The pipeline normalises to [-1, 1].
    assert arr.min() >= -1.0
    assert arr.max() <= 1.0


def test_prepare_sample_matches_committed_bytes() -> None:
    arr = prepare_sample(SAMPLE_PNG)
    actual = arr.astype("<f8").tobytes()
    expected = SAMPLE_BIN.read_bytes()
    assert len(expected) == BIN_BYTES, (
        f"committed fixture sample.bin is {len(expected)} bytes, want {BIN_BYTES} — "
        "regenerate via tests/fixtures/generate.py"
    )
    assert actual == expected, "prepare_sample output drifted from committed sample.bin"


def test_cli_round_trip(tmp_path: Path) -> None:
    out_path = tmp_path / "out.bin"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "models.prepare_samples",
            "--in",
            str(SAMPLE_PNG),
            "--out",
            str(out_path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, (
        f"CLI exit={result.returncode}\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )
    assert out_path.is_file()
    assert out_path.read_bytes() == SAMPLE_BIN.read_bytes()


@pytest.mark.xfail(
    reason=(
        "Orion's sample_test.bin was generated from a UTKFace test-set sample "
        "(torch.random_split(seed=42)), not from data/samples/*.jpg, so a "
        "byte-exact match is structurally impossible without knowing the "
        "originating image. The cross-check is kept as a regression guard for "
        "when the source-image mapping is recovered."
    ),
    strict=False,
)
def test_cross_check_orion_reference() -> None:
    """Byte-exact cross-check against Orion's reference input.

    Will fail (xfail) for two compounding reasons:
    1. The reference ``sample_test.bin`` was generated from a UTKFace
       test-split sample, not from the named ``data/samples/*.jpg`` files.
    2. PIL bicubic resample differs subtly from torch's resize convention.

    Either reason is sufficient to break byte-equality. We still run the
    comparison so a future fix-up (recovering the source image, or matching
    torch's bicubic kernel) makes the test pass cleanly.
    """
    if not ORION_SAMPLES_DIR.is_dir() or not ORION_REFERENCE_BIN.is_file():
        pytest.skip("Orion reference artifacts not present at ~/Dev/orion/...")

    jpgs = sorted(ORION_SAMPLES_DIR.glob("*.jpg"))
    if not jpgs:
        pytest.skip(f"no .jpg files in {ORION_SAMPLES_DIR}")

    arr = prepare_sample(jpgs[0])
    actual = arr.astype("<f8").tobytes()
    expected = ORION_REFERENCE_BIN.read_bytes()
    if actual != expected:
        # Surface a useful diagnostic so the xfail report tells the user
        # something they can act on.
        diff_count = sum(1 for a, b in zip(actual, expected, strict=True) if a != b)
        pytest.fail(
            f"byte mismatch vs Orion reference: {diff_count}/{len(expected)} bytes differ; "
            f"compared {jpgs[0].name} against {ORION_REFERENCE_BIN.name}"
        )
