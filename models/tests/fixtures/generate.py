"""Regenerate the committed test fixtures.

Run this manually whenever the preprocessing pipeline changes intentionally —
the committed ``sample.bin`` is the golden output and the test suite asserts
byte-equality. Determinism is load-bearing: same script invocation must
produce byte-identical ``sample.png`` and ``sample.bin``.

Usage (from repo root):

    cd models && uv run python -m tests.fixtures.generate
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import numpy.typing as npt
from PIL import Image

from models.prepare_samples import prepare_sample, write_bin

FIXTURE_DIR = Path(__file__).resolve().parent
PNG_PATH = FIXTURE_DIR / "sample.png"
BIN_PATH = FIXTURE_DIR / "sample.bin"

# Larger than 64x64 so the resize step in the pipeline has actual work to do
# (and so the bicubic kernel choice has an observable effect on the output).
GEN_SIDE = 128


def _make_gradient() -> npt.NDArray[np.uint8]:
    """Deterministic RGB gradient: ``pixel[h, w, c] = (h + w + c * 17) % 256``.

    The ``* 17`` shift on the channel axis (vs ``+ c`` per the task description)
    breaks symmetry between R / G / B so the three channels don't collapse to
    near-identical values after normalisation — useful as a sanity check that
    HWC -> CHW permutation is implemented correctly.
    """
    h_idx = np.arange(GEN_SIDE, dtype=np.int32)[:, None, None]
    w_idx = np.arange(GEN_SIDE, dtype=np.int32)[None, :, None]
    c_idx = np.arange(3, dtype=np.int32)[None, None, :]
    raw = (h_idx + w_idx + c_idx * 17) % 256
    return raw.astype(np.uint8)


def main() -> None:
    pixels = _make_gradient()
    img = Image.fromarray(pixels, mode="RGB")
    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
    # ``optimize=True`` + fixed encoder defaults: PNG is deterministic given
    # the same pixels, so the committed file is reproducible.
    img.save(PNG_PATH, format="PNG", optimize=True)

    values = prepare_sample(PNG_PATH)
    write_bin(values, BIN_PATH)
    print(f"wrote {PNG_PATH}  ({PNG_PATH.stat().st_size} bytes)")
    print(f"wrote {BIN_PATH}  ({BIN_PATH.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
