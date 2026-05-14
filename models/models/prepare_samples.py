"""Image preprocessing — turn an image file into the 12288-float64 tensor
that ``internal/vclient`` encrypts.

The 5-step pipeline is the cross-language contract spelled out in
``docs/DESIGN.md §internal/vclient``:

1. Decode and convert to RGB (drop alpha).
2. Resize to 64x64 using bicubic resampling.
3. Cast to float, divide by 255.0 (pixels now in [0, 1]).
4. Apply ``(x - 0.5) / 0.5`` per channel (now in [-1, 1]).
5. HWC -> CHW, flatten row-major to ``3 * 64 * 64 = 12288`` float64 values.

Output bytes are little-endian float64 = 12288 * 8 = 98304 bytes.

We follow Orion's reference (``~/Dev/orion/examples/c3ae-demo/models/utkface.py``)
and run steps 3-4 in float32, then cast to float64 only at write time, so the
output bytes line up with Orion's reference where possible. The bicubic kernel
in PIL is documented to differ subtly from torch / OpenCV — drift between
reference inputs is therefore expected and is the reason the Orion byte-exact
cross-check is an xfail regression guard, not a hard requirement.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np
import numpy.typing as npt
from PIL import Image

IMAGE_SIDE = 64
CHANNELS = 3
TENSOR_LEN = CHANNELS * IMAGE_SIDE * IMAGE_SIDE  # 12288
BIN_BYTES = TENSOR_LEN * 8  # float64 = 8 bytes


def prepare_sample(image_path: Path) -> npt.NDArray[np.float64]:
    """Run the 5-step pipeline on a single image file.

    Returns a contiguous 1-D ``float64`` array of length ``TENSOR_LEN``.
    Raises ``FileNotFoundError`` if the input doesn't exist; ``PIL`` errors
    propagate for malformed images.
    """
    with Image.open(image_path) as img:
        # Step 1 + 2: RGB + bicubic resize. ``Image.Resampling.BICUBIC`` is the
        # explicit name introduced in Pillow 9.1; pinning it here means the
        # behaviour is locked even if PIL changes its ``resize`` default again.
        img_rgb = img.convert("RGB").resize(
            (IMAGE_SIDE, IMAGE_SIDE),
            resample=Image.Resampling.BICUBIC,
        )
        # Step 3 + 4: divide by 255, then ``(x - 0.5) / 0.5``. Stay in float32
        # to match Orion's reference rounding before the final cast.
        arr32: npt.NDArray[np.float32] = np.asarray(img_rgb, dtype=np.float32) / 255.0
        arr32 = (arr32 - 0.5) / 0.5
        # Step 5: HWC -> CHW (axes (H, W, C) -> (C, H, W)), then flatten.
        # ``np.transpose`` is the canonical permute; ``.copy()`` forces a
        # contiguous buffer so the subsequent ``reshape`` doesn't surprise us.
        chw32 = np.transpose(arr32, (2, 0, 1)).copy()
        flat = chw32.reshape(-1).astype(np.float64)
        if flat.shape != (TENSOR_LEN,):
            raise RuntimeError(
                f"unexpected output shape {flat.shape}, want ({TENSOR_LEN},) — bug?"
            )
        return flat


def write_bin(values: npt.NDArray[np.float64], out_path: Path) -> None:
    """Write ``values`` as little-endian float64 to ``out_path``.

    Forces ``<f8`` dtype so the result is portable across architectures even
    though numpy's default on x86_64 already happens to be little-endian.
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)
    values.astype("<f8").tofile(out_path)
    actual = out_path.stat().st_size
    if actual != BIN_BYTES:
        raise RuntimeError(
            f"wrote {actual} bytes to {out_path}, want {BIN_BYTES} — disk full or partial write?"
        )


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Preprocess an image into a 12288-float64 .bin for internal/vclient.",
    )
    parser.add_argument(
        "--in",
        dest="input_path",
        type=Path,
        required=True,
        help="Path to the input image (any format Pillow understands).",
    )
    parser.add_argument(
        "--out",
        dest="output_path",
        type=Path,
        required=True,
        help="Path to write the .bin file (little-endian float64, 12288 values).",
    )
    args = parser.parse_args(argv)

    if not args.input_path.is_file():
        print(f"error: {args.input_path} is not a file", file=sys.stderr)
        return 2

    values = prepare_sample(args.input_path)
    write_bin(values, args.output_path)
    print(
        f"wrote {args.output_path}  "
        f"({BIN_BYTES} bytes, range [{values.min():.4f}, {values.max():.4f}])"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
