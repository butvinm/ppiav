#!/usr/bin/env python3
"""Prepare a UTKFace test sample as a raw float64 blob for the FHE bench.

Reproduces the 70/15/15 train/val/test split with the same ``manual_seed(42)``
as ``models/train.py`` (and the original ``examples/c3ae-demo/train.py``) so
the test indices match exactly across runs and across cleartext eval and the
FHE bench.

Usage (from ``models/``):

    # Single sample by test-set index
    python -m models.prepare_samples --idx 0

    # First 3 boundary-band samples (16 <= age <= 20) in test-iteration order
    python -m models.prepare_samples --boundary-band

    # Stratified batch of 10 samples (5 minors / 5 adults) with cleartext
    # FHE-quad reference logits for the eval pipeline
    python -m models.prepare_samples --batch 10 --stratified --with-ref-logit \
        --out-manifest out/eval_inputs.json

Outputs (single / boundary-band):
    out/inputs/sample_<idx>.bin   raw little-endian float64, 12288 values
                                  (3 * 64 * 64), normalized to [-1, 1]
    out/inputs/ground_truth.csv   header: idx,age,is_adult

Outputs (batch):
    out/inputs/sample_<idx>.bin   one per selected test-set position
    out/inputs/ground_truth.csv   merged as in single-sample mode
    <out-manifest>                JSON manifest consumed by bench.eval
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import numpy as np
import torch
from torch.utils.data import Subset

from models.c3ae_fhe import C3AE as C3AE_FHE
from models.utkface import build_test_split

if TYPE_CHECKING:
    from collections.abc import Sequence

BOUNDARY_BAND_TARGET = 3


def select_indices(test_set: Subset, args: argparse.Namespace) -> list[int]:
    """Return the list of test-set positions to dump.

    For ``--idx N`` returns ``[N]``. For ``--boundary-band`` returns the first
    ``BOUNDARY_BAND_TARGET`` positions whose age is in ``[16, 20]`` in
    iteration order.

    Behavior on insufficient samples in ``--boundary-band``:
      - 0 samples found  -> raise (the original strict failure mode)
      - 1 or 2 samples   -> emit a clear ``[warn]`` to stderr and return the
        partial list. Downstream tooling expects exactly ``BOUNDARY_BAND_TARGET``
        samples, so a partial result is operator-visible -- but we don't refuse
        outright because tiny synthetic datasets (e.g. CI fixtures) may
        legitimately have fewer than 3 samples in the band.
    """
    if args.idx is not None:
        if not (0 <= args.idx < len(test_set)):
            raise ValueError(f"--idx {args.idx} out of range for test set of size {len(test_set)}")
        return [args.idx]

    # boundary band: first BOUNDARY_BAND_TARGET samples with 16 <= age <= 20
    picked: list[int] = []
    for i in range(len(test_set)):
        _, _, age = test_set[i]
        if 16 <= int(age) <= 20:
            picked.append(i)
            if len(picked) >= BOUNDARY_BAND_TARGET:
                break
    if not picked:
        raise RuntimeError(
            "No samples with 16 <= age <= 20 found in test set; cannot satisfy --boundary-band."
        )
    if len(picked) < BOUNDARY_BAND_TARGET:
        print(
            f"[warn] --boundary-band requested {BOUNDARY_BAND_TARGET} samples but only "
            f"{len(picked)} found in [16, 20] (test set size {len(test_set)}); "
            f"writing the partial result. Downstream may expect "
            f"exactly {BOUNDARY_BAND_TARGET} samples -- verify before running the FHE pipeline.",
            file=sys.stderr,
        )
    return picked


def select_stratified_indices(test_set: Subset, batch: int) -> list[int]:
    """Pick ``batch`` test-set positions with a 50/50 minor/adult split.

    Walks the test set in iteration order, collects the first ``batch // 2``
    positions with ``is_adult == 0`` and the first ``batch // 2`` with
    ``is_adult == 1``, then returns the concatenated list in ascending
    iteration order. Raises if either class is exhausted before the half-quota
    is hit -- downstream eval assumes an exact 50/50 split.
    """
    if batch < 2 or batch % 2 != 0:
        raise ValueError(f"--batch must be an even integer >= 2 (got {batch})")
    per_class = batch // 2
    minors: list[int] = []
    adults: list[int] = []
    for i in range(len(test_set)):
        _, target, _ = test_set[i]
        is_adult = int(float(target.item()) >= 0.5)
        if is_adult == 0 and len(minors) < per_class:
            minors.append(i)
        elif is_adult == 1 and len(adults) < per_class:
            adults.append(i)
        if len(minors) >= per_class and len(adults) >= per_class:
            break
    if len(minors) < per_class or len(adults) < per_class:
        raise RuntimeError(
            f"--stratified --batch {batch}: test set exhausted before quota met "
            f"(minors={len(minors)}/{per_class}, adults={len(adults)}/{per_class})"
        )
    return sorted(minors + adults)


def dump_sample(test_set: Subset, idx: int, out_dir: Path) -> tuple[int, int]:
    """Dump test-set position ``idx`` as a raw float64 blob.

    Returns ``(age, is_adult)`` for ground-truth CSV bookkeeping.

    The image tensor is shape ``(3, 64, 64)`` already normalized to ``[-1, 1]``.
    We flatten to ``12288`` values and write little-endian ``float64`` (8 bytes
    each = 98304 bytes total).

    float64 is chosen (over float32) because Lattigo's CKKS encoder accepts
    ``[]float64`` natively. Writing float64 here avoids an extra cast in the
    Go bench when reading the file.
    """
    img, target, age = test_set[idx]
    arr = img.detach().cpu().numpy().astype(np.float64).reshape(-1)
    if arr.shape != (12288,):
        raise RuntimeError(f"unexpected sample shape {arr.shape}, want (12288,)")

    out_dir.mkdir(parents=True, exist_ok=True)
    bin_path = out_dir / f"sample_{idx}.bin"
    # ``tobytes`` on a contiguous little-endian float64 array writes exactly
    # 8 * 12288 = 98304 bytes. ``numpy`` is little-endian on x86_64 Linux.
    arr.astype("<f8").tofile(bin_path)

    is_adult = int(float(target.item()) >= 0.5)
    return int(age), is_adult


def write_ground_truth(rows: list[tuple[int, int, int]], out_dir: Path) -> Path:
    """Write/merge ``ground_truth.csv``.

    Idempotency policy: read any existing rows, merge with the rows produced
    in this invocation (keyed by ``idx``, current invocation wins on collision),
    write the deduplicated, idx-sorted result back. This way re-running with
    the same flags is a no-op, and re-running with new indices accumulates.
    """
    csv_path = out_dir / "ground_truth.csv"
    merged: dict[int, tuple[int, int]] = {}

    if csv_path.exists():
        with csv_path.open("r", newline="") as f:
            reader = csv.DictReader(f)
            for r in reader:
                try:
                    merged[int(r["idx"])] = (int(r["age"]), int(r["is_adult"]))
                except (KeyError, ValueError):
                    continue

    for idx, age, is_adult in rows:
        merged[idx] = (age, is_adult)

    out_dir.mkdir(parents=True, exist_ok=True)
    with csv_path.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["idx", "age", "is_adult"])
        for idx in sorted(merged):
            age, is_adult = merged[idx]
            writer.writerow([idx, age, is_adult])
    return csv_path


def compute_ref_logits(
    test_set: Subset,
    indices: Sequence[int],
    weights_path: Path,
) -> list[float]:
    """Run the cleartext FHE-quad C3AE model over ``indices`` and return logits.

    The model is the same Quad-activation network compiled by Orion; running
    it in PyTorch produces the cleartext reference logit that the FHE pipeline
    output is compared against (noise = fhe_logit - ref_logit).
    """
    if not weights_path.exists():
        raise FileNotFoundError(f"--with-ref-logit needs weights at {weights_path}")
    device = torch.device("cpu")
    model = C3AE_FHE(img_size=64, first_stride=2).to(device)
    state = torch.load(weights_path, map_location=device, weights_only=True)
    model.load_state_dict(state)
    model.eval()

    logits: list[float] = []
    with torch.no_grad():
        for idx in indices:
            img, _, _ = test_set[idx]
            img_b = img.unsqueeze(0).to(device)
            out = model(img_b)
            logits.append(float(out.reshape(-1)[0].item()))
    return logits


def write_manifest(
    manifest_path: Path,
    *,
    config: str,
    weights_path: Path,
    out_dir: Path,
    indices: Sequence[int],
    ages: Sequence[int],
    labels: Sequence[int],
    ref_logits: Sequence[float] | None,
) -> None:
    """Write ``eval_inputs.json`` consumed by ``bench.eval``."""
    images: list[dict[str, object]] = []
    for i, idx in enumerate(indices):
        entry: dict[str, object] = {
            "idx": int(idx),
            "path": str(out_dir / f"sample_{idx}.bin"),
            "age": int(ages[i]),
            "label": int(labels[i]),
        }
        if ref_logits is not None:
            entry["ref_logit"] = float(ref_logits[i])
        images.append(entry)

    manifest = {
        "config": config,
        "weights": str(weights_path),
        "generated_at": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
        "images": images,
    }
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    with manifest_path.open("w") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--idx",
        type=int,
        default=None,
        help="Dump a single test-set sample at this position.",
    )
    mode.add_argument(
        "--boundary-band",
        action="store_true",
        help="Dump the first 3 test samples with 16 <= age <= 20.",
    )
    mode.add_argument(
        "--batch",
        type=int,
        default=None,
        help="Dump a batch of N samples (use with --stratified for 50/50 split).",
    )
    parser.add_argument(
        "--stratified",
        action="store_true",
        help="In --batch mode, pick N/2 minors (label=0) and N/2 adults (label=1).",
    )
    parser.add_argument(
        "--with-ref-logit",
        action="store_true",
        help="In --batch mode, compute the cleartext FHE-quad logit per sample.",
    )
    parser.add_argument(
        "--out-manifest",
        type=Path,
        default=None,
        help="In --batch mode, write the eval-input manifest JSON to this path.",
    )
    parser.add_argument(
        "--weights",
        type=Path,
        default=Path("out/weights_fhe.pth"),
        help="Path to FHE-quad weights for --with-ref-logit (default out/weights_fhe.pth).",
    )
    parser.add_argument(
        "--config",
        type=str,
        default="logn16",
        help="Config tag recorded in the manifest (default logn16).",
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=Path("./data/UTKFace"),
        help="UTKFace image directory (jpg files).",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("out/inputs"),
        help="Output directory for sample_*.bin and ground_truth.csv.",
    )
    args = parser.parse_args()

    if args.batch is not None:
        if not args.stratified:
            raise SystemExit("--batch currently requires --stratified")
        if args.out_manifest is None:
            raise SystemExit("--batch requires --out-manifest <path>")
    else:
        if args.stratified or args.with_ref_logit or args.out_manifest is not None:
            raise SystemExit(
                "--stratified / --with-ref-logit / --out-manifest are only valid with --batch"
            )

    test_set = build_test_split(args.data_dir)

    if args.batch is not None:
        indices = select_stratified_indices(test_set, args.batch)
    else:
        indices = select_indices(test_set, args)

    rows: list[tuple[int, int, int]] = []
    for idx in indices:
        age, is_adult = dump_sample(test_set, idx, args.out_dir)
        rows.append((idx, age, is_adult))
        print(f"  wrote {args.out_dir / f'sample_{idx}.bin'}  age={age} is_adult={is_adult}")

    csv_path = write_ground_truth(rows, args.out_dir)
    print(f"  wrote {csv_path}  ({len(rows)} new/updated row(s))")

    if args.batch is not None:
        assert args.out_manifest is not None  # narrowed by the check above
        ages = [r[1] for r in rows]
        labels = [r[2] for r in rows]
        ref_logits: list[float] | None = None
        if args.with_ref_logit:
            ref_logits = compute_ref_logits(test_set, indices, args.weights)
        write_manifest(
            args.out_manifest,
            config=args.config,
            weights_path=args.weights,
            out_dir=args.out_dir,
            indices=indices,
            ages=ages,
            labels=labels,
            ref_logits=ref_logits,
        )
        print(f"  wrote {args.out_manifest}  ({len(indices)} image entries)")


if __name__ == "__main__":
    main()
