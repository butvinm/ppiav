"""UTKFace dataset and 70/15/15 train/val/test split helper for C3AE."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import torch
from PIL import Image
from torch.utils.data import Dataset, Subset, random_split

AGE_MAX = 100


class UTKFaceDataset(Dataset):
    """UTKFace image+label loader with [-1, 1] normalization."""

    def __init__(self, data_dir, img_size: int = 64, age_threshold: int = 18):
        self.img_size = img_size
        self.samples: list[tuple[Path, int, float]] = []

        # sorted() is load-bearing: filesystem-order is unstable across
        # mounts, after add/remove/rename, and across `git clean`. The split
        # downstream is seeded, but the seed only randomizes a *list* — the
        # list itself must be stable.
        for img_path in sorted(Path(data_dir).glob("*.jpg*")):
            try:
                age = min(max(int(img_path.name.split("_")[0]), 0), AGE_MAX)
                is_adult = 1.0 if age >= age_threshold else 0.0
                self.samples.append((img_path, age, is_adult))
            except (ValueError, IndexError):
                continue

        if not self.samples:
            raise ValueError(f"No samples found in {data_dir}")

        ages = [s[1] for s in self.samples]
        minors = sum(1 for s in self.samples if s[2] == 0.0)
        adults = len(self.samples) - minors
        print(
            f"[Dataset] {len(self.samples)} samples: "
            f"{minors} minors ({minors / len(self.samples) * 100:.0f}%), "
            f"{adults} adults, ages {min(ages)}-{max(ages)}"
        )

    def __len__(self) -> int:
        return len(self.samples)

    def __getitem__(self, idx: int):
        img_path, age, is_adult = self.samples[idx]
        img = Image.open(img_path).convert("RGB").resize((self.img_size, self.img_size))
        img_arr = np.array(img, dtype=np.float32) / 255.0
        img_arr = (img_arr - 0.5) / 0.5  # Normalize to [-1, 1]
        img_t = torch.from_numpy(img_arr).permute(2, 0, 1)
        return img_t, torch.tensor([is_adult], dtype=torch.float32), age


def build_test_split(data_dir: Path, img_size: int = 64) -> Subset:
    """Reproduce the canonical 70/15/15 split with manual_seed(42)."""
    dataset = UTKFaceDataset(data_dir, img_size=img_size)
    train_size = int(0.70 * len(dataset))
    val_size = int(0.15 * len(dataset))
    test_size = len(dataset) - train_size - val_size
    _, _, test_set = random_split(
        dataset,
        [train_size, val_size, test_size],
        generator=torch.Generator().manual_seed(42),
    )
    return test_set


def fetch_utkface(target: Path = Path("data/UTKFace")) -> Path:
    """Download UTKFace via kagglehub and symlink target to its JPG dir."""
    if target.is_dir():
        return target
    if target.is_symlink() or target.exists():
        raise FileExistsError(
            f"{target} exists but is not a usable directory; remove it and re-run"
        )
    import kagglehub

    extracted = Path(kagglehub.dataset_download("jangedoo/utkface-new"))
    try:
        jpg_dir = next(extracted.rglob("*.jpg")).parent
    except StopIteration as e:
        raise FileNotFoundError(f"No JPGs found under {extracted}") from e
    target.parent.mkdir(parents=True, exist_ok=True)
    target.symlink_to(jpg_dir)
    return target


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Download UTKFace via kagglehub and symlink it to a stable local path.",
    )
    parser.add_argument(
        "--target",
        type=Path,
        default=Path("data/UTKFace"),
        help="Symlink path to create (default: ./data/UTKFace).",
    )
    args = parser.parse_args()
    target = fetch_utkface(args.target)
    print(f"UTKFace ready at {target} -> {target.resolve()}")


if __name__ == "__main__":
    main()
