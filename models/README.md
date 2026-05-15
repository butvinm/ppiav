# ppiav-models

Training, compilation, and test-sample generation for the Phase-2 FHE pipeline.

## In-tree pipeline

1. `utkface` — Download UTKFace dataset via kagglehub.
2. `train` — Train C3AE for binary age verification (18+) with asymmetric loss.
3. `compile` — Compile the trained model for CKKS FHE inference via Orion.
4. `prepare_samples` — Generate test-set samples as 12288-float64 `.bin` blobs.
5. `ppiav-cli e2e` — Run the full in-process protocol against the compiled model.

```bash
cd models
uv sync
uv run python -m models.utkface --target ./data/UTKFace
uv run python -m models.train --variant fhe --data-dir ./data/UTKFace --epochs 60 --output ./out/weights_fhe.pth
uv run python -m models.compile --variant fhe --config logn16 --weights ./out/weights_fhe.pth --output ./out/logn16/model.orion
uv run python -m models.prepare_samples --idx 0 --data-dir ./data/UTKFace --out-dir ./out/inputs
cd ..
go run ./cmd/ppiav-cli e2e --orion ./models/out/logn16 --image ./models/out/inputs/sample_0.bin --n 1
```

## Hardware requirements

FHE inference at `logn16` peaks at ~114 GB RSS. Training + compilation can run on a 38 GB dev box, but the full pipeline must run on a rented VPS:

- `logn16` (256 GB RAM): `cpu.16.256.240` or larger.

The dev box (38 GB) can only run `utkface`, `train`, and `compile` locally. The final `prepare_samples` + `ppiav-cli e2e` requires a VPS with sufficient RAM for inference.

## Dependencies

- `orion-v2-compiler` from PyPI (compiled CKKS circuits).
- `torch>=2.2` for model training.
- `kagglehub` for dataset download.

## Dev

```bash
cd models
uv run ruff check .
uv run mypy .
```
