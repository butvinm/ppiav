# ppiav-models

Training, compilation, and test-sample generation for the FHE pipeline.

## In-tree pipeline

1. `utkface` — Download UTKFace dataset via kagglehub.
2. `train` — Train C3AE for binary age verification (18+) with asymmetric loss.
3. `compile` — Compile the trained model for CKKS FHE inference via Orion.
4. `prepare_samples` — Generate `.bin` blobs from UTKFace test samples. Single-sample
   mode for ad-hoc use; batch mode (with `--batch N --stratified --with-ref-logit
--out-manifest`) generates the input manifest consumed by `python -m bench.eval`.
5. `python -m bench.eval` — Drive the full protocol across the stratified batch and
   aggregate per-step timing / RSS / wire-bytes / FPR-FNR / noise / SNR.

```bash
cd models
uv sync
uv run python -m models.utkface --target ./data/UTKFace
uv run python -m models.train --variant fhe --data-dir ./data/UTKFace --epochs 60 --output ./out/weights_fhe.pth
uv run python -m models.compile --variant fhe --config logn16 --weights ./out/weights_fhe.pth --output ./out/logn16/model.orion

# Stratified batch + manifest with cleartext reference logits (used by the eval driver).
uv run python -m models.prepare_samples \
    --batch 10 --stratified --with-ref-logit \
    --data-dir ./data/UTKFace \
    --out-dir ./out/inputs \
    --out-manifest ./out/eval_inputs.json

# Drive the full protocol (keygen runs once, then 10× encrypt → infer → mac → partial → finalize).
cd ..
uv --project bench run python -m bench.eval \
    --inputs ./models/out/eval_inputs.json \
    --orion  ./models/out/logn16
```

`bench.eval` writes per-batch outputs to `results/phase2/eval-<UTC-ts>/` — see
`bench/README.md` for the directory layout and aggregated tables / plots.

The legacy single-sample mode is preserved (omit the batch flags) for quick
sanity checks against individual UTKFace indices.

## Hardware requirements

FHE inference at `logn16` peaks at ~114 GB RSS. Training + compilation can run on a 38 GB dev box, but the full pipeline must run on a rented VPS:

- `logn16` (128 GB RAM): `cpu.16.128.240`. ~10 GB headroom at the measured peak; verified by Orion's c3ae `logn16` run (see `~/Dev/orion/docs/plans/completed/2026-05-09-c3ae-vps-runs.md` Task 16).

The dev box (38 GB) can only run `utkface`, `train`, and `compile` locally. The final `prepare_samples` + `bench.eval` evaluation requires a VPS with sufficient RAM for inference.

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
