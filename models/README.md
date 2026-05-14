# ppiav-models

Image preprocessing for the ppiav prototype.

This Python package owns the 5-step pipeline that turns a regular image file
into the 12288-float64 tensor consumed by `internal/vclient.EncryptImage` (see
`docs/DESIGN.md` §`internal/vclient`):

1. Decode + convert to RGB.
2. Resize to 64x64, bicubic.
3. Divide by 255 (pixels in `[0, 1]`).
4. `(x - 0.5) / 0.5` (pixels in `[-1, 1]`).
5. HWC -> CHW, flatten to 12288 little-endian float64s (= 98304 bytes).

## Usage

```bash
cd models
uv sync
uv run python -m models.prepare_samples --in path/to/img.jpg --out path/to/out.bin
```

The output `.bin` is exactly what the Phase-1 CLI consumes:

```bash
go run ./cmd/ppiav-cli e2e --image path/to/out.bin --n 5
```

## Training and compilation are deferred

This package **does not** train or compile a model. The Phase-2 Go path
reuses Orion's pre-trained, pre-compiled C3AE artifacts directly:

- Trained checkpoint: `~/Dev/orion/examples/c3ae-demo/out/weights_fhe.pth`
- Compiled circuit (LogN=16): `~/Dev/orion/examples/c3ae-demo/out/logn16/`
- Reference encrypted input: `~/Dev/orion/examples/c3ae-demo/out/inputs/sample_test.bin`

If Orion's reference becomes stale, retraining + recompiling against a
freshly-trained model is a future task — see `docs/plans/`.

## Dev

```bash
uv run pytest
uv run ruff check .
uv run mypy models tests
```

To regenerate the committed test fixtures (only when the pipeline changes
intentionally):

```bash
uv run python -m tests.fixtures.generate
```
