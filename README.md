# ppiav

Privacy-Preserving Image Attribute Verification using FHE-based facial attribute verification with CKKS (via Lattigo and Orion).

## Quick start

Train a C3AE model, compile it for FHE inference, and run the end-to-end protocol:

```sh
# 1. Download UTKFace dataset
cd models
uv sync
uv run python -m models.utkface --target ./data/UTKFace

# 2. Train the model (use --variant relu for baseline, --variant fhe for FHE)
uv run python -m models.train --variant fhe --data-dir ./data/UTKFace --epochs 60

# 3. Compile for FHE inference
uv run python -m models.compile --variant fhe --config logn16 --weights ./out/weights_fhe.pth --output ./out/logn16/model.orion

# 4. Prepare test sample
uv run python -m models.prepare_samples --idx 0 --data-dir ./data/UTKFace --out-dir ./out/inputs

# 5. Run end-to-end protocol (requires VPS with sufficient RAM for inference)
cd ..
go run ./cmd/ppiav-cli e2e \
    --orion ./models/out/logn16 \
    --image ./models/out/inputs/sample_0.bin \
    --n 5
```

The e2e benchmark outputs to `results/phase2/e2e.json`. Use the `bench/` scripts to visualize:

```sh
cd bench
uv run python -m bench.tables ../results/phase2
uv run python -m bench.plot ../results/phase2
```

## Quick start — Phase 3 (HTTP services + browser SPAs)

### Prerequisites

- Go 1.22+ (`go env GOROOT/lib/wasm/wasm_exec.js` must exist — bundled with the standard Go toolchain).
- Node.js 18+ and `npm` for the TypeScript SPA build (`tsc`).
- `make phase3` copies `wasm_exec.js` from the active Go toolchain into `web/vclient/`; that file is `.gitignore`d and rebuilt on every `make wasm`.

### Build and run locally

Build the WASM blob, both SPAs, and the three Go services:

```sh
make phase3
# or, equivalently
make wasm spas services
```

Run all three services in three terminals (synthetic x² circuit, no Orion model required):

```sh
./bin/ppiav-vservice --addr :8080
./bin/ppiav-vagent --addr :8081 --vservice-url http://localhost:8080 --rservice-url http://localhost:8082
./bin/ppiav-rservice --addr :8082 --vagent-url http://localhost:8081
```

For full FHE inference, pass `--orion <model-dir>` to `ppiav-vservice` (and to `ppiav-vagent` so both services agree on the CKKS params):

```sh
./bin/ppiav-vservice --addr :8080 --orion ./models/out/logn16
./bin/ppiav-vagent  --addr :8081 --orion ./models/out/logn16 \
    --vservice-url http://localhost:8080 --rservice-url http://localhost:8082
```

Or via docker-compose (synthetic x² by default; see comments in `deploy/docker-compose.yml` for the `--orion` override + volume mount):

```sh
cd deploy && docker compose up
```

When deploying behind a reverse proxy or in Docker, pass `--rservice-public-url` to `ppiav-vagent` and `--vagent-public-url` to `ppiav-rservice` so the browser-visible redirect URLs use host-reachable hostnames rather than internal service names.

Browser flow: open `http://localhost:8082/protected`. RService 302s to VAgent's `/verify?sid=...`, the VClient SPA loads, upload an image, and on completion the SPA reads the JSON `{redirect: …}` reply from VAgent and navigates back to `/protected` with the verdict (Accept or Reject).

For WASM debugging open the browser console: `globalThis.lattigo` and `globalThis.ppiav` expose the underlying CKKS and vclient namespaces.

## Training and evaluation

The `models/` package provides a complete training pipeline:

```sh
cd models

# Train ReLU baseline (cleartext-only, faster)
uv run python -m models.train --variant relu --data-dir ./data/UTKFace --epochs 60

# Train FHE variant (Quad approximation for Orion compilation)
uv run python -m models.train --variant fhe --data-dir ./data/UTKFace --epochs 60

# Evaluate both variants
uv run python -m models.eval --data-dir ./data/UTKFace --output results/cleartext.csv
```

See `models/README.md` for detailed documentation.

## Hardware requirements

FHE inference at `logn16` peaks at ~114 GB RSS — use `cpu.16.256.240` or larger.

Training and compilation can run on a dev box (32+ GB RAM), but the full e2e protocol including inference requires a VPS with sufficient RAM for inference.

## Development

```sh
# Go tests
go test ./...
go vet ./...
go build ./...

# Python linting and type checking
cd models
uv run ruff check .
uv run mypy .
```

## Architecture

See `docs/DESIGN.md` for detailed architecture documentation.
