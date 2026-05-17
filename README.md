# ppiav

Privacy-Preserving Image Attribute Verification using FHE-based facial attribute verification with CKKS (via Lattigo and Orion).

A verification operator checks an attribute (age) on an encrypted facial image without ever seeing the image or the result in cleartext. The user's browser performs all client-side cryptography — multi-party CKKS keygen, image encryption, joint decryption — via WebAssembly; three Go services handle the encrypted inference and verdict callback.

## Demo

Prerequisites:

- Go 1.22+ (the bundled `wasm_exec.js` shim is used).
- Node.js 18+ and `npm` for the TypeScript SPA build.

Build everything (WASM bridge, browser SPAs, three Go binaries):

```sh
make
```

Run the three services in three terminals (synthetic `x²` circuit, no model required):

```sh
./bin/ppiav-vservice --addr :8080
./bin/ppiav-vagent   --addr :8081 \
    --vservice-url http://localhost:8080 \
    --rservice-url http://localhost:8082
./bin/ppiav-rservice --addr :8082 --vagent-url http://localhost:8081
```

Open `http://localhost:8082/protected`. The resource service redirects to the verification UI; upload a face image; on completion the browser is redirected back with the verdict (Accept or Reject).

For real FHE age estimation, pass `--orion <model-dir>` to both `ppiav-vservice` and `ppiav-vagent` so they agree on the CKKS parameters — see [Training your own model](#training-your-own-model) for producing the model directory.

Or via docker-compose (synthetic `x²` by default; see comments in `deploy/docker-compose.yml` for the `--orion` override + volume mount):

```sh
cd deploy && docker compose up
```

When deploying behind a reverse proxy or across hosts, pass `--rservice-public-url` to `ppiav-vagent` and `--vagent-public-url` to `ppiav-rservice` so the browser-visible redirect URLs use host-reachable hostnames rather than internal service names.

## Building from source

`make` produces:

- `web/ppiav/ppiav.wasm` — the WASM bridge bundling Lattigo and the ppiav protocol APIs
- `web/vclient/dist/`, `web/rclient/dist/` — TypeScript-compiled SPAs
- `bin/ppiav-vservice`, `bin/ppiav-vagent`, `bin/ppiav-rservice` — the three Go services

Subtargets: `make wasm`, `make spas`, `make services`. `make test` runs the full Go test suite; `make clean` removes build outputs.

## Architecture

See `docs/DESIGN.md` for the protocol, components, threat model, and wire formats.

## Training your own model

The `models/` package provides a complete training pipeline:

```sh
cd models
uv sync

# Download UTKFace dataset
uv run python -m models.utkface --target ./data/UTKFace

# Train: --variant relu (baseline) or --variant fhe (Quad approximation for Orion)
uv run python -m models.train --variant fhe --data-dir ./data/UTKFace --epochs 60

# Compile for FHE inference
uv run python -m models.compile --variant fhe --config logn16 \
    --weights ./out/weights_fhe.pth --output ./out/logn16/model.orion

# Evaluate both variants
uv run python -m models.eval --data-dir ./data/UTKFace --output results/cleartext.csv
```

See `models/README.md` for detailed documentation.

## Hardware requirements

FHE inference at `logn16` peaks at ~114 GB RSS — use a host with at least 128 GB RAM (e.g., `cpu.16.128.240`). Training and compilation can run on a dev box with 32+ GB RAM.

## Benchmarks

Per-stage protocol timings, per-message wire bytes, RSS, and protocol-level FPR/FNR are produced by the `ppiav-cli` artifact pipeline (six per-stage subcommands chained by a Python driver) — a separate code path from the HTTP services in the demo:

```sh
# Prepare a stratified UTKFace batch + cleartext reference logits.
cd models
uv run python -m models.prepare_samples \
    --batch 10 --stratified --with-ref-logit \
    --data-dir ./data/UTKFace \
    --out-dir ./out/inputs \
    --out-manifest ./out/eval_inputs.json

# Drive the full pipeline: keygen runs once, then 10× encrypt → infer → mac → partial → finalize.
cd ../bench
uv run python -m bench.eval \
    --inputs ../models/out/eval_inputs.json \
    --orion  ../models/out/logn16
```

The driver creates `results/<UTC-ts>/` containing `keys/`, per-image `img_<idx>/` directories, `keygen.json`, `eval_inputs.json`, `summary.md` (per-party time + memory by party, keygen by round, per-message bytes, key inventory, plain vs FHE accuracy, noise + SNR, network wire time), and `plots/` (6 PNGs). See `bench/README.md` for the layout.

On a 128 GB host the `logn16` configuration peaks at ~114 GB RSS at the first `infer` step — set `GOMEMLIMIT=120GiB` in the environment before invoking `bench.eval` so the Go runtime applies back-pressure before the OOM killer fires (the in-process `infer` does no streaming and there is no other knob to cap heap growth).

## Development

```sh
go test ./...
go vet ./...
go build ./...

cd models
uv run ruff check .
uv run mypy .
```

WASM debugging: open the browser console — `globalThis.ppiav` is the SPA bridge consumed by the client; `globalThis.lattigo` is registered for low-level CKKS inspection.
