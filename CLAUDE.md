# CLAUDE.md

Guidance for Claude Code working in this repository. See `docs/DESIGN.md` for the full architectural design.

## Project: ppiav

**Privacy-Preserving Image Attribute Verification.** Bachelor's thesis prototype: end-to-end demonstration of FHE-based facial attribute verification using CKKS via Lattigo and Orion. Age estimation is the demonstration case. Defends against semi-honest verification operators and covert client-side adversaries.

Companion thesis context lives at `~/Dev/ITMO/thesis/`.

## Status

Phase 1 (multi-party CKKS + synthetic `x²` + MPD-Auth), Phase 2 (Orion-compiled C3AE inference), Phase 3 (HTTP services + browser SPAs), and Phase 4 (lattigo-hierkeys compressed key transmission) complete. Three Go HTTP services (`ppiav-vservice`, `ppiav-vagent`, `ppiav-rservice`) plus browser SPAs (vclient, rclient) demonstrate the protocol over a network using a WASM build of `internal/vclient`.

`cmd/ppiav-cli` is now an **artifact pipeline**: six per-stage subcommands (`keygen | encrypt | infer | mac | partial-decrypt | finalize`) each load inputs from disk, run one cryptographic op, and write the resulting artifact plus a timing JSON. The old in-process `e2e` / seven step subcommands and the in-process orchestrator-driven bench harness are gone. A Python driver — `python -m bench.eval --inputs ... --orion ...` — chains the subcommands across a stratified UTKFace batch (single shared keygen) into `results/phase2/eval-<UTC-ts>/{keys/, img_<idx>/, eval_inputs.json, keygen.json, summary.md, plots/}`. Per-step peak RSS is now correct (each subcommand is a fresh process) and per-message wire bytes come straight from `os.Stat`. See `docs/plans/completed/20260515-bench-eval-redesign.md` for the original design.

The bench-redesign-v2 layer (`docs/plans/20260516-bench-redesign-v2.md`) adds finer-grained per-stage instrumentation — `infer` emits 4 sub-step samples (`load_keys`, `load_input_ct`, `exec`, `serialize_result`), `mac` emits 2 (`derive_auth_keys`, `compute_ct`), `finalize` emits 2 (`final_decrypt`, `verdict_compute`); keygen share sub-steps now carry `Sample.Bytes` via lattigo `BinarySize()`. Aggregator output is driven by a protocol-message catalog (`bench/bench/_messages.py`): `summary.md` labels wire rows by message id (`VClientGaloisShare`, `VAgentEvalKeyBundle`, etc.) instead of filenames, lists every share/aggregated/derived key in a `## Key inventory` section, and reports a side-by-side plain-C3AE vs FHE-C3AE accuracy / FPR / FNR comparison driven by `ref_logit` from `eval_inputs.json`.

**Subcommand `--orion` flag asymmetry**: `keygen` and `infer` need `--orion <dir>` to load the compiled-model manifest (Phase-2 only); `encrypt`, `mac`, `partial-decrypt`, and `finalize` do NOT — they reconstruct everything they need from the on-disk artifacts written by `keygen` (CKKS params + InputLevel via `params.json`, evaluation keys via `rlk.bin` + `gks_auth.bin` for `mac` and `gks_infer.bin` for `infer`).

**`make eval` prerequisites** (the Python driver): `models/data/UTKFace/` (~331 MB) downloaded via `models/utkface.py` plus `models/out/weights_fhe.pth` produced by `models/train.py`. Neither lives in the repo; both are produced by the VPS pipeline (see `docs/plans/completed/20260514-orion-integration-training-compilation/`). The bench driver fails fast with a clear error if the manifest or weights are missing.

Heavy `LogN=15` round-trip tests under `internal/` are gated behind `PPIAV_RUN_HEAVY=1` to keep `go test ./...` viable on a 38 GB dev box; CI and VPS runs export the flag.

## Implementation Phases

1. **Phase 1** — done. Synthetic CKKS circuit (`x²`), in-process protocol with collaborative keygen + MPD-Auth + joint decryption, CLI + benchmark harness, no model, no Orion.
2. **Phase 2** — done. Training and compilation are in-tree under `models/`. `orion-v2-compiler` is consumed from PyPI. Acceptance runs on a rented `cpu.16.128.240` VPS via the `vps` skill.
3. **Phase 3** — done. Verification Service / Verification Agent / Resource Service Go HTTP services + browser SPAs (vanilla JS + WASM, copy of Orion's `js/lattigo`). Run via `make phase3` then either three terminals or `cd deploy && docker compose up`.
4. **Phase 4** — done. lattigo-hierkeys for compressed key transmission.

## Code conventions

- **Go**: simple, idiomatic, minimal comments. Comments only where the _why_ is non-obvious. No multi-paragraph docstrings.
- **Python**: uv for environments — always activate the venv before any pip/python command. Never install deps to system Python. ruff format + lint, mypy strict.
- **TypeScript** (Phase 3 SPAs in `web/vclient/`, `web/rclient/`, `web/ppiav/`): tsc strict, ES2022 target, DOM lib, no bundler — browsers load `dist/*.js` directly via ES module imports. Each SPA has a `package.json` declaring only `typescript` as a devDep; `web/vclient/` and `web/rclient/` build with `npm run build` (== `tsc`). `web/ppiav/` has no JS emit (the bridge ships as Go-compiled WASM) — its `npm run typecheck` runs `tsc` against the TS surface types. No emoji, no decorative comments. Type the raw `globalThis.ppiav` / `globalThis.lattigo` bridge inline in `main.ts` rather than importing wrappers — keeps the dist/main.js dependency surface to local relatives only.
- **Atomic commits**: stage specific files (`git add path/to/file`), never `git add .`. Clear, concrete commit messages.

## Build system (Phase 3)

`make phase3` chains `wasm → spas → services` with explicit Make dependencies. Order matters: the Go cmd binaries (`ppiav-vservice`, `ppiav-vagent`, `ppiav-rservice`) import `web/ppiav`, `web/vclient`, `web/rclient` which `//go:embed` the compiled WASM blob and `dist/` directories, so those artifacts must exist before `go build`. On a fresh checkout `make phase3` runs `npm install && npm run build` in each SPA, copies `$(go env GOROOT)/lib/wasm/wasm_exec.js` into `web/vclient/`, builds `web/ppiav/ppiav.wasm` via `GOOS=js GOARCH=wasm go build`, then builds the three service binaries into `bin/`.

URLs come in two flavors per peer: `--*-url` is the server-to-server URL (Docker DNS or localhost), `--*-public-url` is the browser-visible URL (host port-mapped or behind a proxy). When the public URL is empty it falls back to the server-to-server URL, preserving the localhost-on-one-host flow.

## Repo layout

```
ppiav/
├── cmd/                  # Go binary entry points
├── internal/             # Go packages (private to this module)
├── web/                  # Browser SPAs + ppiav-crypto WASM module (Phase 3+)
├── models/               # Python ML pipeline (Phase 2+)
├── bench/                # Plotting & analysis scripts
├── docs/                 # Design & decisions
├── deploy/               # Dockerfiles (Phase 3+)
└── results/              # Benchmark outputs
```

## Related repos (read-only references, not dependencies to copy from)

- Orion (FHE deep learning framework, our fork): `~/Dev/orion/` — https://github.com/butvinm/orion
- Lattigo (CKKS): `~/Dev/3rd-party/lattigo/`
- lattigo-hierkeys (hierarchical rotation keys): `~/Dev/lattigo-hierkeys/` — https://github.com/butvinm/lattigo-hierkeys

## Lattigo concurrency

Lattigo **v6.2.0** made all per-structure methods (encryptor, decryptor, evaluator, samplers, PRNG) safe to call concurrently. v6.2.0 removed `ShallowCopy()` because it is no longer needed.

## Out of scope

Auth, TLS, rate limiting, presentation-attack detection (deepfake/spoofing), input sanitization beyond what the protocol demands. The thesis explicitly deprioritizes these as orthogonal concerns.
