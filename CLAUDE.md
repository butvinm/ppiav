# CLAUDE.md

Guidance for Claude Code working in this repository. See `docs/DESIGN.md` for the full architectural design.

## Project: ppiav

**Privacy-Preserving Image Attribute Verification.** Bachelor's thesis prototype: end-to-end demonstration of FHE-based facial attribute verification using CKKS via Lattigo and Orion. Age estimation is the demonstration case. Defends against semi-honest verification operators and covert client-side adversaries.

Companion thesis context lives at `~/Dev/ITMO/thesis/`.

## Status

Phase 1 (multi-party CKKS + synthetic `x²` + MPD-Auth), Phase 2 (Orion-compiled C3AE inference), and Phase 3 (HTTP services + browser SPAs) complete. An in-process orchestrator (`internal/orchestrator`) drives the full §3 protocol via `cmd/ppiav-cli`, emitting per-stage benchmark JSON consumed by the Python `bench/` project. Three Go HTTP services (`ppiav-vservice`, `ppiav-vagent`, `ppiav-rservice`) plus browser SPAs (vclient, rclient) demonstrate the protocol over a network using a WASM build of `internal/vclient`. Phase 4 (lattigo-hierkeys) is outstanding.

## Implementation Phases

1. **Phase 1** — done. Synthetic CKKS circuit (`x²`), in-process protocol with collaborative keygen + MPD-Auth + joint decryption, CLI + benchmark harness, no model, no Orion.
2. **Phase 2** — done. Training and compilation are in-tree under `models/`. `orion-v2-compiler` is consumed from PyPI. Acceptance runs on a rented `cpu.16.128.240` VPS via the `vps` skill.
3. **Phase 3** — done. Verification Service / Verification Agent / Resource Service Go HTTP services + browser SPAs (vanilla JS + WASM, copy of Orion's `js/lattigo`). Run via `make phase3` then either three terminals or `cd deploy && docker compose up`.
4. **Phase 4** — pending. lattigo-hierkeys for compressed key transmission.

## Code conventions

- **Go**: simple, idiomatic, minimal comments. Comments only where the _why_ is non-obvious. No multi-paragraph docstrings.
- **Python**: uv for environments — always activate the venv before any pip/python command. Never install deps to system Python. ruff format + lint, mypy strict.
- **TypeScript** (Phase 3 SPAs in `web/vclient/`, `web/rclient/`, `web/ppiav/`): tsc strict, ES2022 target, DOM lib, no bundler — browsers load `dist/*.js` directly via ES module imports. Each SPA has a `package.json` declaring only `typescript` as a devDep; build with `npm run build` (== `tsc`). No emoji, no decorative comments. Type the raw `globalThis.ppiav` / `globalThis.lattigo` bridge inline in `main.ts` rather than importing wrappers — keeps the dist/main.js dependency surface to local relatives only.
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
