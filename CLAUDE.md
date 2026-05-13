# CLAUDE.md

Guidance for Claude Code working in this repository. See `docs/DESIGN.md` for the full architectural design.

## Project: ppiav

**Privacy-Preserving Image Attribute Verification.** Bachelor's thesis prototype: end-to-end demonstration of FHE-based facial attribute verification using CKKS via Lattigo and Orion. Age estimation is the demonstration case. Defends against semi-honest verification operators and covert client-side adversaries.

Companion thesis context lives at `~/Dev/ITMO/thesis/`.

## Status

Early scaffolding. No code yet. Design captured in `docs/DESIGN.md`.

## Implementation Phases

1. **Phase 1**: Synthetic CKKS circuit (`x²`), CLI + benchmark harness, no model, no Orion. Goal: scaffolding, abstractions, baseline bench numbers.
2. **Phase 2**: Orion-compiled C3AE inference. `models/` Python pipeline (training + compilation).
3. **Phase 3**: Verification Service / Verification Agent / Resource Service Go HTTP services + browser SPAs (vanilla JS + WASM, copy of Orion's `js/lattigo`).
4. **Phase 4**: lattigo-hierkeys for compressed key transmission.

## Code conventions

- **Go**: simple, idiomatic, minimal comments. Comments only where the _why_ is non-obvious. No multi-paragraph docstrings.
- **Python**: uv for environments — always activate the venv before any pip/python command. Never install deps to system Python. ruff format + lint, mypy strict.
- **Atomic commits**: stage specific files (`git add path/to/file`), never `git add .`. Clear, concrete commit messages.
- **No copying** from `~/Dev/orion/examples/` or thesis experiments (`~/Dev/ITMO/thesis/experiments/`). Reference only — write fresh idiomatic code.

## Repo layout

```
ppiav/
├── cmd/                  # Go binary entry points
├── internal/             # Go packages (private to this module)
├── web/                  # Browser SPAs + ppiav-crypto WASM module
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
