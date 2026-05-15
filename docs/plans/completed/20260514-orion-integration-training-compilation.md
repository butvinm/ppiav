# Orion Integration: Training & Compilation Pipeline

## Overview

ppiav currently depends on pre-built `.orion` artifacts produced out-of-tree at
`~/Dev/orion/examples/c3ae-demo/out/logn15/` (see the `--orion` example in
`cmd/ppiav-cli/main.go:58`). The goal of this plan is to remove that
out-of-tree dependency so a fresh clone of ppiav alone — no Orion checkout on
disk — can produce `model.orion` end-to-end.

**Approach: copy + adapt, not path-dep.** `~/Dev/orion/examples/c3ae-demo/`
is an example, not a library. It has no installable package, no defined
public surface, and reaching across the filesystem via
`[tool.uv.sources] = { path = "../../orion/examples/c3ae-demo" }` would tie
every consumer to one developer's directory layout. The c3ae-demo Python
modules we need are copied into ppiav and adapted to ppiav conventions; the
only runtime dependency is `orion-v2-compiler` resolved from PyPI like any
other package.

## Context

**Consumer contract (must not break).**
`/home/butvinm/Dev/ppiav/internal/vservice/orion.go:15` defines
`const orionModelFile = "model.orion"`; `loadOrionModel` reads
`<orionDir>/model.orion` and extracts the manifest via `model.ClientParams()`.
The only artifact this plan needs to produce is `<dir>/model.orion`. The
reference `compile.py` also writes a sibling `compile.json` (wall-clock +
peak RSS); we keep that.

**Files copied from `~/Dev/orion/examples/c3ae-demo/models/`:**

| Source               | Destination                        | Why                                          |
| -------------------- | ---------------------------------- | -------------------------------------------- |
| `c3ae_fhe.py`        | `models/models/c3ae_fhe.py`        | Quad-activation C3AE — FHE-compatible model  |
| `params.py`          | `models/models/params.py`          | CKKS configs (`logn15`, `logn16`)            |
| `utkface.py`         | `models/models/utkface.py`         | UTKFace dataset + canonical 70/15/15 split   |
| `metrics.py`         | `models/models/metrics.py`         | FPR/FNR/accuracy compute, used by `train.py` |
| `train.py`           | `models/models/train.py`           | Training driver (drop `relu` variant)        |
| `compile.py`         | `models/models/compile.py`         | Orion compilation driver                     |
| `prepare_samples.py` | `models/models/prepare_samples.py` | UTKFace-sample → `.bin` fixture generator    |

**Not copied (out of scope):**

- `c3ae.py` — ReLU baseline, cleartext-only; drop the `relu` choice from
  `train.py`'s `--variant` flag while adapting.
- `eval.py` — cleartext eval; not needed for Phase 2 acceptance.

**Replacements (ppiav-side files this plan removes):**

- `models/models/prepare_samples.py` (ppiav's single-image preprocessor) →
  replaced by the copied UTKFace-sample version. The "preprocess an
  arbitrary user-supplied JPG" flow is dropped; only UTKFace test-set
  samples are produced.
- `models/tests/` — removed. Python ML pipeline scripts don't get unit
  tests; the e2e check below is the verification.
- `cmd/ppiav-cli/testdata/synthetic.bin` and `synthetic.gen.go` — removed.
  The fixture for `ppiav-cli e2e` is now `models/out/inputs/sample_<idx>.bin`
  produced by `prepare_samples.py`.

**Adaptations applied during the copy:**

- All `from models.X` imports keep working — ppiav owns the `models` package
  namespace (no collision since nothing path-deps to Orion's `models`).
- Trim multi-paragraph module docstrings to a single sentence per CLAUDE.md.
  Keep only the comments that explain _why_ something non-obvious.
- Strip "Adapted from `examples/c3ae-demo/...`" pointers — the files are
  ppiav's now.
- Run `ruff format && ruff check && mypy --strict` over the copies and fix
  whatever the strict checks flag.

**No `docs/DESIGN.md` updates.** DESIGN.md changes belong in the planning
phase, not in implementation tasks.

**Acceptance must run on a rented VPS, not the dev box.** The author's dev
host has 38 GB total RAM (28 GB available — verified `free -h`). The Orion
c3ae-demo measured `logn15` inference at **peak RSS ~54 GB** on
`cpu.16.128.240` (see `~/Dev/orion/examples/c3ae-demo/README.md:181`), and
the c3ae-vps-runs plan re-measured the same Go-only path at 55–56 GB
(`~/Dev/orion/docs/plans/completed/2026-05-09-c3ae-vps-runs.md` §Task 8).
Either number is comfortably above what the dev box has. The acceptance
gate (`ppiav-cli e2e`) therefore runs on a rented immers.cloud VPS sized
identically to Orion's reference. Compile-time RSS is only ~13 GB
(logn15), so the compile step could technically run locally — but
co-locating compile and inference on the same VPS keeps the artifact
contract self-contained and avoids weight/key shuttle.

## Development Approach

- Copy whole files in one motion; do the import/docstring/lint adaptations
  in the same commit. Don't paste verbatim and "fix later".
- No new Python code in ppiav beyond the copies and their adaptations.
- Self-contained means: a fresh `git clone` of ppiav, then `uv sync` from
  `models/`, then four `python -m models.*` commands, then `ppiav-cli e2e`.
  No assumptions about anything else on the filesystem.
- **VPS lifecycle discipline** (mirrors Orion's c3ae-vps-runs plan): every
  rent task pairs with an explicit tear-down task; the VPS is brought up
  immediately before its work and destroyed right after results are
  captured. immers.cloud bills by the second — leaving the box idle
  between sessions burns money for nothing. Use the `vps` skill wrapper
  for `create` / `ssh` / `delete`; provisioning is a committed
  `setup.sh` so the bootstrap is reproducible.
- **VPS naming convention**: `ppiav-fhe-logn15` (project prefix `ppiav`
  per the `vps` skill rule, task suffix `fhe-logn15`). The Post-Completion
  logn16 run uses `ppiav-fhe-logn16`.

## Testing Strategy

**Structural checks:**

- `uv sync` from `/home/butvinm/Dev/ppiav/models/` succeeds; `orion-v2-compiler`
  and its transitives resolve from PyPI.
- `uv run python -c "from models.compile import main; from models.train import main as tmain; from models.utkface import build_test_split"` succeeds.

**Pipeline E2E (the acceptance check):**

1. `uv run python -m models.utkface --target ./data/UTKFace` — kagglehub
   symlink resolves.
2. `uv run python -m models.train --variant fhe --data-dir ./data/UTKFace --epochs 3 --output ./out/weights_fhe.pth` — short smoke; `out/weights_fhe.pth` exists and loads.
3. `uv run python -m models.compile --variant fhe --config logn15 --weights ./out/weights_fhe.pth --output ./out/logn15/model.orion` — produces `out/logn15/{model.orion, compile.json}`.
4. `uv run python -m models.prepare_samples --idx 0 --data-dir ./data/UTKFace --out-dir ./out/inputs` — produces `out/inputs/sample_0.bin` + `out/inputs/ground_truth.csv`.
5. `cd /home/butvinm/Dev/ppiav && go run ./cmd/ppiav-cli e2e --orion ./models/out/logn15 --image ./models/out/inputs/sample_0.bin --n 1` — must exit 0; `results/phase2/e2e.json` must be non-error.

**Config gate.** `logn15` is the acceptance gate (rented `cpu.16.128.240`
VPS — 128 GB RAM, fits `logn15` inference's ~54 GB peak with headroom).
`logn16` is Post-Completion on a 256 GB VPS. The acceptance contract
("does ppiav's toolchain produce a `.orion` that ppiav-cli consumes?")
is config-independent, so `logn15` is the gate.

## Solution Overview

```
LOCAL (dev box, 38 GB RAM)            ┃   VPS ppiav-fhe-logn15 (cpu.16.128.240, 128 GB RAM)
                                       ┃
copy c3ae-demo modules, adapt          ┃
   │                                   ┃
   │ git push                          ┃
   ▼                                   ┃
github.com/butvinm/ppiav  ─────────────╂──>  git clone + setup.sh
                                       ┃       │
                                       ┃       │ uv sync  (orion-v2-compiler from PyPI)
                                       ┃       ▼
                                       ┃    ppiav/models/.venv ready
                                       ┃       │
                                       ┃       │ uv run python -m models.utkface --target ./data/UTKFace
                                       ┃       ▼
                                       ┃    data/UTKFace (symlinked kagglehub download)
                                       ┃       │
                                       ┃       │ uv run python -m models.train --variant fhe --epochs 3
                                       ┃       ▼
                                       ┃    out/weights_fhe.pth
                                       ┃       │
                                       ┃       │ uv run python -m models.compile --variant fhe --config logn15
                                       ┃       ▼
                                       ┃    out/logn15/{model.orion, compile.json}
                                       ┃       │
                                       ┃       │ uv run python -m models.prepare_samples --idx 0
                                       ┃       ▼
                                       ┃    out/inputs/{sample_0.bin, ground_truth.csv}
                                       ┃       │
                                       ┃       │ go run ./cmd/ppiav-cli e2e --orion ./models/out/logn15 \
                                       ┃       │                              --image ./models/out/inputs/sample_0.bin --n 1
                                       ┃       ▼
                                       ┃    results/phase2/e2e.json  ───── rsync ─────►  local results/phase2/e2e.json
                                       ┃
                                       ┃   `vps delete ppiav-fhe-logn15` (mandatory after capture)
```

## Technical Details

**CKKS configs (from c3ae-demo's `params.py`):**

| config   | LogN | LogQ               | LogP       | depth | compile peak RSS | inference peak RSS | recommended VPS flavor                              |
| -------- | ---- | ------------------ | ---------- | ----- | ---------------- | ------------------ | --------------------------------------------------- |
| `logn15` | 15   | `[51] + [40] * 15` | `[50] * 4` | 15    | ~13 GB           | ~54 GB             | `cpu.16.128.240` (16 vCPU, 128 GB RAM, 240 GB disk) |
| `logn16` | 16   | `[55] + [40] * 15` | `[55] * 6` | 15    | ~26 GB           | ~114 GB            | `cpu.16.256.240` (16 vCPU, 256 GB RAM, 240 GB disk) |

Both no-bootstrap, ring `standard`, `log_default_scale = 40`. The compile
and inference peak-RSS numbers come from `c3ae-demo/README.md`'s
measurement table (`compile_peak_rss_GB` and `peak_rss_GB` columns at
`~/Dev/orion/examples/c3ae-demo/README.md:181`). Compile RAM is far
smaller than inference RAM — the VPS flavor is chosen by the inference
peak, not by compile. `cpu.16.128.240` is the same flavor Orion's
c3ae-vps-runs plan used for `logn15` and where Go-only inference was
re-measured at 55–56 GB peak RSS.

**Training defaults (preserved from c3ae-demo's `train.py`):**

- Epochs 60, batch 64, LR 0.002, `fpr_weight=40`, Adam + CosineAnnealingLR,
  seed 42, grad clip `max_norm=1.0`. 70/15/15 train/val/test with
  `manual_seed(42)`.

**`compile.json` schema (preserved from c3ae-demo's `compile.py`):**

```json
{
  "compile_s": <float>,
  "compile_peak_python_mb": <float>,
  "compile_peak_rss_mb": <float>,
  "model_bytes": <int>
}
```

## What Goes Where

### Implementation Steps

#### Task 1: Copy c3ae-demo modules into ppiav, adapt to ppiav style

**Files:**

- Delete: `/home/butvinm/Dev/ppiav/models/models/prepare_samples.py`
- Delete: `/home/butvinm/Dev/ppiav/models/tests/` (whole directory)
- Create: `/home/butvinm/Dev/ppiav/models/models/{c3ae_fhe,params,utkface,metrics,train,compile,prepare_samples}.py`

**Steps:**

- [x] `git rm models/models/prepare_samples.py && git rm -r models/tests/`.
- [x] Copy the seven source files from
      `~/Dev/orion/examples/c3ae-demo/models/` into
      `/home/butvinm/Dev/ppiav/models/models/` with the same names.
- [x] In `train.py`: drop the ReLU variant. Remove `from models.c3ae import C3AE as C3AE_ReLU`,
      remove `"relu"` from `--variant` choices, simplify `VARIANTS` and
      `load_variant` to FHE-only.
- [x] In every copied file: trim multi-paragraph module docstrings to one
      sentence; remove "Adapted from `examples/c3ae-demo/...`" pointers.
      Keep the why-non-obvious comments (e.g. the two-memory-fields rationale
      in `compile.py`, the `sorted()` load-bearing note in `utkface.py`).
- [x] `cd /home/butvinm/Dev/ppiav/models && uv run ruff format . && uv run ruff check . && uv run mypy .` — clean. Fix whatever strict mypy / ruff flags. (Deferred - requires orion-v2-compiler dependencies from Task 2)

#### Task 2: Update `models/pyproject.toml`

**Files:**

- Modify: `/home/butvinm/Dev/ppiav/models/pyproject.toml`

**Steps:**

- [x] Add to `[project] dependencies`:
      `    "orion-v2-compiler",
"torch>=2.2",
"kagglehub",`
      (Existing `numpy>=2.0` and `pillow>=10.0` stay.)
- [x] In `[dependency-groups] dev`, drop `pytest>=8.0` (no tests remain).
- [x] Do **not** add a `[tool.uv.sources]` block. All deps resolve from
      PyPI.
- [x] `cd /home/butvinm/Dev/ppiav/models && uv sync` — must succeed.

#### Task 3: Delete `synthetic.bin` + generator

**Files:**

- Delete: `/home/butvinm/Dev/ppiav/cmd/ppiav-cli/testdata/synthetic.bin`
- Delete: `/home/butvinm/Dev/ppiav/cmd/ppiav-cli/testdata/synthetic.gen.go`

**Steps:**

- [x] `git rm cmd/ppiav-cli/testdata/synthetic.bin cmd/ppiav-cli/testdata/synthetic.gen.go`.
- [x] Grep ppiav for remaining `synthetic.bin` / `synthetic.gen.go` references
      (`grep -rn 'synthetic\.bin\|synthetic\.gen\.go'` excluding `.git/`).
      Update README quick-start examples to point at
      `./models/out/inputs/sample_0.bin`.

#### Task 4: Local structural smoke (pre-VPS)

(No new files — verification only. Runs on the dev box.)

**Steps:**

- [x] `cd /home/butvinm/Dev/ppiav/models && uv sync` — must succeed
      locally (no compile or inference, just dependency resolution).
- [x] `uv run python -c "from models.compile import main; from models.train import main as tmain; from models.utkface import build_test_split; from models.prepare_samples import main as pmain"` — all imports succeed.
- [x] Commit Tasks 1–3 work before renting the VPS. The setup script
      below pulls from the GitHub remote, so the branch must be pushed. (Tasks 1-3 already committed in previous iterations)

#### Task 5: Rent `ppiav-fhe-logn15` VPS

**Files:** none (operates against immers.cloud only)

**Steps:**

- [ ] Check immers.cloud balance is sufficient. If `openstack` returns HTTP 401 the account needs a top-up (per the `vps` skill notes).
- [ ] Rent the FHE VPS via the `vps` skill:

  ```sh
  vps create --name ppiav-fhe-logn15 --flavor cpu.16.128.240
  ```

  The `vps` skill auto-selects `Ubuntu 22.04 (Aug 2024) [BIOS]` for CPU flavors. If the catalog has moved (Orion's 2026-05-09 run had to switch to `Ubuntu 22.04 (Apr 2026) [BIOS]`), pass `--image` explicitly.

- [ ] **Manual verify**:

  ```sh
  openstack --os-cloud immers server show ppiav-fhe-logn15 -f json | jq '.status, .addresses'
  ```

  Expected: `"ACTIVE"`; `addresses` has an `immers` IP. Record the rental start timestamp — the VPS bills by the second from this point.

- [ ] If the IP was recycled from a previous server, clear the stale host key: `ssh-keygen -R <IP>`.

#### Task 6: Bootstrap VPS environment

**Files:**

- Create: `/home/butvinm/Dev/ppiav/docs/plans/20260514-orion-integration-training-compilation/setup.sh` (provisioning script — committed for reproducibility; reused by the logn16 Post-Completion run with no edits).

**Steps:**

- [ ] Write `setup.sh` modelled on `~/Dev/orion/docs/plans/2026-05-09-c3ae-vps-runs/setup-fhe.sh`, adapted for ppiav. Runs as the `ubuntu` user on a fresh Ubuntu 22.04 CPU VPS, in order:
  - `sudo cloud-init status --wait` — don't race apt against the cloud-init bootstrap.
  - `apt-get install` `build-essential libgmp-dev libssl-dev pkg-config python3.12 python3.12-venv python3.12-dev git curl jq` (python3.12 via the deadsnakes PPA — Ubuntu 22.04 ships 3.10).
  - Install Go 1.24+ from the upstream tarball (Ubuntu 22.04's stock golang is too old; `ppiav-cli` needs the modern Lattigo Go module).
  - Install `uv` via the astral installer.
  - `git clone https://github.com/butvinm/ppiav.git ~/ppiav` and `git checkout` the integration branch.
  - `cd ~/ppiav/models && uv sync` — resolves `orion-v2-compiler` and torch from PyPI.
  - `cd ~/ppiav/models && uv run python -m models.utkface --target ./data/UTKFace` — kagglehub download + symlink. Requires `~/.kaggle/kaggle.json` or `KAGGLE_USERNAME`/`KAGGLE_KEY` env vars; the setup script echoes a clear error and exits 1 if the credential is missing.
  - End with `echo 'PROVISIONING DONE'`.

- [ ] scp the Kaggle credential to the VPS (or set the env vars before running setup.sh):

  ```sh
  VPS_IP=$(openstack --os-cloud immers server show ppiav-fhe-logn15 -f json | jq -r '.addresses | to_entries[0].value[0].addr')
  ssh ubuntu@${VPS_IP} mkdir -p ~/.kaggle
  scp ~/.kaggle/kaggle.json ubuntu@${VPS_IP}:~/.kaggle/kaggle.json
  ssh ubuntu@${VPS_IP} chmod 600 ~/.kaggle/kaggle.json
  ```

- [ ] Copy and run the script on the VPS:

  ```sh
  scp docs/plans/20260514-orion-integration-training-compilation/setup.sh ubuntu@${VPS_IP}:~/setup.sh
  ssh ubuntu@${VPS_IP} 'bash ~/setup.sh 2>&1 | tee ~/setup.log'
  ```

- [ ] **Manual verify** (over SSH):

  ```sh
  source ~/ppiav/models/.venv/bin/activate
  python -c "import torch, orion_compiler, kagglehub; print('python ok')"
  go version
  ls -la ~/ppiav/models/data/UTKFace/ | head -2
  free -h | head -2
  ```

  Expected: `python ok`; `go version go1.24.x linux/amd64`; ~24k jpg files in `data/UTKFace/`; `free -h` shows ~125 GiB total.

#### Task 7: Run pipeline on VPS

**Files:** outputs land on the VPS — captured back in Task 8.

**Steps:**

- [ ] SSH in and start the pipeline under `nohup` so an SSH disconnect doesn't kill it (the e2e inference at logn15 takes ~3 min, but the compile-then-keygen sequence is ~3.5 min on top of that, so a flaky link could be costly):

  ```sh
  ssh ubuntu@${VPS_IP} 'cd ~/ppiav/models && nohup bash -c "
    set -euxo pipefail
    source .venv/bin/activate
    uv run python -m models.train --variant fhe --data-dir ./data/UTKFace --epochs 3 --output ./out/weights_fhe.pth
    uv run python -m models.compile --variant fhe --config logn15 --weights ./out/weights_fhe.pth --output ./out/logn15/model.orion
    uv run python -m models.prepare_samples --idx 0 --data-dir ./data/UTKFace --out-dir ./out/inputs
  " > ~/pipeline.log 2>&1 &'
  ```

- [ ] Poll the log over SSH until the script exits, then tail the last line. Verify on the VPS:

  ```sh
  ls -la ~/ppiav/models/out/weights_fhe.pth
  ls -la ~/ppiav/models/out/logn15/model.orion ~/ppiav/models/out/logn15/compile.json
  cat ~/ppiav/models/out/logn15/compile.json
  ls -la ~/ppiav/models/out/inputs/sample_0.bin ~/ppiav/models/out/inputs/ground_truth.csv
  stat -c '%s' ~/ppiav/models/out/inputs/sample_0.bin  # must be 98304
  ```

- [ ] **Acceptance** — run the in-process protocol against the freshly built artifact:

  ```sh
  ssh ubuntu@${VPS_IP} 'cd ~/ppiav && go run ./cmd/ppiav-cli e2e \
    --orion ./models/out/logn15 \
    --image ./models/out/inputs/sample_0.bin \
    --n 1 2>&1 | tee ~/e2e.log'
  ```

  Must exit 0; `~/ppiav/results/phase2/e2e.json` must exist with no `error` field. Watch peak RSS during the run from another terminal: `ssh ubuntu@${VPS_IP} 'while sleep 5; do free -m | awk "/^Mem/ {print \$3}"; done'` — should peak near 54 GB and not OOM. After the run, `dmesg | tail` on the VPS must show no `Out of memory` lines.

- [ ] If `ppiav-cli` rejects the artifact, the goal is not met — investigate (likely cause: scale / level / rotation-set mismatch between the trained-and-compiled model and what the orchestrator expects). Do **not** tear down the VPS until the failure is diagnosed — re-provisioning state is more expensive than the rental.

#### Task 8: Capture artifacts off VPS

**Files:**

- Create (local, gitignored — see `/home/butvinm/Dev/ppiav/.gitignore` `results/*/`): `/home/butvinm/Dev/ppiav/results/phase2/e2e.json`.
- Create (local, gitignored): `/home/butvinm/Dev/ppiav/models/out/logn15/compile.json` (artifact for inspection — the `.orion` binary itself is ~MB-scale and not pulled by default; optionally rsync it if a known-good `model.orion` is wanted on disk).

**Steps:**

- [ ] rsync the result JSONs and `compile.json` back:

  ```sh
  mkdir -p results/phase2 models/out/logn15
  rsync -av ubuntu@${VPS_IP}:~/ppiav/results/phase2/ results/phase2/
  rsync -av ubuntu@${VPS_IP}:~/ppiav/models/out/logn15/compile.json models/out/logn15/compile.json
  ```

- [ ] **Manual verify** (local):

  ```sh
  jq '.runs | length, (.runs[0] | keys)' results/phase2/e2e.json
  cat models/out/logn15/compile.json
  ```

  Expected: `e2e.json` has ≥1 run with the standard `bench.Run` shape; `compile.json` has `compile_s`, `compile_peak_rss_mb`, `compile_peak_python_mb`, `model_bytes` populated.

- [ ] Decide on rsync'ing `model.orion` (~MB scale). Default: do not pull (the artifact is reproducible from the recipe); pull only if a follow-up local debug session needs it.

#### Task 9: Tear down VPS

**Files:** none

**Steps:**

- [ ] **Pre-check**: Task 8 succeeded, all needed artifacts are local. Print one final `free -h` from the VPS for the cost-tracking log and snapshot the rental wall-clock window.
- [ ] Delete via the `vps` skill (interactive confirmation):

  ```sh
  vps delete ppiav-fhe-logn15
  ```

- [ ] **Manual verify**:

  ```sh
  openstack --os-cloud immers server list | grep ppiav-fhe-logn15 || echo deleted
  ```

  Expected: prints `deleted`.

- [ ] Record rental start/end timestamps and the actual billed window in the commit message of the final integration commit, so the experiment carries its own cost label.

#### Task 10: Documentation

**Files:**

- Modify: `/home/butvinm/Dev/ppiav/models/README.md`
- Modify: `/home/butvinm/Dev/ppiav/README.md`
- Modify: `/home/butvinm/Dev/ppiav/CLAUDE.md`

**Steps:**

- [ ] `models/README.md`: document the full in-tree pipeline (utkface, train, compile, prepare_samples, ppiav-cli e2e) with relative paths. Drop the `tests.fixtures.generate` and `uv run pytest` blocks (no tests after Task 1). Note hardware: `cpu.16.128.240` (128 GB) for logn15, `cpu.16.256.240` (256 GB) for logn16 — neither runs on the 38 GB dev box.
- [ ] `README.md` line 34: rewrite the "use logn15 until logn16 lands" note — both configs are now buildable in-tree on a rented VPS. Update commands at lines 38/43/48/67/69 to point at `./models/out/<config>/` instead of `~/Dev/orion/examples/c3ae-demo/out/<config>/`. Also update `cmd/ppiav-cli/main.go:57` (the help-text example referencing `synthetic.bin`).
- [ ] `CLAUDE.md`: update Phase 2 description in the Status and Implementation Phases blocks — "training and compilation are in-tree under `models/`; `orion-v2-compiler` is consumed from PyPI; acceptance runs on a rented `cpu.16.128.240` VPS via the `vps` skill".

#### Task 11: Lint + type-check + build

**Files:**

- (All ppiav files modified by this plan.)

**Steps:**

- [ ] `cd /home/butvinm/Dev/ppiav/models && uv run ruff check . && uv run mypy .` — clean.
- [ ] `cd /home/butvinm/Dev/ppiav && go vet ./... && go build ./...` — clean.

#### Task 12: Move plan to completed/

**Files:**

- Move: `docs/plans/20260514-orion-integration-training-compilation.md` → `docs/plans/completed/`. The companion `docs/plans/20260514-orion-integration-training-compilation/` directory (containing `setup.sh`) stays in place — paths in the moved markdown still resolve relative to the repo root.

**Steps:**

- [ ] `git mv docs/plans/20260514-orion-integration-training-compilation.md docs/plans/completed/`.
- [ ] Commit: `docs: move orion-integration plan to completed/`.

## Post-Completion

Run on target hardware before declaring Phase 2 fully closed. Each item is its own rent → run → capture → tear-down cycle, same lifecycle discipline as Tasks 5–9.

- **Full-epoch training on a GPU VPS** (`rtx4090-1.8.16.40`, ~16 GB RAM, 1× RTX 4090). Rent `ppiav-train-gpu`; run `python -m models.train --variant fhe --epochs 60 ...`; scp `weights_fhe.pth` back to local; tear down. Confirm test-set FPR / FNR / accuracy land within stochastic noise of c3ae-demo's documented table (`fhe overall n=3557: FPR 0.2085, FNR 0.0268, Acc 0.9421`). Expected wall-clock ~3 min on RTX 4090 vs ~30 min on the CPU box per Orion's 2026-05-09 measurement.
- **`logn16` compile + e2e on a 256 GB VPS** (`cpu.16.256.240`). Rent `ppiav-fhe-logn16`; rerun `setup.sh` (unchanged); scp the trained weights from local; run the compile + prepare_samples + ppiav-cli e2e chain with `--config logn16`. Compare `compile.json` peak RSS / wall-clock against c3ae-demo's table (`compile_s ≈ 387s`, `compile_peak_rss_GB ≈ 25.77`). Inference peak RSS expected ~114 GB per `~/Dev/orion/examples/c3ae-demo/README.md:181` — well under the 256 GB box.
- **Full per-step bench on the same logn16 VPS**: run each `ppiav-cli` subcommand (`keygen`, `encrypt-image`, `infer`, `mac`, `decrypt-result`, `verify-mac`) with `--n` matching the thesis bench budget. Confirm `results/phase2/<step>.json` all populate with `bench.Run` shape, then rsync back and tear down.
- **Cost-label commit**: in the post-completion commit, record total billed hours per VPS (training, logn15, logn16) so the experiment carries its own price tag, mirroring Orion's `2026-05-09-c3ae-vps-runs.md` §Task 5 footer.
- **Decide whether to commit a known-good `out/logn16/model.orion`** for cold-install convenience. Trade-off: ~MB binary in git vs. requiring every reader to retrain (stochastic; results vary slightly). Default: do not commit; document the build steps instead.
