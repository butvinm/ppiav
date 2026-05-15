# bench/

Python driver + aggregator for the protocol evaluation pipeline. Chains the
six `ppiav-cli` subcommands (`keygen`, `encrypt`, `infer`, `mac`,
`partial-decrypt`, `finalize`) across a stratified UTKFace batch with a
single shared keygen, then aggregates per-step timing JSONs + decoded slot
vectors into `summary.md` + `plots/`.

## Quick start

Prerequisites: a compiled Orion model under `models/out/logn16/` and a
stratified input manifest produced by `models.prepare_samples`. See
`../models/README.md` for the training + compile + manifest flow.

```sh
cd bench
uv sync                                       # create venv + install deps
uv run pytest                                 # run unit tests
uv run ruff check .                           # lint
uv run mypy bench tests                       # strict type-check

# Drive the full pipeline across the 10-image batch.
uv run python -m bench.eval \
    --inputs ../models/out/eval_inputs.json \
    --orion  ../models/out/logn16
```

The driver creates `../results/phase2/eval-<UTC-ts>/`, runs `ppiav-cli keygen`
once into `keys/`, then iterates each image through encrypt → infer → mac →
partial-decrypt → finalize, and finally writes `summary.md` + `plots/`.

## Per-batch directory layout

```
results/phase2/eval-<UTC-ts>/
├── keys/
│   ├── pk.bin sk_c.bin sk_a.bin
│   ├── rlk.bin glk_master.bin glk_full.bin
│   ├── mac_key.bin sid.txt params.json
├── img_0/
│   ├── input_ct.bin result_ct.bin auth_ct.bin client_share.bin
│   ├── encrypt.json infer.json mac.json partial.json finalize.json
│   └── decoded.json            # verdict + ref_logit + slots_in_s + noise_per_slot
├── img_1/ ... img_9/
├── eval_inputs.json            # copy of the input manifest (self-contained batch dir)
├── keygen.json                 # per-round timing + RSS (one Run, five Samples)
├── summary.md                  # per-step timing / RSS / bytes / FPR-FNR / noise / SNR / network tables
└── plots/
    ├── e2e_timeline.png
    ├── rss_per_step.png
    ├── bytes_per_message.png
    ├── noise_histogram.png
    ├── snr_per_image.png
    ├── bandwidth_per_message.png
    └── session_timeline_10mbps.png
```

Per-step peak RSS is correct per-process now (each subcommand is a fresh
process); per-message byte sizes come straight from `os.Stat` on the on-disk
artifacts. See `docs/plans/completed/20260515-bench-eval-redesign.md` for
the design rationale.

## Layout

- `bench/eval.py` — driver + aggregator (`python -m bench.eval`).
- `bench/plots_eval.py` — 7 PNG generators called by the aggregator.
- `bench/load.py` — parse `Run`/`Sample` JSON into dataclasses; carries
  `pre_vm_hwm` so callers can compute `delta_rss_mib` (op-attributable RSS
  vs. process baseline).
- `bench/tables.py` — `render_tables(runs)` + `__main__` for ad-hoc table
  rendering against any `results/phaseN/` tree.
- `tests/fixtures/sample_run.json` — committed schema example.

## Heavy local tests

Round-trip tests under `internal/` that exercise `LogN=15` allocate enough
memory to OOM a 38 GB dev box. They are gated behind the environment
variable `PPIAV_RUN_HEAVY=1`. Default `go test ./...` runs the LogN=14
fast variants; CI and VPS runs export the flag.
