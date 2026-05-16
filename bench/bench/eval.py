"""Eval driver: chain `ppiav-cli` subcommands across a stratified batch.

Reads ``eval_inputs.json`` produced by ``models.prepare_samples``, runs one
keygen + per-image (encrypt -> infer -> mac -> partial-decrypt -> finalize)
sequence as subprocesses, and writes per-step bench JSONs + ciphertext
artifacts into ``results/<UTC-timestamp>/``.

Usage::

    python -m bench.eval --inputs models/out/eval_inputs.json \\
        --orion models/out/logn16 [--batch-dir results/custom]
    python -m bench.eval --aggregate-only results/<existing-batch>/

The `ppiav-cli` binary is resolved in order: ``./bin/ppiav-cli`` (built by
``make``), ``PATH`` lookup, ``go run ./cmd/ppiav-cli`` fallback. The driver
copies the manifest into ``<batch>/eval_inputs.json`` so the aggregator
needs only one path to reconstruct ground-truth labels + reference logits.
``aggregate`` post-processes the batch directory into ``summary.md`` +
``plots/*.png``; ``--aggregate-only`` skips the protocol run and just
re-renders the summary + plots from existing JSONs.
"""

from __future__ import annotations

import argparse
import datetime as dt
import importlib
import json
import logging
import shutil
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import numpy as np

from bench._labels_ru import PARTY_BY_STEP, PARTY_NAMES
from bench.load import Run, Sample, load_run

logger = logging.getLogger(__name__)


def _repo_root() -> Path:
    """Repo root inferred from this file's location (``bench/bench/eval.py``)."""
    return Path(__file__).resolve().parents[2]


def resolve_cli() -> list[str]:
    """Pick the ppiav-cli invocation form: prebuilt binary, PATH, or `go run`.

    Returns the argv prefix to which subcommand + flags are appended. The
    `go run` fallback keeps the driver usable on a fresh checkout where
    `make` has not been invoked, at the cost of per-invocation compile
    overhead (~1s/step at first call, cached afterwards).
    """
    root = _repo_root()
    local = root / "bin" / "ppiav-cli"
    if local.is_file():
        return [str(local)]
    path = shutil.which("ppiav-cli")
    if path:
        return [path]
    return ["go", "run", "./cmd/ppiav-cli"]


def _run_step(cli: Sequence[str], subcommand: str, args: Sequence[str], *, cwd: Path) -> None:
    """Invoke one ppiav-cli subcommand; fail fast on non-zero exit.

    The child inherits the parent's stdout + stderr (no capture_output), so
    the operator sees the underlying protocol failure (e.g. an `auth.Ver`
    rejection) streamed live to the terminal — not just a Python traceback
    after the fact.
    """
    argv: list[str] = [*cli, subcommand, *args]
    print(f"[bench.eval] {' '.join(argv)}", flush=True)
    proc = subprocess.run(argv, cwd=cwd, check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"ppiav-cli {subcommand} exited {proc.returncode}: {' '.join(argv)}")


def _load_manifest(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        data: dict[str, Any] = json.load(f)
    images = data.get("images")
    if not isinstance(images, list) or not images:
        raise ValueError(f"{path}: manifest has no images")
    return data


def _resolve_image_path(manifest_dir: Path, raw: str) -> Path:
    """Resolve a manifest image path relative to the ORIGINAL manifest's directory.

    `run_pipeline` copies the manifest into the batch dir for self-contained
    aggregation, but the copy retains the original (relative) paths. Image
    resolution happens here in `run_pipeline` against the original manifest
    dir before the copy is read for any path-bearing field; the aggregator
    only reads idx/label/ref_logit from the copy, so the copy's stale
    relative paths are not consulted at aggregate time.
    """
    p = Path(raw)
    if not p.is_absolute():
        p = (manifest_dir / raw).resolve()
    return p


def run_pipeline(
    inputs: Path,
    orion: Path,
    batch_dir: Path | None,
) -> Path:
    """Run keygen + per-image chain. Returns the resolved batch directory."""
    repo = _repo_root()
    manifest = _load_manifest(inputs)

    if batch_dir is None:
        ts = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
        batch_dir = repo / "results" / ts
    batch_dir = batch_dir.resolve()
    keys_dir = batch_dir / "keys"
    keys_dir.mkdir(parents=True, exist_ok=True)

    # Copy the manifest into the batch dir so `aggregate(batch_dir)` is
    # self-contained — labels + ref_logits round-trip without re-passing the
    # original `--inputs` path.
    shutil.copyfile(inputs, batch_dir / "eval_inputs.json")

    cli = resolve_cli()
    orion_abs = orion.resolve()

    # Keygen: bilateral handshake → keys/ + keygen.json at batch root.
    _run_step(
        cli,
        "keygen",
        [
            "--workdir",
            str(keys_dir),
            "--orion",
            str(orion_abs),
            "--out",
            str(batch_dir / "keygen.json"),
        ],
        cwd=repo,
    )

    manifest_dir = inputs.resolve().parent
    images: list[dict[str, Any]] = manifest["images"]
    for entry in images:
        idx = int(entry["idx"])
        img_dir = batch_dir / f"img_{idx}"
        img_dir.mkdir(parents=True, exist_ok=True)
        image_path = _resolve_image_path(manifest_dir, str(entry["path"]))
        ref_logit = float(entry.get("ref_logit", 0.0))

        input_ct = img_dir / "input_ct.bin"
        result_ct = img_dir / "result_ct.bin"
        auth_ct = img_dir / "auth_ct.bin"
        client_share = img_dir / "client_share.bin"
        decoded = img_dir / "decoded.json"

        _run_step(
            cli,
            "encrypt",
            [
                "--workdir",
                str(keys_dir),
                "--image",
                str(image_path),
                "--out-ct",
                str(input_ct),
                "--out",
                str(img_dir / "encrypt.json"),
            ],
            cwd=repo,
        )
        _run_step(
            cli,
            "infer",
            [
                "--workdir",
                str(keys_dir),
                "--orion",
                str(orion_abs),
                "--in-ct",
                str(input_ct),
                "--out-ct",
                str(result_ct),
                "--out",
                str(img_dir / "infer.json"),
            ],
            cwd=repo,
        )
        _run_step(
            cli,
            "mac",
            [
                "--workdir",
                str(keys_dir),
                "--in-ct",
                str(result_ct),
                "--out-ct",
                str(auth_ct),
                "--out",
                str(img_dir / "mac.json"),
            ],
            cwd=repo,
        )
        _run_step(
            cli,
            "partial-decrypt",
            [
                "--workdir",
                str(keys_dir),
                "--in-ct",
                str(auth_ct),
                "--out-share",
                str(client_share),
                "--out",
                str(img_dir / "partial-decrypt.json"),
            ],
            cwd=repo,
        )
        _run_step(
            cli,
            "finalize",
            [
                "--workdir",
                str(keys_dir),
                "--in-ct",
                str(auth_ct),
                "--in-share",
                str(client_share),
                "--ref-logit",
                repr(ref_logit),
                "--out-decoded",
                str(decoded),
                "--out",
                str(img_dir / "finalize.json"),
            ],
            cwd=repo,
        )

    aggregate(batch_dir)
    return batch_dir


# Protocol step order for the e2e per-image chain.
_PER_IMAGE_STEPS: tuple[str, ...] = (
    "encrypt",
    "infer",
    "mac",
    "partial-decrypt",
    "finalize",
)

# Keygen sub-step labels emitted by `ppiav-cli keygen` (see cmd/ppiav-cli/keygen.go).
_KEYGEN_SUBSTEPS: tuple[str, ...] = (
    "keygen.open",
    "keygen.pk",
    "keygen.rlk-r1",
    "keygen.rlk-r2",
    "keygen.galois",
)

# Network bandwidth points reported in the wire-time table (Mbps).
_BANDWIDTHS_MBPS: tuple[int, ...] = (1, 10, 100)


def _wall_ms(samples: Sequence[Sample]) -> tuple[float, float, float]:
    """Return (mean, p50, p95) wall ms across samples; zeros if empty."""
    if not samples:
        return 0.0, 0.0, 0.0
    arr = np.array([s.wall_ms for s in samples], dtype=np.float64)
    return float(arr.mean()), float(np.percentile(arr, 50)), float(np.percentile(arr, 95))


def _rss_stats(samples: Sequence[Sample]) -> tuple[float, float]:
    """Return (mean delta_rss MiB, mean vm_hwm MiB); zeros if empty."""
    if not samples:
        return 0.0, 0.0
    delta = np.array([s.delta_rss_mib for s in samples], dtype=np.float64)
    hwm = np.array([s.vm_hwm / (1024.0 * 1024.0) for s in samples], dtype=np.float64)
    return float(delta.mean()), float(hwm.mean())


def _format_ms(v: float) -> str:
    return f"{v:.2f}"


def _format_mib(v: float) -> str:
    return f"{v:.1f}"


def _load_manifest_labels(batch_dir: Path) -> dict[int, dict[str, Any]]:
    """Load the manifest copied into the batch dir; key by image idx.

    `aggregate` is invoked with only `batch_dir`, so we expect `run_pipeline`
    to have copied the original `eval_inputs.json` here. If that file is
    missing we surface the same error a missing decoded.json would.
    """
    path = batch_dir / "eval_inputs.json"
    if not path.is_file():
        raise FileNotFoundError(
            f"{path}: manifest missing; did run_pipeline copy eval_inputs.json into the batch dir?"
        )
    with path.open("r", encoding="utf-8") as f:
        data: dict[str, Any] = json.load(f)
    by_idx: dict[int, dict[str, Any]] = {}
    for entry in data.get("images", []):
        by_idx[int(entry["idx"])] = entry
    return by_idx


def _image_dirs(batch_dir: Path) -> list[tuple[int, Path]]:
    """Discover `img_<idx>` subdirectories, sorted by idx for deterministic output."""
    out: list[tuple[int, Path]] = []
    for child in batch_dir.iterdir():
        if not child.is_dir() or not child.name.startswith("img_"):
            continue
        try:
            idx = int(child.name.removeprefix("img_"))
        except ValueError:
            continue
        out.append((idx, child))
    out.sort(key=lambda t: t[0])
    return out


def _load_step_runs(
    img_dirs: Sequence[tuple[int, Path]],
) -> dict[str, list[Sample]]:
    """For each per-image step, collect one bench Sample per image."""
    bucket: dict[str, list[Sample]] = {step: [] for step in _PER_IMAGE_STEPS}
    for _, img_dir in img_dirs:
        for step in _PER_IMAGE_STEPS:
            run = load_run(img_dir / f"{step}.json")
            # Each per-step JSON contains exactly one Sample for that step.
            # If the producer ever appends multiple iterations we still
            # aggregate them flat — that's the correct behaviour for a
            # re-run with iter>0.
            bucket[step].extend(run.samples)
    return bucket


def _load_keygen_run(batch_dir: Path) -> Run:
    return load_run(batch_dir / "keygen.json")


def _per_message_bytes(batch_dir: Path) -> list[tuple[str, int]]:
    """Per-message wire sizes for the bytes / bandwidth tables and Gantt.

    Tries the on-disk `.bin` artifacts first (canonical source: stat the
    files in `keys/` and `img_0/`). When those have been pruned (e.g. the
    batch was rsynced with `--exclude '*.bin'` to strip secret material
    before commit), falls back to the persisted `bytes.json` written by
    a prior aggregate call. If neither is available the table is empty.
    """
    bytes_json = batch_dir / "bytes.json"
    rows: list[tuple[str, int]] = []
    has_bin = False
    keys_dir = batch_dir / "keys"
    if keys_dir.is_dir():
        for path in sorted(keys_dir.iterdir()):
            if not path.is_file():
                continue
            rows.append((f"keys/{path.name}", path.stat().st_size))
            if path.name.endswith(".bin"):
                has_bin = True
    img_dirs = _image_dirs(batch_dir)
    if img_dirs:
        _, first = img_dirs[0]
        for path in sorted(first.iterdir()):
            if not path.is_file() or path.name.endswith(".json"):
                continue
            rows.append((f"img/{path.name}", path.stat().st_size))
            if path.name.endswith(".bin"):
                has_bin = True

    # Persist the cache only when the on-disk picture is "full" (at least
    # one .bin observed). This keeps replot-from-bin-stripped working
    # against an authoritative cache from the original VPS run.
    if has_bin:
        with bytes_json.open("w", encoding="utf-8") as f:
            json.dump([{"name": n, "bytes": b} for n, b in rows], f, indent=2)
        return rows

    # Cache wins over partial on-disk view (no .bin present).
    if bytes_json.is_file():
        with bytes_json.open("r", encoding="utf-8") as f:
            cached: list[dict[str, Any]] = json.load(f)
        return [(str(e["name"]), int(e["bytes"])) for e in cached]
    return rows


def _classify(verdicts: list[str], labels: list[int]) -> dict[str, int | float]:
    """Compute FPR / FNR / accuracy + counts; unknowns reported separately."""
    if len(verdicts) != len(labels):
        raise ValueError(f"verdicts/labels length mismatch: {len(verdicts)} vs {len(labels)}")
    fp = fn = tp = tn = unk = 0
    for v, lab in zip(verdicts, labels, strict=True):
        if v == "unknown":
            unk += 1
            continue
        predict_accept = v == "accept"
        if lab == 1 and predict_accept:
            tp += 1
        elif lab == 1 and not predict_accept:
            fn += 1
        elif lab == 0 and predict_accept:
            fp += 1
        else:
            tn += 1
    n_pos = tp + fn
    n_neg = fp + tn
    decided = tp + tn + fp + fn
    fpr = fp / n_neg if n_neg else 0.0
    fnr = fn / n_pos if n_pos else 0.0
    accuracy = (tp + tn) / decided if decided else 0.0
    return {
        "tp": tp,
        "fn": fn,
        "fp": fp,
        "tn": tn,
        "unknown": unk,
        "fpr": fpr,
        "fnr": fnr,
        "accuracy": accuracy,
    }


def _noise_stats(noise: Sequence[float]) -> dict[str, float]:
    if not noise:
        return {"n": 0, "mean": 0.0, "min": 0.0, "max": 0.0, "std": 0.0}
    arr = np.array(noise, dtype=np.float64)
    return {
        "n": int(arr.size),
        "mean": float(arr.mean()),
        "min": float(arr.min()),
        "max": float(arr.max()),
        "std": float(arr.std(ddof=0)),
    }


def _snr_per_image(
    img_dirs: Sequence[tuple[int, Path]],
    decoded: dict[int, dict[str, Any]],
) -> list[tuple[int, float, float]]:
    """For each image, compute SNR = |ref_logit| / std(noise_per_slot).

    Returns (idx, snr, ref_logit_abs). When std == 0 (degenerate) SNR is inf;
    we surface that as a positive sentinel value rather than NaN so the
    summary table and plot remain readable.
    """
    out: list[tuple[int, float, float]] = []
    for idx, _ in img_dirs:
        d = decoded.get(idx)
        if d is None:
            continue
        ref = float(d.get("ref_logit", 0.0))
        noise = d.get("noise_per_slot") or []
        if not noise:
            continue
        std = float(np.std(np.asarray(noise, dtype=np.float64), ddof=0)) if len(noise) > 1 else 0.0
        ref_abs = abs(ref)
        snr = ref_abs / std if std > 0 else float("inf")
        out.append((idx, snr, ref_abs))
    return out


def _format_seconds(seconds: float) -> str:
    """Compact human-readable wall-time for the network table.

    Reports up to days because glk_full.bin transfers at 1 Mbps land in the
    tens-of-hours range; formatting it as minutes hides the scale.
    """
    if seconds < 1.0:
        return f"{seconds * 1000:.1f} ms"
    if seconds < 60.0:
        return f"{seconds:.2f} s"
    if seconds < 3600.0:
        return f"{seconds / 60.0:.2f} min"
    if seconds < 86400.0:
        return f"{seconds / 3600.0:.2f} h"
    return f"{seconds / 86400.0:.2f} d"


def _party_step_table_md(
    keygen_run: Run,
    per_image: dict[str, list[Sample]],
) -> str:
    """Single combined table: party | step | n | wall ms | ΔRSS MiB | peak VM HWM MiB.

    Keygen sub-rounds run inside one bilateral process, so they're labelled
    "joint". The per-image steps each run as a fresh subprocess on exactly
    one party (see PARTY_BY_STEP in bench/_labels_ru.py).
    """
    lines: list[str] = []
    header = (
        "| party | step | n | mean wall ms | p95 wall ms | mean delta RSS MiB | peak VM HWM MiB |"
    )
    lines.append(header)
    lines.append("|---|---|---:|---:|---:|---:|---:|")

    keygen_total_ms = sum(s.wall_ms for s in keygen_run.samples)
    joint = PARTY_NAMES["joint"]
    total_row = f"| {joint} | keygen (total) | 1 | {_format_ms(keygen_total_ms)} | - | - | - |"
    lines.append(total_row)
    for substep in _KEYGEN_SUBSTEPS:
        matching = [s for s in keygen_run.samples if s.name == substep]
        mean, _p50, p95 = _wall_ms(matching)
        delta, hwm = _rss_stats(matching)
        n = len(matching)
        party = PARTY_NAMES[PARTY_BY_STEP.get(substep, "joint")]
        lines.append(
            f"| {party} | &nbsp;&nbsp;{substep} | {n} | "
            f"{_format_ms(mean)} | {_format_ms(p95)} | "
            f"{_format_mib(delta)} | {_format_mib(hwm)} |"
        )

    for step in _PER_IMAGE_STEPS:
        samples = per_image.get(step, [])
        mean, _p50, p95 = _wall_ms(samples)
        delta, hwm = _rss_stats(samples)
        n = len(samples)
        party = PARTY_NAMES[PARTY_BY_STEP.get(step, "joint")]
        lines.append(
            f"| {party} | {step} | {n} | "
            f"{_format_ms(mean)} | {_format_ms(p95)} | "
            f"{_format_mib(delta)} | {_format_mib(hwm)} |"
        )
    lines.append("")
    lines.append(
        "_delta RSS = vm_hwm - pre_vm_hwm = the step's incremental memory "
        "growth. Peak VM HWM = high-water mark of the resident set at step "
        "exit. Keygen sub-rounds share one process, so each row's "
        "pre_vm_hwm is the previous row's vm_hwm; the delta for "
        "`keygen.galois` is the marginal cost of the Galois-key round on "
        "top of the prior PK + RLK state. Per-image steps each spawn a "
        "fresh process, so their delta RSS is the true per-call peak._"
    )
    return "\n".join(lines)


def _bytes_table_md(rows: Sequence[tuple[str, int]]) -> str:
    lines: list[str] = []
    lines.append("| message | bytes | KiB | MiB |")
    lines.append("|---|---:|---:|---:|")
    for name, size in rows:
        kib = size / 1024.0
        mib = size / (1024.0 * 1024.0)
        lines.append(f"| {name} | {size} | {kib:.1f} | {mib:.2f} |")
    lines.append("")
    lines.append(
        "_Note: `glk_master.bin` and `glk_full.bin` are byte-identical today; "
        "they diverge after lattigo-hierkeys integration (master = compressed seed, "
        "full = expanded set)._"
    )
    return "\n".join(lines)


def _network_table_md(rows: Sequence[tuple[str, int]]) -> str:
    """Per-message bytes / bandwidth → seconds at 1/10/100 Mbps."""
    lines: list[str] = []
    head_cells = ["message", "bytes"] + [f"t @ {b} Mbps" for b in _BANDWIDTHS_MBPS]
    lines.append("| " + " | ".join(head_cells) + " |")
    lines.append("|" + "|".join(["---"] + ["---:"] * (len(head_cells) - 1)) + "|")
    for name, size in rows:
        # Mbps == 1e6 bits / sec; 1 byte = 8 bits → bytes_per_sec = mbps * 1e6 / 8.
        cells = [name, str(size)]
        for mbps in _BANDWIDTHS_MBPS:
            bps = mbps * 1_000_000 / 8.0
            cells.append(_format_seconds(size / bps))
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)


def _verdict_table_md(stats: dict[str, int | float], n_total: int) -> str:
    lines: list[str] = []
    lines.append("| metric | value |")
    lines.append("|---|---:|")
    lines.append(f"| samples (total) | {n_total} |")
    lines.append(f"| true positives | {stats['tp']} |")
    lines.append(f"| true negatives | {stats['tn']} |")
    lines.append(f"| false positives | {stats['fp']} |")
    lines.append(f"| false negatives | {stats['fn']} |")
    lines.append(f"| unknown | {stats['unknown']} |")
    lines.append(f"| FPR | {float(stats['fpr']):.3f} |")
    lines.append(f"| FNR | {float(stats['fnr']):.3f} |")
    lines.append(f"| accuracy | {float(stats['accuracy']):.3f} |")
    return "\n".join(lines)


def _noise_block_md(noise_stats: dict[str, float], snr: list[tuple[int, float, float]]) -> str:
    lines: list[str] = []
    lines.append("**Noise across all (image x non-S slot) pairs:**")
    lines.append("")
    lines.append("| stat | value |")
    lines.append("|---|---:|")
    lines.append(f"| samples | {int(noise_stats['n'])} |")
    lines.append(f"| mean | {noise_stats['mean']:.6f} |")
    lines.append(f"| min | {noise_stats['min']:.6f} |")
    lines.append(f"| max | {noise_stats['max']:.6f} |")
    lines.append(f"| std | {noise_stats['std']:.6f} |")
    lines.append("")
    lines.append("**SNR per image** (`|ref_logit| / std(noise_per_slot_i)`):")
    lines.append("")
    lines.append("| idx | \\|ref_logit\\| | SNR |")
    lines.append("|---:|---:|---:|")
    for idx, snr_v, ref_abs in snr:
        snr_str = "inf" if snr_v == float("inf") else f"{snr_v:.2f}"
        lines.append(f"| {idx} | {ref_abs:.4f} | {snr_str} |")
    return "\n".join(lines)


def aggregate(batch_dir: Path) -> None:
    """Aggregate per-step JSONs + decoded.json into summary.md + plots/.

    Layout produced by Task 13's `run_pipeline`:

    - `<batch>/keygen.json` — single bench Run with five `keygen.*` Samples
    - `<batch>/eval_inputs.json` — copy of the manifest with idx/label/ref_logit
    - `<batch>/img_<idx>/{encrypt,infer,mac,partial-decrypt,finalize}.json` — per-step Runs
    - `<batch>/img_<idx>/decoded.json` — verdict + noise vector
    - `<batch>/keys/*.bin` and `<batch>/img_<idx>/*.bin` — wire-format artifacts

    Writes `<batch>/summary.md` and then defers to `plots_eval.write_plots`
    (Task 15). The plot module is imported lazily so Task 14 lands first;
    once Task 15 is in place the warning disappears.
    """
    batch_dir = Path(batch_dir).resolve()
    keygen_run = _load_keygen_run(batch_dir)
    img_dirs = _image_dirs(batch_dir)
    if not img_dirs:
        raise ValueError(f"{batch_dir}: no img_<idx>/ subdirs found")

    manifest_by_idx = _load_manifest_labels(batch_dir)
    per_image_samples = _load_step_runs(img_dirs)

    # Decoded payloads keyed by idx for the noise + verdict tables.
    decoded_by_idx: dict[int, dict[str, Any]] = {}
    verdicts: list[str] = []
    labels: list[int] = []
    all_noise: list[float] = []
    for idx, img_dir in img_dirs:
        with (img_dir / "decoded.json").open("r", encoding="utf-8") as f:
            d: dict[str, Any] = json.load(f)
        decoded_by_idx[idx] = d
        verdicts.append(str(d.get("verdict", "unknown")))
        entry = manifest_by_idx.get(idx)
        if entry is None:
            raise ValueError(f"manifest missing entry for idx={idx}")
        labels.append(int(entry["label"]))
        for v in d.get("noise_per_slot", []):
            all_noise.append(float(v))

    bytes_rows = _per_message_bytes(batch_dir)
    verdict_stats = _classify(verdicts, labels)
    noise_stats = _noise_stats(all_noise)
    snr = _snr_per_image(img_dirs, decoded_by_idx)

    sections: list[str] = []
    sections.append(f"# Eval summary — {batch_dir.name}")
    sections.append("")
    sections.append(f"- batch dir: `{batch_dir}`")
    sections.append(f"- images: {len(img_dirs)}")
    sections.append(f"- keygen samples: {len(keygen_run.samples)}")
    sections.append("")
    sections.append("## Per-step time + memory by party")
    sections.append("")
    sections.append(_party_step_table_md(keygen_run, per_image_samples))
    sections.append("")
    sections.append("## Per-message bytes")
    sections.append("")
    sections.append(_bytes_table_md(bytes_rows))
    sections.append("")
    sections.append("## Protocol verdict accuracy")
    sections.append("")
    sections.append(_verdict_table_md(verdict_stats, len(img_dirs)))
    sections.append("")
    sections.append("## Noise + SNR")
    sections.append("")
    sections.append(_noise_block_md(noise_stats, snr))
    sections.append("")
    sections.append("## Network wire time")
    sections.append("")
    sections.append(_network_table_md(bytes_rows))
    sections.append("")

    summary_path = batch_dir / "summary.md"
    summary_path.write_text("\n".join(sections), encoding="utf-8")

    agg_data: dict[str, Any] = {
        "batch_dir": str(batch_dir),
        "keygen_run": keygen_run,
        "per_image_samples": per_image_samples,
        "bytes_rows": bytes_rows,
        "verdict_stats": verdict_stats,
        "noise_stats": noise_stats,
        "snr": snr,
        "all_noise": all_noise,
        "decoded_by_idx": decoded_by_idx,
        "manifest_by_idx": manifest_by_idx,
        "image_indices": [idx for idx, _ in img_dirs],
        "bandwidths_mbps": _BANDWIDTHS_MBPS,
        "per_image_steps": _PER_IMAGE_STEPS,
        "keygen_substeps": _KEYGEN_SUBSTEPS,
    }

    # Lazy import so Task 14 lands without depending on Task 15. Once
    # `plots_eval` exists the warning disappears naturally. importlib (not a
    # `from bench import plots_eval`) keeps mypy from failing the module-level
    # symbol check before Task 15 adds the file.
    try:
        plots_eval = importlib.import_module("bench.plots_eval")
    except ImportError as exc:
        logger.warning("plots_eval unavailable (Task 15 not landed yet): %s", exc)
        return
    plots_eval.write_plots(batch_dir, agg_data)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="bench.eval",
        description="Chain ppiav-cli subcommands across a stratified eval batch.",
    )
    parser.add_argument(
        "--inputs",
        type=Path,
        default=None,
        help=(
            "Path to eval_inputs.json produced by models.prepare_samples "
            "(required unless --aggregate-only)."
        ),
    )
    parser.add_argument(
        "--orion",
        type=Path,
        default=None,
        help="Path to Orion compiled-model directory (required unless --aggregate-only).",
    )
    parser.add_argument(
        "--batch-dir",
        type=Path,
        default=None,
        help="Override per-batch output dir (default results/<UTC ts>/).",
    )
    parser.add_argument(
        "--aggregate-only",
        type=Path,
        default=None,
        metavar="BATCH_DIR",
        help="Skip the protocol run; re-render summary.md + plots/ from JSONs in BATCH_DIR.",
    )
    args = parser.parse_args(argv[1:])

    if args.aggregate_only is not None:
        try:
            aggregate(args.aggregate_only)
        except (RuntimeError, FileNotFoundError, ValueError) as exc:
            print(f"[bench.eval] aggregate error: {exc}", file=sys.stderr)
            return 1
        print(f"[bench.eval] aggregate complete: {args.aggregate_only}")
        return 0

    if args.inputs is None or args.orion is None:
        parser.error("--inputs and --orion are required unless --aggregate-only is given")

    try:
        batch_dir = run_pipeline(args.inputs, args.orion, args.batch_dir)
    except (RuntimeError, FileNotFoundError, ValueError) as exc:
        print(f"[bench.eval] error: {exc}", file=sys.stderr)
        return 1

    print(f"[bench.eval] batch complete: {batch_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
