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
from collections import Counter
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import numpy as np

from bench import _messages
from bench._labels_ru import (
    ACCURACY_METRIC_NAMES,
    KEY_LOCATION_NAMES,
    KEYGEN_ROUND_SUBSTEPS,
    PARTY_BY_STEP,
    PARTY_NAMES,
    PARTY_SHORT_NAMES,
    SECTION_HEADERS,
    STEP_NAMES,
    TABLE_HEADERS,
)
from bench._messages import (
    PER_IMAGE_STAGES,
    PER_IMAGE_STEPS,
    KeyInventoryRow,
    MessageBytesRow,
)
from bench.load import Run, Sample, iter_per_image_run_jsons, load_run

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

    img_dirs: list[Path] = []
    for entry in images:
        idx = int(entry["idx"])
        img_dir = batch_dir / f"img_{idx}"
        img_dir.mkdir(parents=True, exist_ok=True)
        img_dirs.append(img_dir)
        image_path = _resolve_image_path(manifest_dir, str(entry["path"]))
        _run_step(
            cli,
            "encrypt",
            [
                "--workdir",
                str(keys_dir),
                "--image",
                str(image_path),
                "--out-ct",
                str(img_dir / "input_ct.bin"),
                "--out",
                str(img_dir / "encrypt.json"),
            ],
            cwd=repo,
        )

    # Orion 2.1.5's LoadModel eagerly pre-encodes LinearTransformations
    # (~265s at LogN=16); amortize across the whole batch in one process.
    _run_step(
        cli,
        "infer-batch",
        [
            "--workdir",
            str(keys_dir),
            "--orion",
            str(orion_abs),
            "--image-dirs",
            ",".join(str(d) for d in img_dirs),
        ],
        cwd=repo,
    )

    for entry, img_dir in zip(images, img_dirs, strict=True):
        ref_logit = float(entry.get("ref_logit", 0.0))
        result_ct = img_dir / "result_ct.bin"
        auth_ct = img_dir / "auth_ct.bin"
        client_share = img_dir / "client_share.bin"
        decoded = img_dir / "decoded.json"
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
    """Collect per-image Samples bucketed by Sample.name across every image.

    The per-image JSON files are named by stage (``encrypt.json``, ``infer.json``,
    ``mac.json``, ``partial-decrypt.json``, ``finalize.json``), and each file
    contains one or more Samples whose ``name`` is the sub-step key (e.g.
    ``infer.exec``, ``mac.derive_auth_keys``). The bucket is keyed by Sample
    name so the per-party table can render one row per sub-step.

    Unknown Sample names (not in ``PER_IMAGE_STEPS``) raise loudly. A stale
    single-block ``Sample.name == "infer"`` from a partially-regenerated batch
    must not be silently absorbed under a non-catalog key.
    """
    allowed = set(PER_IMAGE_STEPS)
    bucket: dict[str, list[Sample]] = {step: [] for step in PER_IMAGE_STEPS}
    for _, img_dir in img_dirs:
        for stage in PER_IMAGE_STAGES:
            json_path = img_dir / f"{stage}.json"
            run = load_run(json_path)
            for sample in run.samples:
                if sample.name not in allowed:
                    raise ValueError(
                        f"{json_path}: unknown sample name {sample.name!r} "
                        f"(expected one of {sorted(allowed)})"
                    )
                bucket[sample.name].append(sample)
    return bucket


def _load_keygen_run(batch_dir: Path) -> Run:
    return load_run(batch_dir / "keygen.json")


def _per_message_bytes(
    batch_dir: Path, samples_by_name: dict[str, list[Sample]]
) -> list[MessageBytesRow]:
    """Per-message wire sizes driven by ``_messages.MESSAGES``.

    Each catalog entry resolves its size via ``resolve_message_bytes``. Missing
    files yield ``size=None`` (rendered as ``—``).
    """
    return [
        MessageBytesRow(
            message_id=msg.id,
            label_ru=msg.label_ru,
            sender=msg.sender,
            receiver=msg.receiver,
            size=_messages.resolve_message_bytes(msg, batch_dir, samples_by_name),
        )
        for msg in _messages.MESSAGES
    ]


def _key_inventory_rows(
    batch_dir: Path, samples_by_name: dict[str, list[Sample]]
) -> list[KeyInventoryRow]:
    """Resolve each KeyEntry in ``_messages.KEYS`` to a display row."""
    rows: list[KeyInventoryRow] = []
    for key in _messages.KEYS:
        size = _messages.resolve_key_bytes(key, batch_dir, samples_by_name)
        location_label = KEY_LOCATION_NAMES.get(key.location, key.location)
        on_wire_label = (
            TABLE_HEADERS["on_wire_yes"] if key.on_wire else TABLE_HEADERS["on_wire_no"]
        )
        rows.append(
            KeyInventoryRow(
                key_name=key.name,
                location=location_label,
                on_wire=on_wire_label,
                size=size,
            )
        )
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


def _classify_plain(manifest_by_idx: dict[int, dict[str, Any]]) -> dict[str, int | float]:
    """Cleartext baseline: apply ``m > 0 ? accept : reject`` to each ref_logit.

    No Auth gate exists in the plaintext flow, so ``unknown`` is always 0.
    Re-uses ``_classify`` for the confusion-matrix math so plain and FHE
    columns are computed by identical code paths.
    """
    verdicts: list[str] = []
    labels: list[int] = []
    for entry in manifest_by_idx.values():
        ref_logit = float(entry.get("ref_logit", 0.0))
        verdicts.append("accept" if ref_logit > 0 else "reject")
        labels.append(int(entry["label"]))
    return _classify(verdicts, labels)


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


def _format_with_prettier(path: Path) -> None:
    """Run prettier on a markdown file in place; no-op if prettier is absent."""
    if shutil.which("prettier") is None:
        logger.info("prettier not on PATH; summary.md left un-formatted")
        return
    proc = subprocess.run(
        ["prettier", "--write", "--prose-wrap", "preserve", str(path)],
        check=False,
        capture_output=True,
    )
    if proc.returncode != 0:
        logger.warning(
            "prettier exited %d on %s; stderr=%s",
            proc.returncode,
            path,
            proc.stderr.decode("utf-8", errors="replace"),
        )


def _format_seconds(seconds: float) -> str:
    """Compact human-readable wall-time for the network table.

    Steps through ms / s / min / h so the largest wire payload
    (``VAgentEvalKeyBundle`` = rlk + pk_top + gks_master) renders in the
    right unit at slow bandwidths.
    """
    if seconds < 1.0:
        return f"{seconds * 1000:.1f} ms"
    if seconds < 60.0:
        return f"{seconds:.2f} s"
    if seconds < 3600.0:
        return f"{seconds / 60.0:.2f} min"
    return f"{seconds / 3600.0:.2f} h"


def _party_step_table_md(
    keygen_run: Run,
    per_image: dict[str, list[Sample]],
) -> str:
    """Per-party table — every row attributes to exactly one party.

    Rows: per-party keygen sub-steps followed by per-image protocol steps.
    Joint round-level totals are rendered separately in ``_keygen_by_round_table_md``.
    """
    lines: list[str] = []
    header = (
        "| party | step | n | mean wall ms | p95 wall ms | mean delta RSS MiB | peak VM HWM MiB |"
    )
    lines.append(header)
    lines.append("|---|---|---:|---:|---:|---:|---:|")

    for substeps in KEYGEN_ROUND_SUBSTEPS.values():
        for substep in substeps:
            matching = [s for s in keygen_run.samples if s.name == substep]
            if not matching:
                continue
            mean, _p50, p95 = _wall_ms(matching)
            delta, hwm = _rss_stats(matching)
            n = len(matching)
            party = PARTY_NAMES[PARTY_BY_STEP[substep]]
            label = STEP_NAMES.get(substep, substep)
            lines.append(
                f"| {party} | {label} | {n} | "
                f"{_format_ms(mean)} | {_format_ms(p95)} | "
                f"{_format_mib(delta)} | {_format_mib(hwm)} |"
            )

    for step in PER_IMAGE_STEPS:
        samples = per_image.get(step, [])
        if not samples:
            continue
        mean, _p50, p95 = _wall_ms(samples)
        delta, hwm = _rss_stats(samples)
        n = len(samples)
        party = PARTY_NAMES[PARTY_BY_STEP.get(step, "client")]
        label = STEP_NAMES.get(step, step)
        lines.append(
            f"| {party} | {label} | {n} | "
            f"{_format_ms(mean)} | {_format_ms(p95)} | "
            f"{_format_mib(delta)} | {_format_mib(hwm)} |"
        )
    lines.append("")
    lines.append(
        "_delta RSS = vm_hwm - pre_vm_hwm = step's incremental memory "
        "growth. Peak VM HWM = high-water mark of the resident set at step "
        "exit. Keygen sub-steps share one process when run via "
        "`ppiav-cli keygen`, so each sub-step's pre_vm_hwm is the previous "
        "sub-step's vm_hwm; the delta is the marginal cost of that sub-step "
        "on top of the prior session state. Per-image steps each spawn a "
        "fresh process, so their delta RSS is the true per-call peak._"
    )
    return "\n".join(lines)


def _keygen_by_round_table_md(keygen_run: Run) -> str:
    """Round-level keygen table — joint rounds, no party column.

    Each row's wall = sum of its sub-step walls; VM HWM = max across the
    round's samples (peak resident set at any point during the round).
    """
    lines: list[str] = []
    lines.append("| round | n | total wall ms | peak VM HWM MiB |")
    lines.append("|---|---:|---:|---:|")
    for round_name, substeps in KEYGEN_ROUND_SUBSTEPS.items():
        round_label = STEP_NAMES.get(round_name, round_name)
        sub_samples = [s for s in keygen_run.samples if s.name in substeps]
        if not sub_samples:
            continue
        wall = sum(s.wall_ms for s in sub_samples)
        hwm = max(s.vm_hwm for s in sub_samples) / (1024.0 * 1024.0)
        n = max(Counter(s.name for s in sub_samples).values(), default=1)
        lines.append(f"| {round_label} | {n} | {_format_ms(wall)} | {_format_mib(hwm)} |")
    lines.append("")
    lines.append(
        "_Rounds execute bilaterally inside one `ppiav-cli keygen` process. "
        "Each row sums its per-party sub-step samples from the table above._"
    )
    return "\n".join(lines)


def _bytes_table_md(rows: Sequence[MessageBytesRow]) -> str:
    """Per-message bytes table keyed by catalog message_id."""
    empty = TABLE_HEADERS["empty"]
    header = (
        f"| {TABLE_HEADERS['message_id']} | {TABLE_HEADERS['message_label']} | "
        f"{TABLE_HEADERS['sender']} | {TABLE_HEADERS['receiver']} | "
        f"{TABLE_HEADERS['bytes']} | {TABLE_HEADERS['kib']} | {TABLE_HEADERS['mib']} |"
    )
    lines: list[str] = [header, "|---|---|---|---|---:|---:|---:|"]
    for r in rows:
        snd = PARTY_SHORT_NAMES.get(r.sender, r.sender)
        rcv = PARTY_SHORT_NAMES.get(r.receiver, r.receiver)
        if r.size is None:
            lines.append(
                f"| {r.message_id} | {r.label_ru} | {snd} | {rcv} | "
                f"{empty} | {empty} | {empty} |"
            )
        else:
            kib = r.size / 1024.0
            mib = r.size / (1024.0 * 1024.0)
            lines.append(
                f"| {r.message_id} | {r.label_ru} | {snd} | {rcv} | "
                f"{r.size} | {kib:.1f} | {mib:.2f} |"
            )
    lines.append("")
    lines.append(
        "_Note: lattigo-hierkeys ships a single compressed master atom set: "
        "`gks_master.bin` is the wire artifact (top-level MasterKey bundle) "
        "consumed by both VAgent (derives the auth-atom keys locally on `mac`) "
        "and VService (derives the inference rotation set on `infer`). "
        "`gks_infer.bin` is the per-target derived set VService caches locally — "
        "derivable from `gks_master.bin + pk_top.bin + params.json` but tens-of-GB "
        "at LogN=16, so cached on disk to avoid multi-minute per-sample re-derivation._"
    )
    return "\n".join(lines)


def _key_inventory_md(rows: Sequence[KeyInventoryRow]) -> str:
    """Key inventory table — every key, on-wire flag, serialized size."""
    empty = TABLE_HEADERS["empty"]
    header = (
        f"| {TABLE_HEADERS['key_name']} | {TABLE_HEADERS['key_location']} | "
        f"{TABLE_HEADERS['on_wire']} | {TABLE_HEADERS['bytes']} | "
        f"{TABLE_HEADERS['kib']} | {TABLE_HEADERS['mib']} |"
    )
    lines: list[str] = [header, "|---|---|---|---:|---:|---:|"]
    for r in rows:
        if r.size is None:
            lines.append(
                f"| {r.key_name} | {r.location} | {r.on_wire} | "
                f"{empty} | {empty} | {empty} |"
            )
        else:
            kib = r.size / 1024.0
            mib = r.size / (1024.0 * 1024.0)
            lines.append(
                f"| {r.key_name} | {r.location} | {r.on_wire} | "
                f"{r.size} | {kib:.1f} | {mib:.2f} |"
            )
    return "\n".join(lines)


def _network_table_md(rows: Sequence[MessageBytesRow]) -> str:
    """Per-message bytes / bandwidth → seconds at 1/10/100 Mbps, keyed by message_id."""
    empty = TABLE_HEADERS["empty"]
    head_cells = [TABLE_HEADERS["message_id"], TABLE_HEADERS["bytes"]] + [
        f"t @ {b} Mbps" for b in _BANDWIDTHS_MBPS
    ]
    lines: list[str] = []
    lines.append("| " + " | ".join(head_cells) + " |")
    lines.append("|" + "|".join(["---"] + ["---:"] * (len(head_cells) - 1)) + "|")
    for r in rows:
        if r.size is None:
            cells = [r.message_id, empty] + [empty] * len(_BANDWIDTHS_MBPS)
            lines.append("| " + " | ".join(cells) + " |")
            continue
        cells = [r.message_id, str(r.size)]
        for mbps in _BANDWIDTHS_MBPS:
            bps = mbps * 1_000_000 / 8.0
            cells.append(_format_seconds(r.size / bps))
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)


def _accuracy_compare_table_md(
    fhe_stats: dict[str, int | float],
    plain_stats: dict[str, int | float],
    n_total: int,
) -> str:
    """Side-by-side plain vs FHE confusion-matrix + rate table.

    Plaintext column has no Auth gate so ``unknown`` is always 0 there; the
    FHE column carries whatever the protocol reported. Rate rows (FPR/FNR/
    accuracy) render to three decimals.
    """
    metric_col = TABLE_HEADERS["metric"]
    plain_col = TABLE_HEADERS["plain_column"]
    fhe_col = TABLE_HEADERS["fhe_column"]

    def _cell(stats: dict[str, int | float], key: str) -> str:
        if key in ("fpr", "fnr", "accuracy"):
            return f"{float(stats[key]):.3f}"
        return str(int(stats[key]))

    rows: list[tuple[str, str, str]] = [
        (
            ACCURACY_METRIC_NAMES["samples"],
            str(n_total),
            str(n_total),
        ),
    ]
    for key in ("tp", "tn", "fp", "fn", "unknown", "fpr", "fnr", "accuracy"):
        rows.append(
            (
                ACCURACY_METRIC_NAMES[key],
                _cell(plain_stats, key),
                _cell(fhe_stats, key),
            )
        )

    lines: list[str] = []
    lines.append(f"| {metric_col} | {plain_col} | {fhe_col} |")
    lines.append("|---|---:|---:|")
    for name, plain_val, fhe_val in rows:
        lines.append(f"| {name} | {plain_val} | {fhe_val} |")
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
    """Render summary.md + plots/ from per-step JSONs + decoded.json in batch_dir."""
    batch_dir = Path(batch_dir).resolve()
    keygen_run = _load_keygen_run(batch_dir)
    img_dirs = _image_dirs(batch_dir)
    if not img_dirs:
        raise ValueError(f"{batch_dir}: no img_<idx>/ subdirs found")

    manifest_by_idx = _load_manifest_labels(batch_dir)
    per_image_samples = _load_step_runs(img_dirs)

    # Flat samples-by-name index spanning keygen Run + every per-image Run.
    # Drives both the message-bytes resolver and the key-inventory resolver.
    samples_by_name: dict[str, list[Sample]] = {}
    for s in keygen_run.samples:
        samples_by_name.setdefault(s.name, []).append(s)
    for _, img_dir in img_dirs:
        for json_path in iter_per_image_run_jsons(img_dir):
            run = load_run(json_path)
            for s in run.samples:
                samples_by_name.setdefault(s.name, []).append(s)

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

    bytes_rows = _per_message_bytes(batch_dir, samples_by_name)
    key_rows = _key_inventory_rows(batch_dir, samples_by_name)
    verdict_stats = _classify(verdicts, labels)
    plain_stats = _classify_plain(manifest_by_idx)
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
    sections.append("## Keygen by round (joint)")
    sections.append("")
    sections.append(_keygen_by_round_table_md(keygen_run))
    sections.append("")
    sections.append(f"## {SECTION_HEADERS['per_message_bytes']}")
    sections.append("")
    sections.append(_bytes_table_md(bytes_rows))
    sections.append("")
    sections.append(f"## {SECTION_HEADERS['key_inventory']}")
    sections.append("")
    sections.append(_key_inventory_md(key_rows))
    sections.append("")
    sections.append(f"## {SECTION_HEADERS['accuracy_plain_vs_fhe']}")
    sections.append("")
    sections.append(_accuracy_compare_table_md(verdict_stats, plain_stats, len(img_dirs)))
    sections.append("")
    sections.append("## Noise + SNR")
    sections.append("")
    sections.append(_noise_block_md(noise_stats, snr))
    sections.append("")
    sections.append(f"## {SECTION_HEADERS['network_wire_time']}")
    sections.append("")
    sections.append(_network_table_md(bytes_rows))
    sections.append("")

    summary_path = batch_dir / "summary.md"
    summary_path.write_text("\n".join(sections), encoding="utf-8")
    _format_with_prettier(summary_path)

    agg_data: dict[str, Any] = {
        "keygen_run": keygen_run,
        "per_image_samples": per_image_samples,
        "message_bytes_rows": bytes_rows,
        "verdict_stats": verdict_stats,
        "plain_stats": plain_stats,
        "snr": snr,
        "all_noise": all_noise,
        "bandwidths_mbps": _BANDWIDTHS_MBPS,
    }

    # Lazy import — keeps a broken matplotlib backend (e.g. missing system
    # libs on a minimal VPS image) from aborting the summary render.
    try:
        plots_eval = importlib.import_module("bench.plots_eval")
    except ImportError as exc:
        logger.warning("plots_eval unavailable: %s", exc)
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
