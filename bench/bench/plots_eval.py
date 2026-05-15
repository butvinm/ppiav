"""Plot generation for the eval batch.

`write_plots(batch_dir, agg_data)` is invoked at the tail end of
`bench.eval.aggregate` (Task 14) and writes seven PNGs into
``<batch>/plots/``. The function is intentionally tolerant of empty
buckets (degenerate runs still produce a plots/ dir with whatever data
exists) so a partial pipeline failure still leaves human-readable
artifacts.

Inputs (consumed from `agg_data`; shape matches what `eval.aggregate`
builds):

- `keygen_run` — `bench.load.Run` for the keygen handshake; samples named
  ``keygen.open`` / ``keygen.pk`` / ``keygen.rlk-r1`` / ``keygen.rlk-r2`` /
  ``keygen.galois``.
- `per_image_samples` — `dict[str, list[Sample]]` keyed by per-image step
  (``encrypt`` / ``infer`` / ``mac`` / ``partial-decrypt`` / ``finalize``).
- `bytes_rows` — `list[tuple[str, int]]` of every artifact's wire size,
  prefixed with ``keys/`` or ``img/``.
- `all_noise` — flattened noise samples across (image x non-S slot) pairs.
- `snr` — `list[tuple[idx, snr, ref_logit_abs)]`, one entry per image.
- `bandwidths_mbps` — bandwidth axis for the per-message bandwidth plot.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")  # headless backend; must be set before importing pyplot.

import matplotlib.pyplot as plt
import numpy as np

from bench.load import Run, Sample

# Macro-phase color palette. Setup = blue, inference = orange, verify = green.
# Picked to render legibly both on screen and printed (high contrast pairs).
_COLOR_SETUP = "#1f77b4"
_COLOR_INFER = "#ff7f0e"
_COLOR_VERIFY = "#2ca02c"

# Compute-step ordering for the e2e timeline (matches protocol order).
_KEYGEN_SUBSTEPS: tuple[str, ...] = (
    "keygen.open",
    "keygen.pk",
    "keygen.rlk-r1",
    "keygen.rlk-r2",
    "keygen.galois",
)
_PER_IMAGE_STEPS: tuple[str, ...] = (
    "encrypt",
    "infer",
    "mac",
    "partial-decrypt",
    "finalize",
)

# Phase grouping: which macro-phase each step belongs to.
_PHASE_SETUP: frozenset[str] = frozenset(_KEYGEN_SUBSTEPS)
_PHASE_INFER: frozenset[str] = frozenset({"encrypt", "infer"})
_PHASE_VERIFY: frozenset[str] = frozenset({"mac", "partial-decrypt", "finalize"})


def _phase_color(step: str) -> str:
    if step in _PHASE_SETUP:
        return _COLOR_SETUP
    if step in _PHASE_INFER:
        return _COLOR_INFER
    if step in _PHASE_VERIFY:
        return _COLOR_VERIFY
    # Unknown step — render in grey rather than crashing.
    return "#888888"


def _mean_wall_ms(samples: Sequence[Sample]) -> float:
    if not samples:
        return 0.0
    return float(np.mean([s.wall_ms for s in samples]))


def _mean_delta_rss_mib(samples: Sequence[Sample]) -> float:
    if not samples:
        return 0.0
    return float(np.mean([s.delta_rss_mib for s in samples]))


def _keygen_samples_by_name(keygen_run: Run) -> dict[str, list[Sample]]:
    bucket: dict[str, list[Sample]] = {name: [] for name in _KEYGEN_SUBSTEPS}
    for s in keygen_run.samples:
        bucket.setdefault(s.name, []).append(s)
    return bucket


def _ordered_steps_and_means(
    keygen_run: Run,
    per_image: dict[str, list[Sample]],
) -> list[tuple[str, float]]:
    """Return ordered `(step, mean_ms)` for keygen substeps + per-image steps."""
    out: list[tuple[str, float]] = []
    keygen_bucket = _keygen_samples_by_name(keygen_run)
    for name in _KEYGEN_SUBSTEPS:
        out.append((name, _mean_wall_ms(keygen_bucket.get(name, []))))
    for step in _PER_IMAGE_STEPS:
        out.append((step, _mean_wall_ms(per_image.get(step, []))))
    return out


def _plot_e2e_timeline(path: Path, ordered: Sequence[tuple[str, float]]) -> None:
    """Horizontal Gantt of one mean e2e session, compute-only."""
    fig, ax = plt.subplots(figsize=(11, 3.2))
    x = 0.0
    for step, ms in ordered:
        color = _phase_color(step)
        ax.barh(0, ms, left=x, height=0.6, color=color, edgecolor="white", linewidth=0.5)
        if ms > 0:
            label_x = x + ms / 2.0
            ax.text(
                label_x,
                0,
                step,
                ha="center",
                va="center",
                fontsize=7,
                rotation=0,
                color="white" if ms > 5 else "black",
            )
        x += ms
    ax.set_yticks([])
    ax.set_xlabel("wall time (ms)")
    ax.set_title("E2E timeline (mean compute, one session)")
    _set_phase_legend(ax)
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)


def _set_phase_legend(ax: Any) -> None:
    from matplotlib.patches import Patch

    handles = [
        Patch(facecolor=_COLOR_SETUP, label="setup (keygen)"),
        Patch(facecolor=_COLOR_INFER, label="inference (encrypt/infer)"),
        Patch(facecolor=_COLOR_VERIFY, label="verify (mac/partial/finalize)"),
    ]
    ax.legend(handles=handles, loc="upper right", fontsize=8, framealpha=0.9)


def _plot_rss_per_step(
    path: Path,
    keygen_run: Run,
    per_image: dict[str, list[Sample]],
) -> None:
    """Bar chart, mean delta RSS MiB per step."""
    labels: list[str] = []
    values: list[float] = []
    colors: list[str] = []
    keygen_bucket = _keygen_samples_by_name(keygen_run)
    for name in _KEYGEN_SUBSTEPS:
        labels.append(name)
        values.append(_mean_delta_rss_mib(keygen_bucket.get(name, [])))
        colors.append(_phase_color(name))
    for step in _PER_IMAGE_STEPS:
        labels.append(step)
        values.append(_mean_delta_rss_mib(per_image.get(step, [])))
        colors.append(_phase_color(step))

    fig, ax = plt.subplots(figsize=(10, 4.5))
    xs = np.arange(len(labels))
    ax.bar(xs, values, color=colors)
    ax.set_xticks(xs)
    ax.set_xticklabels(labels, rotation=35, ha="right", fontsize=8)
    ax.set_ylabel("mean delta RSS (MiB)")
    ax.set_title("Per-step memory delta (vm_hwm - pre_vm_hwm)")
    _set_phase_legend(ax)
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)


def _plot_bytes_per_message(path: Path, bytes_rows: Sequence[tuple[str, int]]) -> None:
    """Bar chart, log y, one bar per message."""
    if not bytes_rows:
        # Render an empty axes so the plots/ dir is still complete.
        fig, ax = plt.subplots(figsize=(6, 3))
        ax.set_title("bytes per message (no artifacts)")
        fig.tight_layout()
        fig.savefig(path, dpi=120)
        plt.close(fig)
        return

    names = [name for name, _ in bytes_rows]
    sizes = [max(size, 1) for _, size in bytes_rows]  # log axis can't take 0
    fig, ax = plt.subplots(figsize=(11, 5))
    xs = np.arange(len(names))
    ax.bar(xs, sizes, color="#4c78a8")
    ax.set_yscale("log")
    ax.set_xticks(xs)
    ax.set_xticklabels(names, rotation=45, ha="right", fontsize=7)
    ax.set_ylabel("bytes (log scale)")
    ax.set_title("Per-message wire size")
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)


def _plot_noise_histogram(path: Path, noise: Sequence[float]) -> None:
    """Histogram of flattened noise samples across all (image x slot) pairs."""
    fig, ax = plt.subplots(figsize=(8, 4.5))
    if noise:
        arr = np.asarray(noise, dtype=np.float64)
        # 60 bins reads well for thousands of samples without aliasing.
        ax.hist(arr, bins=60, color="#5f9ea0", edgecolor="white", linewidth=0.3)
        ax.set_xlabel("noise (decoded slot - ref_logit)")
        ax.set_ylabel("count")
    else:
        ax.set_xlabel("noise (no samples)")
    ax.set_title("Noise distribution across (image x non-S slot) pairs")
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)


def _plot_snr_per_image(path: Path, snr: Sequence[tuple[int, float, float]]) -> None:
    """Strip plot of one dot per image's SNR."""
    fig, ax = plt.subplots(figsize=(7, 4.5))
    if snr:
        # Replace +inf SNR (zero-std degenerate) with the max finite + 20%
        # so the dot is visible at the top of the y-axis rather than off-screen.
        finite = [v for _, v, _ in snr if np.isfinite(v)]
        sentinel = max(finite) * 1.2 if finite else 1.0
        ys = [v if np.isfinite(v) else sentinel for _, v, _ in snr]
        # Single-category x-axis: all points at x=0 with small jitter for
        # readability when SNRs cluster.
        rng = np.random.default_rng(seed=0)
        xs = rng.uniform(-0.15, 0.15, size=len(ys))
        ax.scatter(xs, ys, s=64, alpha=0.85, color=_COLOR_INFER, edgecolors="black")
        for x, y, (idx, _, _) in zip(xs, ys, snr, strict=True):
            ax.annotate(str(idx), (x, y), textcoords="offset points", xytext=(6, 0), fontsize=7)
        ax.set_xticks([0])
        ax.set_xticklabels(["images"])
        ax.set_xlim(-0.5, 0.5)
        ax.set_ylabel("SNR = |ref_logit| / std(noise_per_slot)")
    else:
        ax.set_xlabel("(no images)")
    ax.set_title("SNR per image")
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)


def _plot_bandwidth_per_message(
    path: Path,
    bytes_rows: Sequence[tuple[str, int]],
    bandwidths_mbps: Sequence[int],
) -> None:
    """Grouped bar chart: three bars (1/10/100 Mbps) per message."""
    if not bytes_rows or not bandwidths_mbps:
        fig, ax = plt.subplots(figsize=(6, 3))
        ax.set_title("bandwidth per message (no data)")
        fig.tight_layout()
        fig.savefig(path, dpi=120)
        plt.close(fig)
        return

    names = [name for name, _ in bytes_rows]
    sizes = np.array([size for _, size in bytes_rows], dtype=np.float64)
    n_msgs = len(names)
    n_bw = len(bandwidths_mbps)
    width = 0.8 / n_bw

    fig, ax = plt.subplots(figsize=(12, 5))
    xs = np.arange(n_msgs)
    cmap = plt.get_cmap("viridis")
    for i, mbps in enumerate(bandwidths_mbps):
        bps = mbps * 1_000_000 / 8.0  # bytes per second
        seconds = sizes / bps
        offset = (i - (n_bw - 1) / 2) * width
        ax.bar(
            xs + offset,
            seconds,
            width=width,
            label=f"{mbps} Mbps",
            color=cmap(i / max(n_bw - 1, 1)),
        )
    ax.set_yscale("log")
    ax.set_xticks(xs)
    ax.set_xticklabels(names, rotation=45, ha="right", fontsize=7)
    ax.set_ylabel("transfer time (s, log scale)")
    ax.set_title("Per-message transfer time at 1 / 10 / 100 Mbps")
    ax.legend(loc="upper right", fontsize=8)
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)


# Mapping from compute step to the primary on-the-wire artifact name(s) it
# emits. Names match the `keys/...` / `img/...` prefix used in
# `bench.eval._per_message_bytes`. Steps without an emitted artifact (e.g.
# `keygen.open` is bookkeeping handshake setup) map to an empty tuple — they
# get zero transfer width on the timeline.
_STEP_TO_ARTIFACT: dict[str, tuple[str, ...]] = {
    "keygen.open": ("keys/sid.txt", "keys/params.json"),
    "keygen.pk": ("keys/pk.bin",),
    "keygen.rlk-r1": (),
    "keygen.rlk-r2": ("keys/rlk.bin",),
    "keygen.galois": ("keys/glk_full.bin",),
    "encrypt": ("img/input_ct.bin",),
    "infer": ("img/result_ct.bin",),
    "mac": ("img/auth_ct.bin",),
    "partial-decrypt": ("img/client_share.bin",),
    "finalize": (),
}


def _transfer_ms_for_step(
    step: str,
    bytes_by_name: dict[str, int],
    mbps: int,
) -> float:
    """Sum transfer ms for the artifacts emitted by `step` at `mbps` Mbps."""
    total_bytes = 0
    for name in _STEP_TO_ARTIFACT.get(step, ()):
        total_bytes += bytes_by_name.get(name, 0)
    if total_bytes == 0:
        return 0.0
    bps = mbps * 1_000_000 / 8.0
    return (total_bytes / bps) * 1000.0


def _plot_session_timeline(
    path: Path,
    ordered: Sequence[tuple[str, float]],
    bytes_rows: Sequence[tuple[str, int]],
    mbps: int,
) -> None:
    """Horizontal Gantt with compute + transfer sections interleaved at `mbps` Mbps.

    Compute sections use the macro-phase colour; transfer sections use the
    same colour but with hatching + reduced alpha so the eye can tell them
    apart without a third hue.
    """
    bytes_by_name = dict(bytes_rows)

    fig, ax = plt.subplots(figsize=(13, 3.5))
    x = 0.0
    for step, ms in ordered:
        color = _phase_color(step)
        # Compute section first.
        ax.barh(0, ms, left=x, height=0.6, color=color, edgecolor="white", linewidth=0.5)
        if ms > 0:
            ax.text(
                x + ms / 2,
                0.0,
                step,
                ha="center",
                va="center",
                fontsize=7,
                color="white" if ms > 8 else "black",
            )
        x += ms

        # Transfer section: artifacts emitted by this step at `mbps`.
        tx_ms = _transfer_ms_for_step(step, bytes_by_name, mbps)
        if tx_ms > 0:
            ax.barh(
                0,
                tx_ms,
                left=x,
                height=0.6,
                color=color,
                alpha=0.4,
                hatch="//",
                edgecolor="white",
                linewidth=0.5,
            )
            if tx_ms > 0:
                ax.text(
                    x + tx_ms / 2,
                    0.0,
                    "tx",
                    ha="center",
                    va="center",
                    fontsize=6,
                    color="black",
                )
            x += tx_ms

    ax.set_yticks([])
    ax.set_xlabel("wall time (ms)")
    ax.set_title(f"Session timeline (compute + transfer @ {mbps} Mbps)")

    from matplotlib.patches import Patch

    handles = [
        Patch(facecolor=_COLOR_SETUP, label="setup compute"),
        Patch(facecolor=_COLOR_INFER, label="inference compute"),
        Patch(facecolor=_COLOR_VERIFY, label="verify compute"),
        Patch(facecolor="#bbbbbb", hatch="//", label="transfer"),
    ]
    ax.legend(handles=handles, loc="upper right", fontsize=8, framealpha=0.9)
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)


def write_plots(batch_dir: Path, agg_data: dict[str, Any]) -> None:
    """Write all seven eval plots into `<batch_dir>/plots/`.

    `agg_data` shape matches what `bench.eval.aggregate` constructs. Missing
    keys default to empty buckets so a partial pipeline still produces
    inspectable PNGs.
    """
    batch_dir = Path(batch_dir).resolve()
    plots_dir = batch_dir / "plots"
    plots_dir.mkdir(parents=True, exist_ok=True)

    keygen_run: Run = agg_data["keygen_run"]
    per_image: dict[str, list[Sample]] = agg_data.get("per_image_samples", {})
    bytes_rows: list[tuple[str, int]] = list(agg_data.get("bytes_rows", []))
    all_noise: list[float] = list(agg_data.get("all_noise", []))
    snr: list[tuple[int, float, float]] = list(agg_data.get("snr", []))
    bandwidths_mbps: Sequence[int] = agg_data.get("bandwidths_mbps", (1, 10, 100))

    ordered = _ordered_steps_and_means(keygen_run, per_image)

    _plot_e2e_timeline(plots_dir / "e2e_timeline.png", ordered)
    _plot_rss_per_step(plots_dir / "rss_per_step.png", keygen_run, per_image)
    _plot_bytes_per_message(plots_dir / "bytes_per_message.png", bytes_rows)
    _plot_noise_histogram(plots_dir / "noise_histogram.png", all_noise)
    _plot_snr_per_image(plots_dir / "snr_per_image.png", snr)
    _plot_bandwidth_per_message(
        plots_dir / "bandwidth_per_message.png", bytes_rows, bandwidths_mbps
    )
    _plot_session_timeline(plots_dir / "session_timeline_10mbps.png", ordered, bytes_rows, mbps=10)
