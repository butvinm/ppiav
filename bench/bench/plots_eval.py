"""Plot generation for the eval batch.

`write_plots(batch_dir, agg_data)` is invoked at the tail of
`bench.eval.aggregate` and writes six PNGs into ``<batch>/plots/``.

Inputs (consumed from `agg_data`; shape matches what `eval.aggregate` builds):
- `keygen_run` — `bench.load.Run` for the keygen handshake.
- `per_image_samples` — `dict[str, list[Sample]]` keyed by per-image step.
- `bytes_rows` — `list[tuple[str, int]]` of every artifact's wire size.
- `all_noise` — flattened noise samples across (image x non-S slot) pairs.
- `snr` — `list[tuple[idx, snr, ref_logit_abs)]`, one entry per image.
- `bandwidths_mbps` — bandwidth axis for the bandwidth plot.

Plot text is in Russian via ``bench._labels_ru`` (user-editable). No titles
on any plot — the surrounding summary.md / thesis chapter caption it.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")  # headless backend; must be set before importing pyplot.

import matplotlib.pyplot as plt
import numpy as np

from bench._labels_ru import (
    AXIS,
    KEYGEN_ROUND_SUBSTEPS,
    LEGEND,
    PARTY_BY_STEP,
    PARTY_NAMES,
    STEP_NAMES,
    TRANSFERS_PER_IMAGE,
)
from bench.eval import _KEYGEN_SUBSTEPS, _PER_IMAGE_STEPS
from bench.load import Run, Sample

# Macro-phase color palette. setup = blue, inference = orange, verify = green.
_COLOR_SETUP = "#1f77b4"
_COLOR_INFER = "#ff7f0e"
_COLOR_VERIFY = "#2ca02c"

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
    return "#888888"


def _step_label(step: str) -> str:
    return STEP_NAMES.get(step, step)


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


def _plot_rss_per_step(
    path: Path,
    keygen_run: Run,
    per_image: dict[str, list[Sample]],
) -> None:
    labels: list[str] = []
    values: list[float] = []
    colors: list[str] = []
    keygen_bucket = _keygen_samples_by_name(keygen_run)
    for name in _KEYGEN_SUBSTEPS:
        labels.append(_step_label(name))
        values.append(_mean_delta_rss_mib(keygen_bucket.get(name, [])))
        colors.append(_phase_color(name))
    for step in _PER_IMAGE_STEPS:
        labels.append(_step_label(step))
        values.append(_mean_delta_rss_mib(per_image.get(step, [])))
        colors.append(_phase_color(step))

    fig, ax = plt.subplots(figsize=(10, 4.5))
    xs = np.arange(len(labels))
    ax.bar(xs, values, color=colors)
    ax.set_xticks(xs)
    ax.set_xticklabels(labels, rotation=35, ha="right", fontsize=8)
    ax.set_ylabel(AXIS["delta_rss_mib"])
    _set_macro_phase_legend(ax, transfer=False)
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)


def _plot_bytes_per_message(path: Path, bytes_rows: Sequence[tuple[str, int]]) -> None:
    fig, ax = plt.subplots(figsize=(11, 5))
    if not bytes_rows:
        fig.tight_layout()
        fig.savefig(path, dpi=120)
        plt.close(fig)
        return

    names = [name for name, _ in bytes_rows]
    sizes = [max(size, 1) for _, size in bytes_rows]  # log axis can't take 0
    xs = np.arange(len(names))
    ax.bar(xs, sizes, color="#4c78a8")
    ax.set_yscale("log")
    ax.set_xticks(xs)
    ax.set_xticklabels(names, rotation=45, ha="right", fontsize=7)
    ax.set_xlabel(AXIS["message_name"])
    ax.set_ylabel(AXIS["bytes_log"])
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)


def _plot_noise_histogram(path: Path, noise: Sequence[float]) -> None:
    fig, ax = plt.subplots(figsize=(8, 4.5))
    if noise:
        arr = np.asarray(noise, dtype=np.float64)
        ax.hist(arr, bins=60, color="#5f9ea0", edgecolor="white", linewidth=0.3)
        ax.set_xlabel(AXIS["noise_value"])
        ax.set_ylabel(AXIS["noise_count"])
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)


def _plot_snr_per_image(path: Path, snr: Sequence[tuple[int, float, float]]) -> None:
    fig, ax = plt.subplots(figsize=(7, 4.5))
    if snr:
        finite = [v for _, v, _ in snr if np.isfinite(v)]
        sentinel = max(finite) * 1.2 if finite else 1.0
        ys = [v if np.isfinite(v) else sentinel for _, v, _ in snr]
        rng = np.random.default_rng(seed=0)
        xs = rng.uniform(-0.15, 0.15, size=len(ys))
        ax.scatter(xs, ys, s=64, alpha=0.85, color=_COLOR_INFER, edgecolors="black")
        for x, y, (idx, _, _) in zip(xs, ys, snr, strict=True):
            ax.annotate(str(idx), (x, y), textcoords="offset points", xytext=(6, 0), fontsize=7)
        ax.set_xticks([0])
        ax.set_xticklabels([AXIS["image_idx"]])
        ax.set_xlim(-0.5, 0.5)
        ax.set_ylabel(AXIS["snr_value"])
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)


def _plot_bandwidth_per_message(
    path: Path,
    bytes_rows: Sequence[tuple[str, int]],
    bandwidths_mbps: Sequence[int],
) -> None:
    fig, ax = plt.subplots(figsize=(12, 5))
    if not bytes_rows or not bandwidths_mbps:
        fig.tight_layout()
        fig.savefig(path, dpi=120)
        plt.close(fig)
        return

    names = [name for name, _ in bytes_rows]
    sizes = np.array([size for _, size in bytes_rows], dtype=np.float64)
    n_msgs = len(names)
    n_bw = len(bandwidths_mbps)
    width = 0.8 / n_bw

    xs = np.arange(n_msgs)
    cmap = plt.get_cmap("viridis")
    for i, mbps in enumerate(bandwidths_mbps):
        bps = mbps * 1_000_000 / 8.0
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
    ax.set_xlabel(AXIS["message_name"])
    ax.set_ylabel(AXIS["transfer_seconds"])
    ax.legend(loc="upper right", fontsize=8)
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)


def _set_macro_phase_legend(ax: Any, *, transfer: bool) -> None:
    from matplotlib.patches import Patch

    handles = [
        Patch(facecolor=_COLOR_SETUP, label=LEGEND["macro_setup"]),
        Patch(facecolor=_COLOR_INFER, label=LEGEND["macro_inference"]),
        Patch(facecolor=_COLOR_VERIFY, label=LEGEND["macro_verify"]),
    ]
    if transfer:
        handles.append(Patch(facecolor="#bbbbbb", hatch="//", label=LEGEND["transfer"]))
    ax.legend(handles=handles, loc="upper right", fontsize=8, framealpha=0.9)


# Lane order for the swim-lane Gantt: client / service / agent.
# Joint rounds (legacy keygen.json) are drawn as multi-lane spanning blocks.
_LANE_ORDER: tuple[str, ...] = ("client", "service", "agent")

# For each keygen round, the set of party lanes the round's compute spans
# when only round-level (not per-party) samples are available.
_KEYGEN_ROUND_LANES: dict[str, tuple[str, ...]] = {
    "keygen.open": ("client", "service", "agent"),
    "keygen.pk": ("client", "agent"),
    "keygen.rlk-r1": ("client", "agent"),
    "keygen.rlk-r2": ("client", "agent"),
    "keygen.galois": ("client", "service", "agent"),
}


def _bytes_for_per_image_artifact(
    bytes_by_name: dict[str, int],
    artifact: str,
) -> int:
    """Per-image artifacts live under the `img/` prefix in `bytes_by_name`."""
    return bytes_by_name.get(f"img/{artifact}", 0)


def _plot_session_timeline_swimlane(
    path: Path,
    ordered: Sequence[tuple[str, float]],
    bytes_rows: Sequence[tuple[str, int]],
    mbps: int,
) -> None:
    """Per-party swim-lane Gantt for one mean session at `mbps` Mbps.

    Lanes (top → bottom): joint (keygen), client, service, agent. Each
    step's compute is a solid bar in its party's lane; each per-image
    transfer is a hatched bar bridging sender's and receiver's lanes
    during the on-the-wire window.
    """
    bytes_by_name = dict(bytes_rows)
    bps = mbps * 1_000_000 / 8.0

    # Map step → ms for quick lookup.
    step_ms: dict[str, float] = dict(ordered)

    # Build the list of (lanes, kind, t_start, t_end, label, color) events.
    # `kind` = "compute" or "transfer". `lanes` is a tuple — single-element
    # for a single-lane compute, multi-element for a spanning rect.
    events: list[dict[str, Any]] = []
    t = 0.0

    # 1. Keygen: per-party sub-substeps if available (instrumented driver),
    # else round-level spanning blocks across the involved party lanes.
    sub_party_names: list[str] = [
        sub for substeps in KEYGEN_ROUND_SUBSTEPS.values() for sub in substeps
    ]
    has_per_party = any(step_ms.get(sub, 0.0) > 0 for sub in sub_party_names)

    if has_per_party:
        for substeps in KEYGEN_ROUND_SUBSTEPS.values():
            for sub in substeps:
                ms = step_ms.get(sub, 0.0)
                if ms <= 0:
                    continue
                party = PARTY_BY_STEP.get(sub, "client")
                events.append(
                    {
                        "lanes": (party,),
                        "kind": "compute",
                        "t_start": t,
                        "t_end": t + ms,
                        "label": _step_label(sub),
                        "color": _phase_color(sub),
                    }
                )
                t += ms
    else:
        for sub in _KEYGEN_SUBSTEPS:
            ms = step_ms.get(sub, 0.0)
            if ms <= 0:
                continue
            events.append(
                {
                    "lanes": _KEYGEN_ROUND_LANES.get(sub, ("client", "agent")),
                    "kind": "compute",
                    "t_start": t,
                    "t_end": t + ms,
                    "label": _step_label(sub),
                    "color": _phase_color(sub),
                }
            )
            t += ms

    # 2. Per-image protocol steps + their post-step transfers.
    transfer_by_step: dict[str, tuple[str, str, str]] = {
        # encrypt → input_ct from client to service
        "encrypt": ("client", "service", "input_ct.bin"),
        # infer → result_ct from service to agent
        "infer": ("service", "agent", "result_ct.bin"),
        # mac → auth_ct from agent to client
        "mac": ("agent", "client", "auth_ct.bin"),
        # partial-decrypt → client_share from client to agent
        "partial-decrypt": ("client", "agent", "client_share.bin"),
        # finalize → no outgoing message
    }
    # sanity: keep _labels_ru.TRANSFERS_PER_IMAGE in sync (cheap assert at import time)
    if tuple((s, r, a) for s, r, a in TRANSFERS_PER_IMAGE) != tuple(
        (transfer_by_step[k][0], transfer_by_step[k][1], transfer_by_step[k][2])
        for k in ("encrypt", "infer", "mac", "partial-decrypt")
    ):
        # not fatal — _labels_ru lets the user reorder; just trust the local map.
        pass

    for step in _PER_IMAGE_STEPS:
        party = PARTY_BY_STEP.get(step, "joint")
        ms = step_ms.get(step, 0.0)
        if ms > 0:
            events.append(
                {
                    "lanes": (party,),
                    "kind": "compute",
                    "t_start": t,
                    "t_end": t + ms,
                    "label": _step_label(step),
                    "color": _phase_color(step),
                }
            )
            t += ms

        if step in transfer_by_step:
            sender, receiver, artifact = transfer_by_step[step]
            size = _bytes_for_per_image_artifact(bytes_by_name, artifact)
            if size > 0:
                tx_ms = (size / bps) * 1000.0
                events.append(
                    {
                        "lanes": (sender, receiver),
                        "kind": "transfer",
                        "t_start": t,
                        "t_end": t + tx_ms,
                        "label": artifact,
                        "color": _phase_color(step),
                    }
                )
                t += tx_ms

    total_ms = t if t > 0 else 1.0
    use_seconds = total_ms >= 1000.0
    scale = 1000.0 if use_seconds else 1.0
    x_label_key = "session_seconds" if use_seconds else "session_ms"

    fig, ax = plt.subplots(figsize=(13, 4.0))
    bar_height = 0.6

    for ev in events:
        t_start = ev["t_start"] / scale
        width = (ev["t_end"] - ev["t_start"]) / scale
        lanes = ev["lanes"]
        if ev["kind"] == "compute" and len(lanes) == 1:
            party = lanes[0]
            y = _LANE_ORDER.index(party)
            ax.barh(
                y,
                width,
                left=t_start,
                height=bar_height,
                color=ev["color"],
                edgecolor="white",
                linewidth=0.5,
            )
            if width > total_ms / scale * 0.02:
                ax.text(
                    t_start + width / 2,
                    y,
                    ev["label"],
                    ha="center",
                    va="center",
                    fontsize=7,
                    color="white",
                )
        elif ev["kind"] == "compute":
            # Multi-lane spanning compute: legacy joint keygen round drawn
            # across the involved party lanes as one tall hatched rect.
            ys = sorted(_LANE_ORDER.index(p) for p in lanes)
            y_mid = (ys[0] + ys[-1]) / 2.0
            tall_height = (ys[-1] - ys[0]) + bar_height
            ax.barh(
                y_mid,
                width,
                left=t_start,
                height=tall_height,
                color=ev["color"],
                alpha=0.55,
                hatch="\\\\",
                edgecolor="white",
                linewidth=0.4,
            )
            if width > total_ms / scale * 0.02:
                ax.text(
                    t_start + width / 2,
                    y_mid,
                    ev["label"],
                    ha="center",
                    va="center",
                    fontsize=7,
                    color="white",
                )
        else:
            # Transfer: hatched rect spanning sender + receiver lanes.
            sender, receiver = lanes
            y_top = _LANE_ORDER.index(sender)
            y_bot = _LANE_ORDER.index(receiver)
            y_mid = (y_top + y_bot) / 2.0
            tall_height = abs(y_top - y_bot) + bar_height
            ax.barh(
                y_mid,
                width,
                left=t_start,
                height=tall_height,
                color=ev["color"],
                alpha=0.35,
                hatch="//",
                edgecolor="white",
                linewidth=0.4,
            )

    ax.set_yticks(list(range(len(_LANE_ORDER))))
    ax.set_yticklabels([PARTY_NAMES[p] for p in _LANE_ORDER], fontsize=9)
    ax.set_ylabel(AXIS["party_lane"])
    ax.set_xlabel(AXIS[x_label_key])
    ax.set_xlim(0, total_ms / scale * 1.02)
    ax.invert_yaxis()
    _set_macro_phase_legend(ax, transfer=True)
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)


def write_plots(batch_dir: Path, agg_data: dict[str, Any]) -> None:
    """Write all six eval plots into `<batch_dir>/plots/`."""
    batch_dir = Path(batch_dir).resolve()
    plots_dir = batch_dir / "plots"
    plots_dir.mkdir(parents=True, exist_ok=True)
    # Drop stale PNGs from a previous render so a replot doesn't leave
    # files for plots we no longer emit (e.g. legacy e2e_timeline.png).
    for path in plots_dir.glob("*.png"):
        path.unlink()

    keygen_run: Run = agg_data["keygen_run"]
    per_image: dict[str, list[Sample]] = agg_data.get("per_image_samples", {})
    bytes_rows: list[tuple[str, int]] = list(agg_data.get("bytes_rows", []))
    all_noise: list[float] = list(agg_data.get("all_noise", []))
    snr: list[tuple[int, float, float]] = list(agg_data.get("snr", []))
    bandwidths_mbps: Sequence[int] = agg_data.get("bandwidths_mbps", (1, 10, 100))

    ordered = _ordered_steps_and_means(keygen_run, per_image)

    # rss_per_step.png + bytes_per_message.png are intentionally not emitted:
    # the per-party time+memory table and the per-message bytes table in
    # summary.md cover the same information more precisely.
    _plot_noise_histogram(plots_dir / "noise_histogram.png", all_noise)
    _plot_snr_per_image(plots_dir / "snr_per_image.png", snr)
    _plot_bandwidth_per_message(
        plots_dir / "bandwidth_per_message.png", bytes_rows, bandwidths_mbps
    )
    _plot_session_timeline_swimlane(
        plots_dir / "session_timeline_10mbps.png", ordered, bytes_rows, mbps=10
    )
