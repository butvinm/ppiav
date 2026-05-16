"""Plot generation for the eval batch.

`write_plots(batch_dir, agg_data)` is invoked at the tail of
`bench.eval.aggregate` and writes the eval PNGs into ``<batch>/plots/``.

Inputs (consumed from `agg_data`; shape matches what `eval.aggregate` builds):
- `keygen_run` — `bench.load.Run` for the keygen handshake.
- `per_image_samples` — `dict[str, list[Sample]]` keyed by per-image step name
  (including the fine-grained sub-steps `infer.load_keys`, `mac.derive_auth_keys`, ...).
- `message_bytes_rows` — catalog-keyed
  `list[tuple[message_id, label_ru, sender, receiver, bytes_or_None]]` from
  the message catalog (`_messages.MESSAGES`).
- `plain_stats` / `verdict_stats` — confusion-matrix dicts from `_classify`.
- `all_noise` — flattened noise samples across (image x non-S slot) pairs.
- `snr` — `list[tuple[idx, snr, ref_logit_abs)]`, one entry per image.
- `bandwidths_mbps` — bandwidth axis for the bandwidth plot.

Plot text is in Russian via ``bench._labels_ru`` (user-editable). No titles
on any plot — the surrounding summary.md / thesis chapter captions it.
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
    ACCURACY_METRIC_NAMES,
    AXIS,
    KEYGEN_ROUND_SUBSTEPS,
    LEGEND,
    PARTY_BY_STEP,
    PARTY_NAMES,
    PARTY_SHORT_NAMES,
    STEP_NAMES,
    TABLE_HEADERS,
    TRANSFERS_PER_IMAGE,
)
from bench._messages import PER_IMAGE_STEPS
from bench.eval import MessageBytesRow
from bench.load import Run, Sample

# Macro-phase color palette. setup = blue, inference = orange, verify = green.
_COLOR_SETUP = "#1f77b4"
_COLOR_INFER = "#ff7f0e"
_COLOR_VERIFY = "#2ca02c"

# Sender-party color tags for the per-message bytes / bandwidth plots.
# Distinct hues per actor so the catalog ordering reads at a glance.
_SENDER_COLORS: dict[str, str] = {
    "client": "#4c78a8",
    "agent": "#f58518",
    "service": "#54a24b",
    "resource_service": "#b279a2",
}

# Parent-stage color families for the per-party Gantt sub-step lanes.
# Each parent stage gets a base color; sub-steps get distinct shades from
# the same matplotlib colormap so visual grouping is preserved across the
# lane. Order within the tuple is `(base_cmap_name, n_shades)`.
_SUBSTEP_FAMILIES: dict[str, tuple[str, int]] = {
    "infer": ("Blues", 4),
    "mac": ("Greens", 2),
    "finalize": ("Purples", 2),
}

def _parent_stage(step: str) -> str:
    """Return the parent-stage name for a per-image step or sub-step."""
    return step.split(".", 1)[0]


def _phase_color(step: str) -> str:
    parent = _parent_stage(step)
    if parent == "keygen":
        return _COLOR_SETUP
    if parent in {"encrypt", "infer"}:
        return _COLOR_INFER
    if parent in {"mac", "partial-decrypt", "finalize"}:
        return _COLOR_VERIFY
    return "#888888"


def _substep_shade(
    step: str, ordinal: int, total: int
) -> str | tuple[float, float, float, float]:
    """Return a per-sub-step shade from its parent's color family.

    Falls back to the macro-phase color (a hex string) when no family is
    registered (e.g. `encrypt`, `partial-decrypt` — single-sample stages
    with no sub-steps); otherwise returns an RGBA tuple from a matplotlib
    colormap, which is the natural color spec for ``ax.barh``.
    """
    parent = _parent_stage(step)
    family = _SUBSTEP_FAMILIES.get(parent)
    if family is None:
        return _phase_color(step)
    cmap_name, _n = family
    cmap = plt.get_cmap(cmap_name)
    # Anchor in the mid-to-dark range so shades read against a white bg.
    t = 0.7 if total <= 1 else 0.35 + 0.55 * (ordinal / max(total - 1, 1))
    rgba: tuple[float, float, float, float] = cmap(t)
    return rgba


def _step_label(step: str) -> str:
    return STEP_NAMES.get(step, step)


def _mean_wall_ms(samples: Sequence[Sample]) -> float:
    if not samples:
        return 0.0
    return float(np.mean([s.wall_ms for s in samples]))


def _keygen_samples_by_name(keygen_run: Run) -> dict[str, list[Sample]]:
    bucket: dict[str, list[Sample]] = {}
    for s in keygen_run.samples:
        bucket.setdefault(s.name, []).append(s)
    return bucket


def _ordered_steps_and_means(
    keygen_run: Run,
    per_image: dict[str, list[Sample]],
) -> list[tuple[str, float]]:
    """Return ordered `(step, mean_ms)` for keygen sub-steps + per-image sub-steps."""
    out: list[tuple[str, float]] = []
    keygen_bucket = _keygen_samples_by_name(keygen_run)
    for substeps in KEYGEN_ROUND_SUBSTEPS.values():
        for sub in substeps:
            out.append((sub, _mean_wall_ms(keygen_bucket.get(sub, []))))
    for step in PER_IMAGE_STEPS:
        out.append((step, _mean_wall_ms(per_image.get(step, []))))
    return out


def _plot_bytes_per_message(path: Path, rows: Sequence[MessageBytesRow]) -> None:
    """Per-message wire sizes, log-y. Bars colored by sender party."""
    fig, ax = plt.subplots(figsize=(12, 5))
    if not rows:
        fig.tight_layout()
        fig.savefig(path, dpi=120)
        plt.close(fig)
        return

    ids = [r[0] for r in rows]
    senders = [r[2] for r in rows]
    # Coerce None → 1 byte so the log axis is safe; matches the existing
    # bytes_per_message convention. Missing-file rows get the same
    # treatment but the table-side renders an em-dash to disambiguate.
    sizes = [max(r[4] or 1, 1) for r in rows]
    colors = [_SENDER_COLORS.get(s, "#888888") for s in senders]

    xs = np.arange(len(ids))
    ax.bar(xs, sizes, color=colors)
    ax.set_yscale("log")
    ax.set_xticks(xs)
    ax.set_xticklabels(ids, rotation=45, ha="right", fontsize=7)
    ax.set_xlabel(AXIS["message_name"])
    ax.set_ylabel(AXIS["bytes_log"])
    _set_sender_legend(ax, senders)
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)


def _plot_bandwidth_per_message(
    path: Path,
    rows: Sequence[MessageBytesRow],
    bandwidths_mbps: Sequence[int],
) -> None:
    """Per-message transfer-time across the bandwidth axis. Sender-colored x-ticks."""
    fig, ax = plt.subplots(figsize=(13, 5))
    if not rows or not bandwidths_mbps:
        fig.tight_layout()
        fig.savefig(path, dpi=120)
        plt.close(fig)
        return

    ids = [r[0] for r in rows]
    senders = [r[2] for r in rows]
    sizes_np = np.array([float(r[4] or 0) for r in rows], dtype=np.float64)
    n_msgs = len(ids)
    n_bw = len(bandwidths_mbps)
    width = 0.8 / n_bw

    xs = np.arange(n_msgs)
    cmap = plt.get_cmap("viridis")
    for i, mbps in enumerate(bandwidths_mbps):
        bps = mbps * 1_000_000 / 8.0
        # max(_, eps) so log axis can render zero-sized synthetic acks.
        seconds = np.maximum(sizes_np / bps, 1e-6)
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
    ax.set_xticklabels(ids, rotation=45, ha="right", fontsize=7)
    # Color each x-tick label by sender — preserves the per-party color tag
    # from `bytes_per_message.png` without doubling the bar legend.
    for tick, sender in zip(ax.get_xticklabels(), senders, strict=True):
        tick.set_color(_SENDER_COLORS.get(sender, "#333333"))
    ax.set_xlabel(AXIS["message_name"])
    ax.set_ylabel(AXIS["transfer_seconds"])
    ax.legend(loc="upper right", fontsize=8)
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)


def _plot_accuracy_plain_vs_fhe(
    path: Path,
    plain_stats: dict[str, int | float],
    fhe_stats: dict[str, int | float],
) -> None:
    """Grouped bar chart: accuracy / FPR / FNR, plain vs FHE."""
    fig, ax = plt.subplots(figsize=(7, 4.5))
    metrics = ("accuracy", "fpr", "fnr")
    labels = [ACCURACY_METRIC_NAMES[m] for m in metrics]

    plain_vals = [float(plain_stats[m]) for m in metrics]
    fhe_vals = [float(fhe_stats[m]) for m in metrics]

    xs = np.arange(len(metrics))
    width = 0.38
    ax.bar(
        xs - width / 2,
        plain_vals,
        width=width,
        color="#888888",
        label=TABLE_HEADERS["plain_column"],
    )
    ax.bar(
        xs + width / 2,
        fhe_vals,
        width=width,
        color=_COLOR_INFER,
        label=TABLE_HEADERS["fhe_column"],
    )
    ax.set_xticks(xs)
    ax.set_xticklabels(labels)
    ax.set_ylim(0.0, 1.0)
    ax.set_ylabel(AXIS.get("rate", "доля"))
    ax.legend(loc="upper right", fontsize=9)
    # Annotate the bar tops with the numeric value — three decimals matches
    # the comparison table in summary.md.
    for x, v in zip(xs - width / 2, plain_vals, strict=True):
        ax.text(x, v + 0.01, f"{v:.3f}", ha="center", va="bottom", fontsize=7)
    for x, v in zip(xs + width / 2, fhe_vals, strict=True):
        ax.text(x, v + 0.01, f"{v:.3f}", ha="center", va="bottom", fontsize=7)
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


def _set_sender_legend(ax: Any, senders: Sequence[str]) -> None:
    from matplotlib.patches import Patch

    seen: list[str] = []
    for s in senders:
        if s not in seen:
            seen.append(s)
    handles = [
        Patch(facecolor=_SENDER_COLORS.get(s, "#888888"), label=PARTY_SHORT_NAMES.get(s, s))
        for s in seen
    ]
    ax.legend(handles=handles, loc="upper right", fontsize=8, framealpha=0.9)


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
_LANE_ORDER: tuple[str, ...] = ("client", "service", "agent")


def _bytes_for_message(
    bytes_rows: Sequence[MessageBytesRow],
    message_id: str,
) -> int:
    """Resolve a message's wire size from the catalog rows; 0 if missing."""
    for mid, _label, _sender, _receiver, size in bytes_rows:
        if mid == message_id:
            return int(size) if size is not None else 0
    return 0


def _substep_ordinals(steps: Sequence[str]) -> dict[str, tuple[int, int]]:
    """For each sub-stepped name, return `(ordinal, total)` within its parent stage."""
    by_parent: dict[str, list[str]] = {}
    for step in steps:
        parent = _parent_stage(step)
        by_parent.setdefault(parent, []).append(step)
    out: dict[str, tuple[int, int]] = {}
    for members in by_parent.values():
        total = len(members)
        for ordinal, step in enumerate(members):
            out[step] = (ordinal, total)
    return out


def _plot_session_timeline_swimlane(
    path: Path,
    ordered: Sequence[tuple[str, float]],
    bytes_rows: Sequence[MessageBytesRow],
    mbps: int,
) -> None:
    """Per-party swim-lane Gantt for one mean session at `mbps` Mbps.

    Lanes (top → bottom): client, service, agent. Each per-image sub-step
    is a solid bar in its party's lane; same color family within a parent
    stage. Inter-party transfers are hatched rects bridging sender + receiver
    lanes during the on-the-wire window.
    """
    bps = mbps * 1_000_000 / 8.0

    # Map step → ms for quick lookup.
    step_ms: dict[str, float] = dict(ordered)

    # Build the list of (lanes, kind, t_start, t_end, label, color) events.
    # `kind` = "compute" or "transfer". `lanes` is a tuple — single-element
    # for a single-lane compute, multi-element for a spanning rect.
    events: list[dict[str, Any]] = []
    t = 0.0

    # 1. Keygen: per-party sub-step blocks on each party's lane.
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

    # 2. Per-image protocol sub-steps + their post-stage transfers.
    # Transfers come from the canonical TRANSFERS_PER_IMAGE list (single
    # source of truth in _labels_ru); each tuple names the parent stage
    # after which the transfer fires, the sender/receiver, and the catalog
    # message_id whose bytes size the rect. input_ct hops twice
    # (VClient->VAgent then VAgent->VService) — both rendered separately.
    ordinals = _substep_ordinals(PER_IMAGE_STEPS)
    last_substep_of_parent: dict[str, str] = {}
    for step in PER_IMAGE_STEPS:
        last_substep_of_parent[_parent_stage(step)] = step

    transfers_after_step: dict[str, list[tuple[str, str, str]]] = {}
    for after_parent, sender, receiver, message_id in TRANSFERS_PER_IMAGE:
        anchor = last_substep_of_parent.get(after_parent)
        if anchor is None:
            continue
        transfers_after_step.setdefault(anchor, []).append((sender, receiver, message_id))

    for step in PER_IMAGE_STEPS:
        ms = step_ms.get(step, 0.0)
        if ms > 0:
            party = PARTY_BY_STEP.get(step, "joint")
            ordinal, total = ordinals.get(step, (0, 1))
            color = _substep_shade(step, ordinal, total) if total > 1 else _phase_color(step)
            events.append(
                {
                    "lanes": (party,),
                    "kind": "compute",
                    "t_start": t,
                    "t_end": t + ms,
                    "label": _step_label(step),
                    "color": color,
                }
            )
            t += ms

        # Anchor transfers to the trailing sub-step of each parent stage; do
        # not emit transfers when the parent's sub-steps had no real samples.
        if ms <= 0:
            continue
        for sender, receiver, message_id in transfers_after_step.get(step, []):
            size = _bytes_for_message(bytes_rows, message_id)
            if size <= 0:
                continue
            tx_ms = (size / bps) * 1000.0
            events.append(
                {
                    "lanes": (sender, receiver),
                    "kind": "transfer",
                    "t_start": t,
                    "t_end": t + tx_ms,
                    "label": message_id,
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
                    fontsize=6,
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
    """Write eval plots into `<batch_dir>/plots/`."""
    batch_dir = Path(batch_dir).resolve()
    plots_dir = batch_dir / "plots"
    plots_dir.mkdir(parents=True, exist_ok=True)
    # Drop stale PNGs from a previous render so a replot doesn't leave
    # files for plots we no longer emit (e.g. legacy e2e_timeline.png).
    for path in plots_dir.glob("*.png"):
        path.unlink()

    keygen_run: Run = agg_data["keygen_run"]
    per_image: dict[str, list[Sample]] = agg_data.get("per_image_samples", {})
    message_bytes_rows: list[MessageBytesRow] = list(agg_data.get("message_bytes_rows", []))
    plain_stats: dict[str, int | float] = agg_data.get("plain_stats", {})
    fhe_stats: dict[str, int | float] = agg_data.get("verdict_stats", {})
    all_noise: list[float] = list(agg_data.get("all_noise", []))
    snr: list[tuple[int, float, float]] = list(agg_data.get("snr", []))
    bandwidths_mbps: Sequence[int] = agg_data.get("bandwidths_mbps", (1, 10, 100))

    ordered = _ordered_steps_and_means(keygen_run, per_image)

    _plot_bytes_per_message(plots_dir / "bytes_per_message.png", message_bytes_rows)
    _plot_bandwidth_per_message(
        plots_dir / "bandwidth_per_message.png", message_bytes_rows, bandwidths_mbps
    )
    if plain_stats and fhe_stats:
        _plot_accuracy_plain_vs_fhe(
            plots_dir / "accuracy_plain_vs_fhe.png", plain_stats, fhe_stats
        )
    _plot_noise_histogram(plots_dir / "noise_histogram.png", all_noise)
    _plot_snr_per_image(plots_dir / "snr_per_image.png", snr)
    _plot_session_timeline_swimlane(
        plots_dir / "session_timeline_10mbps.png", ordered, message_bytes_rows, mbps=10
    )
