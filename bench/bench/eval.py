"""Eval driver: chain `ppiav-cli` subcommands across a stratified batch.

Reads ``eval_inputs.json`` produced by ``models.prepare_samples``, runs one
keygen + per-image (encrypt -> infer -> mac -> partial-decrypt -> finalize)
sequence as subprocesses, and writes per-step bench JSONs + ciphertext
artifacts into ``results/phase2/eval-<UTC-timestamp>/``.

Usage::

    python -m bench.eval --inputs models/out/eval_inputs.json \\
        --orion models/out/logn16 [--batch-dir results/phase2/eval-custom]

The `ppiav-cli` binary is resolved in order: ``./bin/ppiav-cli`` (built by
``make``), ``PATH`` lookup, ``go run ./cmd/ppiav-cli`` fallback. Aggregation
into ``summary.md`` + ``plots/*.png`` is the job of Task 14's ``aggregate``
function; this module exposes a stub that raises NotImplementedError.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import shutil
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any


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

    Errors stream the captured stderr to the parent process so the operator
    sees the underlying protocol failure (e.g. an `auth.Ver` rejection) and
    not just a Python traceback.
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


def _resolve_image_path(repo: Path, raw: str) -> Path:
    """Resolve a manifest image path against the repo root if it's relative."""
    p = Path(raw)
    if not p.is_absolute():
        p = (repo / raw).resolve()
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
        batch_dir = repo / "results" / "phase2" / f"eval-{ts}"
    batch_dir = batch_dir.resolve()
    keys_dir = batch_dir / "keys"
    keys_dir.mkdir(parents=True, exist_ok=True)

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

    images: list[dict[str, Any]] = manifest["images"]
    for entry in images:
        idx = int(entry["idx"])
        img_dir = batch_dir / f"img_{idx}"
        img_dir.mkdir(parents=True, exist_ok=True)
        image_path = _resolve_image_path(repo, str(entry["path"]))
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


def aggregate(batch_dir: Path) -> None:
    """Aggregate per-step JSONs + decoded.json into summary.md + plots/.

    Stub: implemented in Task 14 (summary.md generation) + Task 15 (plot
    generation). Raises NotImplementedError until then so callers don't
    silently no-op.
    """
    raise NotImplementedError(
        f"aggregate({batch_dir}) is implemented by Task 14; see "
        "docs/plans/20260515-bench-eval-redesign.md"
    )


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="bench.eval",
        description="Chain ppiav-cli subcommands across a stratified eval batch.",
    )
    parser.add_argument(
        "--inputs",
        type=Path,
        required=True,
        help="Path to eval_inputs.json produced by models.prepare_samples.",
    )
    parser.add_argument(
        "--orion",
        type=Path,
        required=True,
        help="Path to Orion compiled-model directory (consumed by keygen + infer).",
    )
    parser.add_argument(
        "--batch-dir",
        type=Path,
        default=None,
        help="Override per-batch output dir (default results/phase2/eval-<UTC ts>/).",
    )
    args = parser.parse_args(argv[1:])

    try:
        batch_dir = run_pipeline(args.inputs, args.orion, args.batch_dir)
    except NotImplementedError as exc:
        # aggregate() is a stub; surface the message but treat as success
        # for the pipeline portion (Task 13 owns chaining, not aggregation).
        print(f"[bench.eval] pipeline complete; aggregate pending: {exc}", file=sys.stderr)
        return 0
    except (RuntimeError, FileNotFoundError, ValueError) as exc:
        print(f"[bench.eval] error: {exc}", file=sys.stderr)
        return 1

    print(f"[bench.eval] batch complete: {batch_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
