"""Tests for bench.tables.render_tables."""

from __future__ import annotations

from pathlib import Path

from bench.load import load_run
from bench.tables import render_tables

FIXTURE = Path(__file__).parent / "fixtures" / "sample_run.json"


def test_render_tables_contains_every_stage() -> None:
    run = load_run(FIXTURE)
    out = render_tables([run])
    # Both stages from the fixture must appear.
    assert "open" in out
    assert "setup" in out
    # Header is present.
    assert "stage" in out
    assert "mean ms" in out


def test_render_tables_numeric_formatting() -> None:
    run = load_run(FIXTURE)
    out = render_tables([run])
    # open: wall=1.5 ms exactly. setup: mean of (9500, 9300) = 9400.00 ms.
    assert "1.50" in out
    assert "9400.00" in out


def test_render_tables_empty_input() -> None:
    out = render_tables([])
    assert "no samples" in out
