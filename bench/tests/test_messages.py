"""Tests for the protocol message + key catalog in bench._messages."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

import pytest

from bench._messages import (
    KEYS,
    MESSAGES,
    FilePath,
    Message,
    MultiFilePath,
    SampleBytes,
    resolve_key_bytes,
    resolve_message_bytes,
)
from bench.load import Sample, load_run

FIXTURE = Path(__file__).parent / "fixtures" / "sample_batch"


def _samples_by_name() -> dict[str, list[Sample]]:
    """Build the flat samples-by-name index from every JSON in the fixture batch.

    Mirrors what ``bench.eval.aggregate`` does at runtime: load keygen.json +
    every per-image JSON, then group Samples by name across all Runs.
    """
    index: dict[str, list[Sample]] = defaultdict(list)
    keygen_run = load_run(FIXTURE / "keygen.json")
    for s in keygen_run.samples:
        index[s.name].append(s)
    for img_dir in sorted(FIXTURE.iterdir()):
        if not img_dir.is_dir() or not img_dir.name.startswith("img_"):
            continue
        for json_path in sorted(img_dir.glob("*.json")):
            # decoded.json is not a bench Run — skip the same way bench.eval does.
            if json_path.name == "decoded.json":
                continue
            run = load_run(json_path)
            for s in run.samples:
                index[s.name].append(s)
    return dict(index)


def test_messages_catalog_has_expected_entries() -> None:
    """Every message id we expect to surface in summary.md must be in the catalog."""
    expected_ids = {
        "VAgentSessionInit",
        "VServiceSessionResponse",
        "VClientParamsRequest",
        "VAgentParamsRequest",
        "VAgentSessionParams",
        "VClientPKShare",
        "VAgentPKShare",
        "VClientRLKRound1Share",
        "VAgentRLKRound1Share",
        "VClientRLKRound2Share",
        "VAgentRLKRound2Ack",
        "VClientGaloisShare",
        "VAgentEvalKeyBundle",
        "VServiceKeysAck",
        "VAgentGaloisAck",
        "VClientInputCT",
        "VAgentInputCT",
        "VServiceResultCT",
        "VAgentAuthCT",
        "VClientPartialShare",
        "VAgentVerificationAck",
    }
    actual_ids = {m.id for m in MESSAGES}
    assert actual_ids == expected_ids


def test_messages_have_unique_ids() -> None:
    ids = [m.id for m in MESSAGES]
    assert len(ids) == len(set(ids)), "duplicate message ids in MESSAGES"


def test_keys_have_unique_names() -> None:
    names = [k.name for k in KEYS]
    assert len(names) == len(set(names)), "duplicate key names in KEYS"


def test_keys_catalog_has_expected_entries() -> None:
    expected_names = {
        "sk_c",
        "sk_a",
        "pk_c",
        "pk_a",
        "pk_eval",
        "pk_top",
        "rlk_c^(1)",
        "rlk_a^(1)",
        "rlk_c^(2)",
        "rlk_a^(2)",
        "rlk",
        "gks^master_c",
        "gks^master_a",
        "gks^master",
        "gks^auth",
        "gks^infer",
        "mac_key",
    }
    actual_names = {k.name for k in KEYS}
    assert actual_names == expected_names


def test_resolve_every_message_against_fixture() -> None:
    """Every message in MESSAGES resolves to a non-None size against the fixture."""
    samples = _samples_by_name()
    for msg in MESSAGES:
        size = resolve_message_bytes(msg, FIXTURE, samples)
        assert size is not None, f"{msg.id} resolved to None"
        assert size >= 0, f"{msg.id} resolved to negative size {size}"


def test_resolve_every_key_against_fixture() -> None:
    """Every key in KEYS resolves to a non-None size against the fixture."""
    samples = _samples_by_name()
    for key in KEYS:
        size = resolve_key_bytes(key, FIXTURE, samples)
        assert size is not None, f"{key.name} resolved to None"
        assert size >= 0, f"{key.name} resolved to negative size {size}"


def test_resolve_share_message_uses_sample_bytes() -> None:
    """VClientPKShare reads from the keygen.pk.client_gen Sample.Bytes."""
    samples = _samples_by_name()
    msg = next(m for m in MESSAGES if m.id == "VClientPKShare")
    size = resolve_message_bytes(msg, FIXTURE, samples)
    # Fixture sets keygen.pk.client_gen.bytes = 11001.
    assert size == 11001


def test_resolve_synthetic_returns_constant() -> None:
    """Synthetic-sourced messages return the declared constant."""
    samples = _samples_by_name()
    msg = next(m for m in MESSAGES if m.id == "VAgentSessionInit")
    size = resolve_message_bytes(msg, FIXTURE, samples)
    assert size == 64


def test_resolve_filepath_returns_stat_size() -> None:
    """FilePath-sourced messages return the file size from os.stat."""
    samples = _samples_by_name()
    msg = next(m for m in MESSAGES if m.id == "VClientInputCT")
    size = resolve_message_bytes(msg, FIXTURE, samples)
    # Placeholder zero-byte fixture; size is 0, not None.
    assert size == 0


def test_resolve_multifile_sums_sizes() -> None:
    """MultiFilePath sums sizes across every file when all present."""
    samples = _samples_by_name()
    msg = next(m for m in MESSAGES if m.id == "VAgentEvalKeyBundle")
    size = resolve_message_bytes(msg, FIXTURE, samples)
    expected = sum(
        (FIXTURE / rel).stat().st_size
        for rel in ("keys/rlk.bin", "keys/pk_top.bin", "keys/gks_master.bin")
    )
    assert size == expected


def test_resolve_multifile_missing_returns_none(tmp_path: Path) -> None:
    """MultiFilePath returns None if ANY rel is missing — no silent undercount."""
    (tmp_path / "keys").mkdir()
    (tmp_path / "keys" / "a.bin").write_bytes(b"x" * 16)
    # b.bin is intentionally missing.
    fake_msg = Message(
        id="FakeMultiMissing",
        sender="agent",
        receiver="service",
        label_ru="фейковый составной",
        bytes_source=MultiFilePath(("keys/a.bin", "keys/b.bin")),
    )
    assert resolve_message_bytes(fake_msg, tmp_path, {}) is None


def test_resolve_missing_filepath_returns_none(tmp_path: Path) -> None:
    """A FilePath pointing at a non-existent file resolves to None."""
    fake_msg = Message(
        id="FakeMissingFile",
        sender="client",
        receiver="agent",
        label_ru="фейковый отсутствующий файл",
        bytes_source=FilePath("keys/does_not_exist.bin"),
    )
    assert resolve_message_bytes(fake_msg, FIXTURE, {}) is None


def test_resolve_missing_sample_returns_none() -> None:
    """A SampleBytes pointing at an absent Sample name resolves to None."""
    fake_msg = Message(
        id="FakeMissingSample",
        sender="client",
        receiver="agent",
        label_ru="фейковый отсутствующий сэмпл",
        bytes_source=SampleBytes("never.measured.step"),
    )
    assert resolve_message_bytes(fake_msg, FIXTURE, {}) is None


def test_resolve_sample_with_zero_bytes_returns_none() -> None:
    """SampleBytes pointing at a Sample with bytes=0 is treated as 'not measured'."""
    samples = _samples_by_name()
    # keygen.pk.agent_agg has bytes=0 in the fixture (aggregation produces no share).
    fake_msg = Message(
        id="FakeAggSampleProbe",
        sender="agent",
        receiver="client",
        label_ru="фейковая агрегация",
        bytes_source=SampleBytes("keygen.pk.agent_agg"),
    )
    assert resolve_message_bytes(fake_msg, FIXTURE, samples) is None


def test_resolve_key_filepath_returns_size() -> None:
    """A FilePath-sourced key reads its size from os.stat."""
    samples = _samples_by_name()
    key = next(k for k in KEYS if k.name == "sk_c")
    assert resolve_key_bytes(key, FIXTURE, samples) == 0  # placeholder


def test_resolve_key_sample_uses_sample_bytes() -> None:
    """A SampleBytes-sourced key reads its size from the keygen Sample."""
    samples = _samples_by_name()
    key = next(k for k in KEYS if k.name == "gks^master_c")
    # Fixture sets keygen.galois.client_gen.bytes = 44001.
    assert resolve_key_bytes(key, FIXTURE, samples) == 44001


def test_resolve_key_derived_agent_from_mac_sample() -> None:
    """gks^auth size resolves from the mac.derive_auth_keys Sample.Bytes."""
    samples = _samples_by_name()
    key = next(k for k in KEYS if k.name == "gks^auth")
    # Fixture sets img_0/mac.json mac.derive_auth_keys.bytes = 55501.
    assert resolve_key_bytes(key, FIXTURE, samples) == 55501


def test_missing_file_after_deletion_returns_none(tmp_path: Path) -> None:
    """Deleting a fixture .bin in a temp-copied batch makes its resolver return None."""
    # Mirror just the keys/ subdir we touch; no need to copy the full batch.
    keys_dir = tmp_path / "keys"
    keys_dir.mkdir()
    # Leave pk_eval.bin absent intentionally.
    samples: dict[str, list[Sample]] = {}
    key = next(k for k in KEYS if k.name == "pk_eval")
    assert resolve_key_bytes(key, tmp_path, samples) is None


def test_key_entry_dataclass_frozen() -> None:
    """KeyEntry is frozen — catalog entries cannot be mutated at runtime."""
    key = KEYS[0]
    with pytest.raises(AttributeError):
        key.name = "mutated"  # type: ignore[misc]
