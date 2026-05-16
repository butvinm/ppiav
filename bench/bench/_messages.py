"""Protocol message + key catalog.

Authoritative inventory of every wire message in ``docs/protocol.puml`` and
every key the protocol manipulates. Drives the per-message bytes table, the
key inventory table, and the network wire-time table in ``summary.md``.

The catalog is data-only: ``MESSAGES`` and ``KEYS`` are immutable lists of
frozen dataclasses; the size resolvers (``resolve_message_bytes``,
``resolve_key_bytes``) dispatch on the ``bytes_source`` variant tag.

Renames from the bench-redesign-v1 layout: every share message now carries
an explicit ``Share`` suffix; ``VAgentInferenceKeys`` → ``VAgentEvalKeyBundle``
(the wire artifact is ``rlk + gks_master``, not the locally-derived
``gks_infer``); per-image messages reference ``img_0/`` as the canonical
sample since all images produce identically-sized ciphertexts at fixed
CKKS parameters.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from bench.load import Sample

Party = Literal["client", "agent", "service", "resource_service"]

KeyLocation = Literal[
    "client_local",
    "agent_local",
    "service_local",
    "derived_agent",
    "derived_service",
    "aggregated_all",
    "share",
]


@dataclass(frozen=True)
class FilePath:
    """Size resolved by stat-ing ``batch_dir / rel``."""

    rel: str


@dataclass(frozen=True)
class SampleBytes:
    """Size resolved by reading ``samples_by_name[name][0].bytes``."""

    name: str


@dataclass(frozen=True)
class Synthetic:
    """Size is a constant — for tiny handshake / ack envelopes with no on-disk artifact."""

    bytes_: int


@dataclass(frozen=True)
class Unavailable:
    """Size cannot be measured — renders as em-dash with the reason in a footnote."""

    reason: str


BytesSource = FilePath | SampleBytes | Synthetic | Unavailable


@dataclass(frozen=True)
class Message:
    id: str
    sender: Party
    receiver: Party
    label_ru: str
    bytes_source: BytesSource


@dataclass(frozen=True)
class KeyEntry:
    name: str
    location: KeyLocation
    on_wire: bool
    bytes_source: BytesSource


# Authoritative message catalog (drawn from docs/protocol.puml). Order is
# chronological by phase: session init -> keygen -> input -> inference ->
# verifiable decryption.
MESSAGES: list[Message] = [
    Message(
        id="VAgentSessionInit",
        sender="agent",
        receiver="service",
        label_ru="Запрос сессии (агент → сервис)",
        bytes_source=Synthetic(64),
    ),
    Message(
        id="VServiceSessionResponse",
        sender="service",
        receiver="agent",
        label_ru="Параметры протокола + sid",
        bytes_source=FilePath("keys/params.json"),
    ),
    Message(
        id="VAgentSessionParams",
        sender="agent",
        receiver="client",
        label_ru="Параметры протокола (агент → клиент)",
        bytes_source=FilePath("keys/params.json"),
    ),
    Message(
        id="VClientPKShare",
        sender="client",
        receiver="agent",
        label_ru="Доля pk клиента",
        bytes_source=SampleBytes("keygen.pk.client_gen"),
    ),
    Message(
        id="VAgentPKShare",
        sender="agent",
        receiver="client",
        label_ru="Доля pk агента",
        bytes_source=SampleBytes("keygen.pk.agent_gen"),
    ),
    Message(
        id="VClientRLKRound1Share",
        sender="client",
        receiver="agent",
        label_ru="Доля rlk клиента, раунд 1",
        bytes_source=SampleBytes("keygen.rlk-r1.client_gen"),
    ),
    Message(
        id="VAgentRLKRound1Share",
        sender="agent",
        receiver="client",
        label_ru="Доля rlk агента, раунд 1",
        bytes_source=SampleBytes("keygen.rlk-r1.agent_gen"),
    ),
    Message(
        id="VClientRLKRound2Share",
        sender="client",
        receiver="agent",
        label_ru="Доля rlk клиента, раунд 2",
        bytes_source=SampleBytes("keygen.rlk-r2.client_gen"),
    ),
    Message(
        id="VAgentRLKRound2Ack",
        sender="agent",
        receiver="client",
        label_ru="Подтверждение rlk",
        bytes_source=Synthetic(32),
    ),
    Message(
        id="VClientGaloisShare",
        sender="client",
        receiver="agent",
        label_ru="Master доля gks клиента",
        bytes_source=SampleBytes("keygen.galois.client_gen"),
    ),
    Message(
        id="VAgentEvalKeyBundle",
        sender="agent",
        receiver="service",
        label_ru="rlk + gks_master → сервису",
        bytes_source=FilePath("keys/rlk.bin"),
    ),
    Message(
        id="VServiceKeysAck",
        sender="service",
        receiver="agent",
        label_ru="Подтверждение установки ключей",
        bytes_source=Synthetic(32),
    ),
    Message(
        id="VAgentGaloisAck",
        sender="agent",
        receiver="client",
        label_ru="Подтверждение gks",
        bytes_source=Synthetic(32),
    ),
    Message(
        id="VClientInputCT",
        sender="client",
        receiver="agent",
        label_ru="Шифротекст изображения (клиент → агент)",
        bytes_source=FilePath("img_0/input_ct.bin"),
    ),
    Message(
        id="VAgentInputCT",
        sender="agent",
        receiver="service",
        label_ru="Шифротекст изображения (агент → сервис)",
        bytes_source=FilePath("img_0/input_ct.bin"),
    ),
    Message(
        id="VServiceResultCT",
        sender="service",
        receiver="agent",
        label_ru="Шифротекст результата",
        bytes_source=FilePath("img_0/result_ct.bin"),
    ),
    Message(
        id="VAgentAuthCT",
        sender="agent",
        receiver="client",
        label_ru="Аутентифицированный шифротекст",
        bytes_source=FilePath("img_0/auth_ct.bin"),
    ),
    Message(
        id="VClientPartialShare",
        sender="client",
        receiver="agent",
        label_ru="Частично расшифрованный шифротекст",
        bytes_source=FilePath("img_0/client_share.bin"),
    ),
]


# Authoritative key inventory: every key the protocol manipulates, including
# shares (transmitted), aggregates (locally reconstructed by every party), and
# derived bundles (computed in-memory, never transmitted).
KEYS: list[KeyEntry] = [
    KeyEntry(
        name="sk_c",
        location="client_local",
        on_wire=False,
        bytes_source=FilePath("keys/sk_c.bin"),
    ),
    KeyEntry(
        name="sk_a",
        location="agent_local",
        on_wire=False,
        bytes_source=FilePath("keys/sk_a.bin"),
    ),
    KeyEntry(
        name="pk_c",
        location="share",
        on_wire=True,
        bytes_source=SampleBytes("keygen.pk.client_gen"),
    ),
    KeyEntry(
        name="pk_a",
        location="share",
        on_wire=True,
        bytes_source=SampleBytes("keygen.pk.agent_gen"),
    ),
    KeyEntry(
        name="pk_eval",
        location="aggregated_all",
        on_wire=False,
        bytes_source=FilePath("keys/pk_eval.bin"),
    ),
    KeyEntry(
        name="pk_top",
        location="derived_service",
        on_wire=True,
        bytes_source=FilePath("keys/pk_top.bin"),
    ),
    KeyEntry(
        name="rlk_c^(1)",
        location="share",
        on_wire=True,
        bytes_source=SampleBytes("keygen.rlk-r1.client_gen"),
    ),
    KeyEntry(
        name="rlk_a^(1)",
        location="share",
        on_wire=True,
        bytes_source=SampleBytes("keygen.rlk-r1.agent_gen"),
    ),
    KeyEntry(
        name="rlk_c^(2)",
        location="share",
        on_wire=True,
        bytes_source=SampleBytes("keygen.rlk-r2.client_gen"),
    ),
    KeyEntry(
        name="rlk_a^(2)",
        location="share",
        on_wire=True,
        bytes_source=SampleBytes("keygen.rlk-r2.agent_gen"),
    ),
    KeyEntry(
        name="rlk",
        location="aggregated_all",
        on_wire=False,
        bytes_source=FilePath("keys/rlk.bin"),
    ),
    KeyEntry(
        name="gks^master_c",
        location="share",
        on_wire=True,
        bytes_source=SampleBytes("keygen.galois.client_gen"),
    ),
    KeyEntry(
        name="gks^master_a",
        location="share",
        on_wire=False,
        bytes_source=SampleBytes("keygen.galois.agent_gen"),
    ),
    KeyEntry(
        name="gks^master",
        location="aggregated_all",
        on_wire=True,
        bytes_source=FilePath("keys/gks_master.bin"),
    ),
    KeyEntry(
        name="gks^auth",
        location="derived_agent",
        on_wire=False,
        bytes_source=SampleBytes("mac.derive_auth_keys"),
    ),
    KeyEntry(
        name="gks^infer",
        location="derived_service",
        on_wire=False,
        bytes_source=FilePath("keys/gks_infer.bin"),
    ),
    KeyEntry(
        name="mac_key",
        location="agent_local",
        on_wire=False,
        bytes_source=FilePath("keys/mac_key.bin"),
    ),
]


def _resolve_bytes_source(
    source: BytesSource,
    batch_dir: Path,
    samples_by_name: dict[str, list[Sample]],
) -> int | None:
    """Dispatch on the BytesSource variant.

    Returns:
        - ``FilePath(rel)``: ``(batch_dir / rel).stat().st_size`` if the file
          exists, else ``None``.
        - ``SampleBytes(name)``: ``samples_by_name[name][0].bytes`` if the name
          is present and its first sample has a non-zero Bytes field, else
          ``None``. We treat ``Bytes == 0`` as "not measured" so callers can
          distinguish from a genuine zero-byte payload (which never occurs in
          practice for our share types).
        - ``Synthetic(n)``: ``n``.
        - ``Unavailable(reason)``: ``None``.
    """
    if isinstance(source, FilePath):
        path = batch_dir / source.rel
        if not path.is_file():
            return None
        return path.stat().st_size
    if isinstance(source, SampleBytes):
        samples = samples_by_name.get(source.name)
        if not samples:
            return None
        first = samples[0]
        if first.bytes <= 0:
            return None
        return first.bytes
    if isinstance(source, Synthetic):
        return source.bytes_
    if isinstance(source, Unavailable):
        return None
    raise TypeError(f"unknown BytesSource variant: {type(source).__name__}")


def resolve_message_bytes(
    message: Message,
    batch_dir: Path,
    samples_by_name: dict[str, list[Sample]],
) -> int | None:
    """Resolve a message's wire size via its bytes_source."""
    return _resolve_bytes_source(message.bytes_source, batch_dir, samples_by_name)


def resolve_key_bytes(
    key: KeyEntry,
    batch_dir: Path,
    samples_by_name: dict[str, list[Sample]],
) -> int | None:
    """Resolve a key's serialized size via its bytes_source."""
    return _resolve_bytes_source(key.bytes_source, batch_dir, samples_by_name)
