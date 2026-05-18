"""Protocol message + key catalog.

Authoritative inventory of every wire message in ``docs/protocol.puml`` and
every key the protocol manipulates. Drives the per-message bytes table, the
key inventory table, and the network wire-time table in ``summary.md``.

The catalog is data-only: ``MESSAGES`` and ``KEYS`` are immutable lists of
frozen dataclasses; the size resolvers (``resolve_message_bytes``,
``resolve_key_bytes``) dispatch on the ``bytes_source`` variant tag.

Scope: this catalog covers VClient↔VAgent and VAgent↔VService wire
messages. Resource-service-side traffic (ResourceClient↔ResourceService and
ResourceService↔VerificationAgent in ``docs/protocol.puml`` — L14-L15,
L18, L23-L24, L27-L28, L93-L95, L98, L101-L107) is explicitly out of scope
per the bench-redesign-v2 plan: the bench measures the FHE protocol
itself, not the surrounding resource-access plumbing.

Naming convention: ``Message.id`` matches the Go wire-struct name in
``internal/protocol/wire.go`` (e.g. ``SessionOpen``, ``Manifest``,
``InferEvalKeys``, ``EncryptedImage``, ``InferenceResult``,
``AuthenticatedResult``, ``PartialDecryption``, ``FinalizeRedirect``).
Empty-body HTTP events that have no Go wire struct (the ``RequestX``
GETs, the ``XxxAck`` empty-200 responses) use CamelCase names derived
from the protocol.puml arrow labels.

Same Go type traversing two hops appears as TWO catalog entries with
the SAME ``id`` but different ``(sender, receiver)``. The catalog's
uniqueness key is the tuple ``(id, sender, receiver)``.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal, NamedTuple

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
class MultiFilePath:
    """Sum of stat sizes across multiple ``batch_dir / rel`` paths.

    Returns ``None`` if ANY file is missing — the message renders as ``—``
    rather than silently undercounting the bundle.
    """

    rels: tuple[str, ...]


@dataclass(frozen=True)
class SampleBytes:
    """Size resolved by reading ``samples_by_name[name][0].bytes``."""

    name: str


@dataclass(frozen=True)
class Synthetic:
    """Size is a constant — for tiny handshake / ack envelopes with no on-disk artifact."""

    size: int


BytesSource = FilePath | MultiFilePath | SampleBytes | Synthetic


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


# Ordered chronological list of per-image step Sample names emitted by the
# per-image subcommands. Drives the per-party table iteration order in
# bench.eval and the Gantt lane ordering in bench.plots_eval.
PER_IMAGE_STEPS: tuple[str, ...] = (
    "encrypt",
    "infer.load_keys",
    "infer.load_input_ct",
    "infer.exec",
    "infer.serialize_result",
    "mac.derive_auth_keys",
    "mac.compute_ct",
    "partial-decrypt",
    "finalize.final_decrypt",
    "finalize.verdict_compute",
)

# Parent-stage names derived from PER_IMAGE_STEPS — one entry per per-image
# subcommand JSON file (encrypt.json, infer.json, ...). Order matches the
# chronological PER_IMAGE_STEPS order.
PER_IMAGE_STAGES: tuple[str, ...] = tuple(
    dict.fromkeys(s.split(".", 1)[0] for s in PER_IMAGE_STEPS)
)


class MessageBytesRow(NamedTuple):
    """One row of the per-message bytes table; size=None renders as em-dash."""

    message_id: str
    label_ru: str
    sender: str
    receiver: str
    size: int | None


class KeyInventoryRow(NamedTuple):
    """One row of the key inventory table; size=None renders as em-dash."""

    key_name: str
    location: str
    on_wire: str
    size: int | None


# Authoritative message catalog. Order is chronological by phase: session
# open → manifest fetch → keygen (pk, rlk r1, rlk r2, galois) → eval-key
# upload → result subscription → image submission → inference → verifiable
# decryption.
#
# Ids match Go wire structs in internal/protocol/wire.go where one exists.
# CamelCase puml-arrow names cover the empty-body request/ack events.
MESSAGES: list[Message] = [
    # -- Session start (POST /sessions) ----------------------------------------
    Message(
        id="SessionOpen",
        sender="client",
        receiver="agent",
        label_ru="Открытие сессии (клиент → агент)",
        bytes_source=Synthetic(64),
    ),
    Message(
        id="SessionOpen",
        sender="agent",
        receiver="service",
        label_ru="Открытие сессии (агент → сервис)",
        bytes_source=Synthetic(64),
    ),
    Message(
        id="VerificationSession",
        sender="service",
        receiver="agent",
        label_ru="Идентификатор сессии (сервис → агент)",
        bytes_source=Synthetic(96),
    ),
    Message(
        id="VerificationSession",
        sender="agent",
        receiver="client",
        label_ru="Идентификатор сессии (агент → клиент)",
        bytes_source=Synthetic(96),
    ),
    # -- Manifest fetch (GET /params) -----------------------------------------
    Message(
        id="RequestManifest",
        sender="client",
        receiver="agent",
        label_ru="Запрос параметров протокола (клиент → агент)",
        bytes_source=Synthetic(64),
    ),
    Message(
        id="RequestManifest",
        sender="agent",
        receiver="service",
        label_ru="Запрос параметров протокола (агент → сервис)",
        bytes_source=Synthetic(64),
    ),
    Message(
        id="Manifest",
        sender="service",
        receiver="agent",
        label_ru="Параметры протокола (сервис → агент)",
        bytes_source=FilePath("keys/params.json"),
    ),
    Message(
        id="Manifest",
        sender="agent",
        receiver="client",
        label_ru="Параметры протокола (агент → клиент)",
        bytes_source=FilePath("keys/params.json"),
    ),
    # -- PK round (POST /pk-share) -------------------------------------------
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
    # -- RLK round 1 (POST /rlk/round1) --------------------------------------
    Message(
        id="VClientRLKRound1",
        sender="client",
        receiver="agent",
        label_ru="Доля rlk клиента, раунд 1",
        bytes_source=SampleBytes("keygen.rlk-r1.client_gen"),
    ),
    Message(
        id="VAgentRLKRound1",
        sender="agent",
        receiver="client",
        label_ru="Доля rlk агента, раунд 1",
        bytes_source=SampleBytes("keygen.rlk-r1.agent_gen"),
    ),
    # -- RLK round 2 (POST /rlk/round2, empty 200 reply) --------------------
    Message(
        id="VClientRLKRound2",
        sender="client",
        receiver="agent",
        label_ru="Доля rlk клиента, раунд 2",
        bytes_source=SampleBytes("keygen.rlk-r2.client_gen"),
    ),
    Message(
        id="RLKRound2Ack",
        sender="agent",
        receiver="client",
        label_ru="Подтверждение rlk р2 (HTTP 200)",
        bytes_source=Synthetic(32),
    ),
    # -- Galois shares (POST /gks-shares) ------------------------------------
    Message(
        id="VClientGaloisShares",
        sender="client",
        receiver="agent",
        label_ru="Master доли gks клиента",
        bytes_source=SampleBytes("keygen.galois.client_gen"),
    ),
    Message(
        id="GaloisSharesAck",
        sender="agent",
        receiver="client",
        label_ru="Подтверждение gks (HTTP 200)",
        bytes_source=Synthetic(32),
    ),
    # -- Eval key bundle upload (POST /eval-keys) ----------------------------
    Message(
        id="InferEvalKeys",
        sender="agent",
        receiver="service",
        label_ru="rlk + pk_top + gks_master → сервису",
        bytes_source=SampleBytes("keygen.eval_keys_bundle"),
    ),
    Message(
        id="EvalKeysAck",
        sender="service",
        receiver="agent",
        label_ru="Подтверждение установки ключей (HTTP 200)",
        bytes_source=Synthetic(32),
    ),
    # -- Result subscription (GET /sessions/{sid}/result, SSE open) ----------
    Message(
        id="RequestResult",
        sender="client",
        receiver="agent",
        label_ru="Подписка на результат (SSE)",
        bytes_source=Synthetic(64),
    ),
    # -- Image submission + forward (POST /image, POST /infer) ---------------
    Message(
        id="EncryptedImage",
        sender="client",
        receiver="agent",
        label_ru="Шифротекст изображения (клиент → агент)",
        bytes_source=SampleBytes("encrypt"),
    ),
    Message(
        id="EncryptedImage",
        sender="agent",
        receiver="service",
        label_ru="Шифротекст изображения (агент → сервис)",
        bytes_source=SampleBytes("encrypt"),
    ),
    # -- Inference result (response from /infer) ------------------------------
    Message(
        id="InferenceResult",
        sender="service",
        receiver="agent",
        label_ru="Шифротекст результата",
        bytes_source=SampleBytes("infer.serialize_result"),
    ),
    # -- Authenticated result delivery (SSE event) ---------------------------
    Message(
        id="AuthenticatedResult",
        sender="agent",
        receiver="client",
        label_ru="Аутентифицированный шифротекст",
        bytes_source=SampleBytes("mac.compute_ct"),
    ),
    # -- Partial decryption return (POST /partial-decryption) ----------------
    Message(
        id="PartialDecryption",
        sender="client",
        receiver="agent",
        label_ru="Частично расшифрованный шифротекст",
        bytes_source=SampleBytes("partial-decrypt"),
    ),
    # -- Finalize redirect (response from /partial-decryption) ---------------
    Message(
        id="FinalizeRedirect",
        sender="agent",
        receiver="client",
        label_ru="Перенаправление на страницу ресурса",
        bytes_source=Synthetic(128),
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
        location="aggregated_all",
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
        - ``MultiFilePath(rels)``: sum of ``stat().st_size`` across every rel;
          ``None`` if ANY file is missing (no silent under-counting).
        - ``SampleBytes(name)``: ``samples_by_name[name][0].bytes`` if the name
          is present and its first sample has a non-zero Bytes field, else
          ``None``. We treat ``Bytes == 0`` as "not measured" so callers can
          distinguish from a genuine zero-byte payload (which never occurs in
          practice for our share types).
        - ``Synthetic(n)``: ``n``.
    """
    if isinstance(source, FilePath):
        path = batch_dir / source.rel
        if not path.is_file():
            return None
        return path.stat().st_size
    if isinstance(source, MultiFilePath):
        total = 0
        for rel in source.rels:
            path = batch_dir / rel
            if not path.is_file():
                return None
            total += path.stat().st_size
        return total
    if isinstance(source, SampleBytes):
        samples = samples_by_name.get(source.name)
        if not samples:
            return None
        first = samples[0]
        if first.bytes <= 0:
            return None
        return first.bytes
    if isinstance(source, Synthetic):
        return source.size
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
