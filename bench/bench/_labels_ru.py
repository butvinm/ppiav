"""Russian labels for bench plots and summary tables.

The defaults below are derived from ``docs/protocol.puml`` (the canonical
sequence diagram). Edit the right-hand strings to taste; the left-hand
keys are stable and used by ``plots_eval`` and the ``eval`` aggregator.
Keep English abbreviations for cryptographic artefacts (pk, rlk, glk,
sk_c, sk_a, mac_key, sid, params) per the user convention.

After editing, regenerate plots without rerunning the protocol:

    cd bench
    uv run python -m bench.eval --aggregate-only ../results/<ts>/

The aggregator + plots_eval import from this module at runtime, so
changes take effect on the next replot without any rebuild.

Mapping from protocol.puml section headers to step keys:
    keygen.open     ← "Инициализация сессии верификации"
    keygen.pk       ← "Генерация открытого ключа"
    keygen.rlk-r1   ← "Генерация ключа релинеаризации (раунд 1)"
    keygen.rlk-r2   ← "Генерация ключа релинеаризации (раунд 2)"
    keygen.galois   ← "Генерация ключей вращения"
    encrypt         ← "Захват и шифрование изображения"
    infer           ← "Инференс на зашифрованных данных"
    mac             ← "Создание аутентифицированного шифротекста"
    partial-decrypt ← "Частичная расшифровка" + "Noise flooding"
    finalize        ← "Окончательная расшифровка" + "Проверка аутентичности"
                      + "Вычисление вердикта верификации"
"""

from __future__ import annotations

# Step / sub-step display names — short Russian phrasings derived from
# protocol.puml section headers. Plot bars are tight on space, so each
# value is kept to ~3 words max.
STEP_NAMES: dict[str, str] = {
    # Round-level keygen labels (legacy bench runs emit these directly).
    "keygen": "генерация ключей",
    "keygen.open": "инициализация сессии",
    "keygen.pk": "генерация pk",
    "keygen.rlk-r1": "генерация rlk, раунд 1",
    "keygen.rlk-r2": "генерация rlk, раунд 2",
    "keygen.galois": "генерация ключей вращения",
    # Per-party keygen sub-steps emitted by the instrumented driver
    # (ppiav-cli keygen). Each round splits into per-party Gen + Agg
    # phases. Future bench runs surface these in the per-party table
    # and Gantt; legacy round-level samples are aggregated into the
    # round totals shown in the "Keygen by round" table.
    "keygen.open.service": "инициализация сессии (сервис)",
    "keygen.open.agent": "инициализация сессии (агент)",
    "keygen.open.client": "инициализация сессии (клиент)",
    "keygen.pk.client_gen": "pk: генерация sk_c, pk_c",
    "keygen.pk.agent_gen": "pk: генерация sk_a, pk_a",
    "keygen.pk.agent_agg": "pk: агрегация (агент)",
    "keygen.pk.client_agg": "pk: агрегация (клиент)",
    "keygen.rlk-r1.client_gen": "rlk р1: генерация ephSk_c, rlk_c",
    "keygen.rlk-r1.agent_gen": "rlk р1: генерация ephSk_a, rlk_a",
    "keygen.rlk-r1.agent_agg": "rlk р1: агрегация (агент)",
    "keygen.rlk-r1.client_agg": "rlk р1: агрегация (клиент)",
    "keygen.rlk-r2.client_gen": "rlk р2: генерация rlk_c",
    "keygen.rlk-r2.agent_gen": "rlk р2: генерация rlk_a",
    "keygen.rlk-r2.agent_agg": "rlk р2: агрегация rlk (агент)",
    "keygen.galois.client_gen": "gks: генерация gks_master_c",
    "keygen.galois.agent_gen": "gks: генерация gks_master_a",
    "keygen.galois.agent_agg": "gks: агрегация + иерархический вывод (агент)",
    "keygen.galois.service_store": "gks: иерархический вывод (сервис)",
    # Per-image protocol steps.
    "encrypt": "шифрование изображения",
    "infer": "инференс",
    "mac": "аутентификация шифротекста",
    "partial-decrypt": "частичная расшифровка",
    "finalize": "окончательная расшифровка",
}

# Round → ordered list of per-party sub-step keys, used by the aggregator
# to render the "Keygen by round" table and to drive Gantt rendering when
# the per-party samples are present in keygen.json.
KEYGEN_ROUND_SUBSTEPS: dict[str, tuple[str, ...]] = {
    "keygen.open": (
        "keygen.open.service",
        "keygen.open.agent",
        "keygen.open.client",
    ),
    "keygen.pk": (
        "keygen.pk.client_gen",
        "keygen.pk.agent_gen",
        "keygen.pk.agent_agg",
        "keygen.pk.client_agg",
    ),
    "keygen.rlk-r1": (
        "keygen.rlk-r1.client_gen",
        "keygen.rlk-r1.agent_gen",
        "keygen.rlk-r1.agent_agg",
        "keygen.rlk-r1.client_agg",
    ),
    "keygen.rlk-r2": (
        "keygen.rlk-r2.client_gen",
        "keygen.rlk-r2.agent_gen",
        "keygen.rlk-r2.agent_agg",
    ),
    "keygen.galois": (
        "keygen.galois.client_gen",
        "keygen.galois.agent_gen",
        "keygen.galois.agent_agg",
        "keygen.galois.service_store",
    ),
}

# Party display names — derived from protocol.puml actor declarations
# (`participant "..." as ...`). Used for swim-lane Gantt rows and the
# per-party memory table. Short enough to fit on the y-axis.
PARTY_NAMES: dict[str, str] = {
    "client": "клиент верификации",
    "service": "сервис верификации",
    "agent": "агент верификации",
    "joint": "совместно",
}

# Axis / legend / table-header strings.
AXIS: dict[str, str] = {
    "wall_ms": "время выполнения, мс",
    "wall_s": "время выполнения, с",
    "delta_rss_mib": "прирост RSS, МиБ",
    "vm_hwm_mib": "пик RSS, МиБ",
    "bytes_log": "размер сообщения, байт (лог. шкала)",
    "noise_value": "шум в слоте",
    "noise_count": "число слотов",
    "snr_value": "SNR (|ref_logit| / std(шум))",
    "image_idx": "индекс изображения",
    "transfer_seconds": "время передачи, с",
    "session_seconds": "время сессии, с",
    "session_ms": "время сессии, мс",
    "party_lane": "сторона",
    "message_name": "сообщение",
}

# Legend entries (Gantt + macro-phase colours).
LEGEND: dict[str, str] = {
    "compute": "вычисления",
    "transfer": "передача по сети",
    "setup_compute": "генерация ключей (вычисления)",
    "inference_compute": "инференс (вычисления)",
    "verify_compute": "проверка (вычисления)",
    "macro_setup": "генерация ключей",
    "macro_inference": "инференс",
    "macro_verify": "проверка результата",
}

# Per-step → party mapping. Per-party keygen sub-steps map to their
# specific party (no "joint" anywhere). Legacy round-level keys keep a
# "joint" tag but are NOT placed on any Gantt lane; the aggregator
# renders them in the "Keygen by round" no-party table.
PARTY_BY_STEP: dict[str, str] = {
    # Legacy round-level keys: aggregator handles separately.
    "keygen": "joint",
    "keygen.open": "joint",
    "keygen.pk": "joint",
    "keygen.rlk-r1": "joint",
    "keygen.rlk-r2": "joint",
    "keygen.galois": "joint",
    # Per-party keygen sub-steps.
    "keygen.open.service": "service",
    "keygen.open.agent": "agent",
    "keygen.open.client": "client",
    "keygen.pk.client_gen": "client",
    "keygen.pk.agent_gen": "agent",
    "keygen.pk.agent_agg": "agent",
    "keygen.pk.client_agg": "client",
    "keygen.rlk-r1.client_gen": "client",
    "keygen.rlk-r1.agent_gen": "agent",
    "keygen.rlk-r1.agent_agg": "agent",
    "keygen.rlk-r1.client_agg": "client",
    "keygen.rlk-r2.client_gen": "client",
    "keygen.rlk-r2.agent_gen": "agent",
    "keygen.rlk-r2.agent_agg": "agent",
    "keygen.galois.client_gen": "client",
    "keygen.galois.agent_gen": "agent",
    "keygen.galois.agent_agg": "agent",
    "keygen.galois.service_store": "service",
    # Per-image steps.
    "encrypt": "client",
    "infer": "service",
    "mac": "agent",
    "partial-decrypt": "client",
    "finalize": "agent",
}

# Producer → consumer mapping for the per-image transfer arrows in the
# session-timeline Gantt. Mirrors the message flow in protocol.puml's
# inference + verifiable-decryption sections. Each tuple is
# (sender_party, receiver_party, artifact_filename); the artifact is
# sized via os.stat at aggregate time.
TRANSFERS_PER_IMAGE: tuple[tuple[str, str, str], ...] = (
    ("client", "service", "input_ct.bin"),
    ("service", "agent", "result_ct.bin"),
    ("agent", "client", "auth_ct.bin"),
    ("client", "agent", "client_share.bin"),
)
