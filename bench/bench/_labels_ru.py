"""Russian labels for bench plots and summary tables.

The defaults below are derived from ``docs/protocol.puml`` (the canonical
sequence diagram). Edit the right-hand strings to taste; the left-hand
keys are stable and used by ``plots_eval`` and the ``eval`` aggregator.
Keep English abbreviations for cryptographic artefacts (pk, rlk, gks,
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
    # Round-level keygen labels — used by _keygen_by_round_table_md to label
    # the joint-round rows (production never emits a Sample named "keygen.*"
    # at this level; the aggregator iterates KEYGEN_ROUND_SUBSTEPS and pulls
    # the round display name from these keys).
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
    # Per-image protocol steps (sub-steppable stages emit one Sample per
    # sub-step; encrypt and partial-decrypt remain single-sample).
    "encrypt": "шифрование изображения",
    "partial-decrypt": "частичная расшифровка",
    # Per-image sub-steps emitted by the instrumented per-image subcommands.
    "infer.load_keys": "инференс: загрузка rlk + gks_infer",
    "infer.load_input_ct": "инференс: загрузка шифротекста входа",
    "infer.exec": "инференс: вычисление",
    "infer.serialize_result": "инференс: сериализация результата",
    "mac.derive_auth_keys": "mac: вывод gks_auth",
    "mac.compute_ct": "mac: вычисление аутентифицированного ct",
    "finalize.final_decrypt": "финализация: расшифровка + Auth",
    "finalize.verdict_compute": "финализация: вычисление вердикта",
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

# Section headers + table column labels for summary.md. Keep keys ASCII;
# values stay Russian per project convention.
SECTION_HEADERS: dict[str, str] = {
    "per_message_bytes": "Размер сообщений",
    "key_inventory": "Инвентарь ключей",
    "network_wire_time": "Время передачи по сети",
    "accuracy_plain_vs_fhe": "Точность: C3AE открытый текст vs FHE",
}

# Column headers for the per-message bytes / key inventory tables. Kept
# here so adjacent tables stay terminology-consistent.
TABLE_HEADERS: dict[str, str] = {
    "message_id": "id",
    "message_label": "сообщение",
    "sender": "отправитель",
    "receiver": "получатель",
    "bytes": "байт",
    "kib": "КиБ",
    "mib": "МиБ",
    "key_name": "ключ",
    "key_location": "расположение",
    "on_wire": "передаётся",
    "on_wire_yes": "да",
    "on_wire_no": "нет",
    "empty": "—",
    "metric": "метрика",
    "plain_column": "открытый текст",
    "fhe_column": "FHE",
}

# Russian labels for the confusion-matrix / rate rows used by the
# plain-vs-FHE accuracy comparison table. Keys mirror the dict returned
# by ``_classify`` plus a synthetic ``samples`` row.
ACCURACY_METRIC_NAMES: dict[str, str] = {
    "samples": "выборка (всего)",
    "tp": "истинно-положительные",
    "tn": "истинно-отрицательные",
    "fp": "ложно-положительные",
    "fn": "ложно-отрицательные",
    "unknown": "не определено",
    "fpr": "FPR",
    "fnr": "FNR",
    "accuracy": "точность",
}

# Display names for KeyEntry.location values (KeyLocation literal).
KEY_LOCATION_NAMES: dict[str, str] = {
    "client_local": "клиент",
    "agent_local": "агент",
    "service_local": "сервис",
    "derived_agent": "агент (производный)",
    "derived_service": "сервис (производный)",
    "aggregated_all": "у всех (агрегированный)",
    "share": "доля (на проводе)",
}

# Display names for Party values used in the per-message bytes table.
PARTY_SHORT_NAMES: dict[str, str] = {
    "client": "клиент",
    "agent": "агент",
    "service": "сервис",
    "resource_service": "ресурс-сервис",
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
    "rate": "доля",
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

# Per-step → party mapping for every Sample name production actually emits.
PARTY_BY_STEP: dict[str, str] = {
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
    "partial-decrypt": "client",
    # Per-image sub-steps.
    "infer.load_keys": "service",
    "infer.load_input_ct": "service",
    "infer.exec": "service",
    "infer.serialize_result": "service",
    "mac.derive_auth_keys": "agent",
    "mac.compute_ct": "agent",
    "finalize.final_decrypt": "agent",
    "finalize.verdict_compute": "agent",
}

# Per-image transfer events for the session-timeline Gantt. Mirrors the
# message flow in protocol.puml's inference + verifiable-decryption sections.
# Each tuple is (after_parent_stage, sender_party, receiver_party, message_id);
# the resolver pulls bytes from the per-message catalog row to size the rect.
# input_ct hops twice on the wire: VClient -> VAgent (VClientInputCT) then
# VAgent -> VService (VAgentInputCT); both are charged separately.
TRANSFERS_PER_IMAGE: tuple[tuple[str, str, str, str], ...] = (
    ("encrypt", "client", "agent", "VClientInputCT"),
    ("encrypt", "agent", "service", "VAgentInputCT"),
    ("infer", "service", "agent", "VServiceResultCT"),
    ("mac", "agent", "client", "VAgentAuthCT"),
    ("partial-decrypt", "client", "agent", "VClientPartialShare"),
)
