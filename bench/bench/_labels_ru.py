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
    "keygen": "генерация ключей",
    "keygen.open": "инициализация сессии",
    "keygen.pk": "генерация pk",
    "keygen.rlk-r1": "генерация rlk, раунд 1",
    "keygen.rlk-r2": "генерация rlk, раунд 2",
    "keygen.galois": "генерация ключей вращения",
    "encrypt": "шифрование изображения",
    "infer": "инференс",
    "mac": "аутентификация шифротекста",
    "partial-decrypt": "частичная расшифровка",
    "finalize": "окончательная расшифровка",
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

# Per-step → party mapping (used for the swim-lane Gantt row assignment
# and the per-party memory table). Keep keys aligned with ``STEP_NAMES``.
PARTY_BY_STEP: dict[str, str] = {
    "keygen": "joint",
    "keygen.open": "joint",
    "keygen.pk": "joint",
    "keygen.rlk-r1": "joint",
    "keygen.rlk-r2": "joint",
    "keygen.galois": "joint",
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
