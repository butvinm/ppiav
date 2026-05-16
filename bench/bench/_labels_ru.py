"""Russian labels for bench plots and summary tables.

Edit the right-hand strings below; the left-hand keys are stable and used by
``plots_eval`` and ``eval`` aggregator. Keep English abbreviations for
cryptographic artefacts (pk, rlk, glk, sk_c, sk_a, mac_key, sid, params).

After editing, regenerate plots without rerunning the protocol:

    python -m bench.eval --aggregate-only path/to/results/<ts>/

The aggregator + plots_eval import from this module at runtime, so changes
take effect on the next replot without any rebuild.
"""

from __future__ import annotations

# Step / sub-step display names. Used as bar / row labels in plots and
# in the summary.md tables.
STEP_NAMES: dict[str, str] = {
    # collaborative keygen sub-rounds (joint, no single party)
    "keygen": "генерация ключей",
    "keygen.open": "открытие сессии",
    "keygen.pk": "агрегация pk",
    "keygen.rlk-r1": "rlk раунд 1",
    "keygen.rlk-r2": "rlk раунд 2",
    "keygen.galois": "galois ключи",
    # per-image protocol steps
    "encrypt": "шифрование",
    "infer": "инференс",
    "mac": "MPD-Auth",
    "partial-decrypt": "частичная расшифровка",
    "finalize": "финализация",
}

# Party display names (for swim-lane Gantt rows and per-party tables).
PARTY_NAMES: dict[str, str] = {
    "client": "клиент",
    "service": "сервис",
    "agent": "агент",
    "joint": "совместно",
}

# Axis / legend / table-header strings. Keys are internal; values are
# user-visible Russian text. Free to rephrase.
AXIS: dict[str, str] = {
    # x / y axes
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
    # gantt lane label
    "party_lane": "сторона",
    # message column
    "message_name": "сообщение",
}

# Legend entries (Gantt + macro-phase colours).
LEGEND: dict[str, str] = {
    "compute": "вычисления",
    "transfer": "передача",
    "setup_compute": "подготовка (вычисления)",
    "inference_compute": "инференс (вычисления)",
    "verify_compute": "проверка (вычисления)",
    "macro_setup": "подготовка",
    "macro_inference": "инференс",
    "macro_verify": "проверка",
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
# session-timeline Gantt. Each tuple is (sender_party, receiver_party,
# artifact_filename). The artifact is sized via os.stat at aggregate time.
TRANSFERS_PER_IMAGE: tuple[tuple[str, str, str], ...] = (
    ("client", "service", "input_ct.bin"),
    ("service", "agent", "result_ct.bin"),
    ("agent", "client", "auth_ct.bin"),
    ("client", "agent", "client_share.bin"),
)
