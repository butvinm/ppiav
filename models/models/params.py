"""CKKS parameters for C3AE FHE experiments (logn16, no-bootstrap)."""

from orion_compiler import CKKSParams

PARAMS: dict[str, CKKSParams] = {
    # LogN16_D15_P6_R1: 17 Q primes (1x55 + 16x40), 6 P primes (55).
    # 16 primes cover the C3AE model's 15 multiplicative levels of depth
    # (input_level=15 if compiled with reserve_output_levels=0); the
    # extra 17th prime gives orion-v2-compiler's bootstrap solver room
    # to bump input_level by `CompilerConfig.reserve_output_levels` so
    # the compiled circuit's final node lands at level >= 1 — the
    # headroom MAC's slot-mask multiply requires. Drive the bump from
    # `models.compile --reserve-output-levels 1`.
    "logn16": CKKSParams(
        logn=16,
        logq=(55, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40),
        logp=(55, 55, 55, 55, 55, 55),
        log_default_scale=40,
        ring_type="standard",
    ),
}
