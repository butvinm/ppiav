"""CKKS parameters for C3AE FHE experiments (logn16, no-bootstrap)."""

from orion_compiler import CKKSParams

PARAMS: dict[str, CKKSParams] = {
    "logn16": CKKSParams(
        logn=16,
        logq=(55, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40),
        logp=(55, 55, 55, 55, 55, 55),
        log_default_scale=40,
        ring_type="standard",
    ),
}
