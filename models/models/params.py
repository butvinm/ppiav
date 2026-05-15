"""CKKS parameters for C3AE FHE experiments (logn15 and logn16, no-bootstrap)."""

from orion_compiler import CKKSParams

PARAMS: dict[str, CKKSParams] = {
    "logn15": CKKSParams(
        logn=15,
        logq=(51, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40),
        logp=(50, 50, 50, 50),
        log_default_scale=40,
        ring_type="standard",
    ),
    "logn16": CKKSParams(
        logn=16,
        logq=(55, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40),
        logp=(55, 55, 55, 55, 55, 55),
        log_default_scale=40,
        ring_type="standard",
    ),
}
