"""CKKS parameters for C3AE FHE experiments (logn16, no-bootstrap)."""

from orion_compiler import CKKSParams

PARAMS: dict[str, CKKSParams] = {
    # LogN16_D16_P6: 17 Q primes (1x55 + 16x40), 6 P primes (55), depth=16.
    # The extra Q prime over the standard logn16 spec gives the deepest C3AE
    # compile one unused level so MAC's slot-mask multiply can run without
    # mod-Q wraparound at level 0.
    "logn16": CKKSParams(
        logn=16,
        logq=(55, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40),
        logp=(55, 55, 55, 55, 55, 55),
        log_default_scale=40,
        ring_type="standard",
    ),
}
