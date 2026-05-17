"""CKKS parameters for C3AE FHE experiments (logn16, no-bootstrap)."""

from orion_compiler import CKKSParams

PARAMS: dict[str, CKKSParams] = {
    # LogN16_D15_P6: 16 Q primes (1x55 + 15x40), 6 P primes (55).
    # This declares ONLY what the C3AE model needs: 15 multiplicative levels
    # of depth (input_level=15, encrypt at MaxLevel=15, 15 rescales, output
    # at level 0). Headroom that protocol-layer operations need on top
    # (MAC's slot-mask multiply requires level ≥ 1) is added by the Go
    # protocol layer in `internal/protocol/orion_params.go::LoadOrionParams`,
    # the same way LLKN's PHK primes live outside the model's view.
    "logn16": CKKSParams(
        logn=16,
        logq=(55, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40),
        logp=(55, 55, 55, 55, 55, 55),
        log_default_scale=40,
        ring_type="standard",
    ),
}
