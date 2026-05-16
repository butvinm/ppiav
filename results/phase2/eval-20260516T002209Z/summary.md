# Eval summary — eval-20260516T002209Z

> **Caveat:** the FPR / FNR / accuracy and SNR numbers below are NOT
> interpretable as protocol correctness yet — the verdict threshold and
> the noise/ref_logit scale are mismatched (deferred Task 27a in
> `docs/plans/completed/20260515-bench-eval-redesign.md`). The wall-time,
> RSS, per-message bytes, and network tables are valid measurements of
> the protocol's cost and footprint, which is what this batch is for.

- batch dir: `/home/ubuntu/ppiav/results/phase2/eval-20260516T002209Z`
- images: 10
- keygen samples: 5

## Per-step wall time

| step            |   n |   mean ms |    p50 ms |    p95 ms |
| --------------- | --: | --------: | --------: | --------: |
| keygen (total)  |   1 | 172729.64 |         — |         — |
| keygen.open     |   1 |     41.17 |     41.17 |     41.17 |
| keygen.pk       |   1 |    152.28 |    152.28 |    152.28 |
| keygen.rlk-r1   |   1 |    715.59 |    715.59 |    715.59 |
| keygen.rlk-r2   |   1 |    280.73 |    280.73 |    280.73 |
| keygen.galois   |   1 | 171539.87 | 171539.87 | 171539.87 |
| encrypt         |  10 |    116.38 |    116.30 |    123.72 |
| infer           |  10 | 247538.24 | 247549.70 | 253777.96 |
| mac             |  10 |   1298.91 |   1292.70 |   1331.45 |
| partial-decrypt |  10 |      4.16 |      4.17 |      4.28 |
| finalize        |  10 |      7.34 |      7.24 |      7.86 |

## Per-step RSS

| step            | mean delta RSS MiB | mean VM HWM MiB |
| --------------- | -----------------: | --------------: |
| keygen.open     |                0.0 |          1996.5 |
| keygen.pk       |                0.0 |          1996.7 |
| keygen.rlk-r1   |              273.6 |          2270.3 |
| keygen.rlk-r2   |              308.4 |          2578.7 |
| keygen.galois   |            63489.5 |         66068.3 |
| encrypt         |               26.4 |           121.5 |
| infer           |            73570.5 |        117946.9 |
| mac             |                0.6 |         42817.3 |
| partial-decrypt |                0.4 |            77.8 |
| finalize        |                0.7 |            77.8 |

## Per-message bytes

| message              |       bytes |        KiB |      MiB |
| -------------------- | ----------: | ---------: | -------: |
| keys/glk_full.bin    | 22284736438 | 21762437.9 | 21252.38 |
| keys/glk_master.bin  | 22284736438 | 21762437.9 | 21252.38 |
| keys/mac_key.bin     |         302 |        0.3 |     0.00 |
| keys/params.json     |         508 |        0.5 |     0.00 |
| keys/pk.bin          |    23069064 |    22528.4 |    22.00 |
| keys/rlk.bin         |    69207232 |    67585.2 |    66.00 |
| keys/sid.txt         |          32 |        0.0 |     0.00 |
| keys/sk_a.bin        |    11534528 |    11264.2 |    11.00 |
| keys/sk_c.bin        |    11534528 |    11264.2 |    11.00 |
| img/auth_ct.bin      |     1048894 |     1024.3 |     1.00 |
| img/client_share.bin |      524304 |      512.0 |     0.50 |
| img/input_ct.bin     |    16777774 |    16384.5 |    16.00 |
| img/result_ct.bin    |     1048894 |     1024.3 |     1.00 |

_Note: `glk_master.bin` and `glk_full.bin` are byte-identical today; they diverge under Phase-4 lattigo-hierkeys (master = compressed seed, full = expanded set)._

## Protocol verdict accuracy

| metric          | value |
| --------------- | ----: |
| samples (total) |    10 |
| true positives  |     0 |
| true negatives  |     5 |
| false positives |     0 |
| false negatives |     5 |
| unknown         |     0 |
| FPR             | 0.000 |
| FNR             | 1.000 |
| accuracy        | 0.500 |

## Noise + SNR

**Noise across all (image x non-S slot) pairs:**

| stat    |        value |
| ------- | -----------: |
| samples |          640 |
| mean    |  -158.122061 |
| min     | -1216.950195 |
| max     |    78.849648 |
| std     |   375.087690 |

**SNR per image** (`|ref_logit| / std(noise_per_slot_i)`):

| idx | \|ref_logit\| |               SNR |
| --: | ------------: | ----------------: |
|   0 |       16.5628 |   356407533815.99 |
|   1 |     1216.9502 | 25275629365730.30 |
|   2 |       20.0280 |   466321022643.52 |
|   3 |      408.5040 |  8288942550761.64 |
|   4 |       10.6847 |   185564217764.74 |
|   5 |       13.1281 |   269400445284.14 |
|  24 |       33.4911 |   746551019545.66 |
|  25 |       26.9990 |   633277920015.15 |
|  35 |        7.7763 |   167396577571.96 |
|  43 |       78.8496 |  1623578110509.21 |

## Network wire time

| message              |       bytes |  t @ 1 Mbps | t @ 10 Mbps | t @ 100 Mbps |
| -------------------- | ----------: | ----------: | ----------: | -----------: |
| keys/glk_full.bin    | 22284736438 | 2971.30 min |  297.13 min |    29.71 min |
| keys/glk_master.bin  | 22284736438 | 2971.30 min |  297.13 min |    29.71 min |
| keys/mac_key.bin     |         302 |      2.4 ms |      0.2 ms |       0.0 ms |
| keys/params.json     |         508 |      4.1 ms |      0.4 ms |       0.0 ms |
| keys/pk.bin          |    23069064 |    3.08 min |     18.46 s |       1.85 s |
| keys/rlk.bin         |    69207232 |    9.23 min |     55.37 s |       5.54 s |
| keys/sid.txt         |          32 |      0.3 ms |      0.0 ms |       0.0 ms |
| keys/sk_a.bin        |    11534528 |    1.54 min |      9.23 s |     922.8 ms |
| keys/sk_c.bin        |    11534528 |    1.54 min |      9.23 s |     922.8 ms |
| img/auth_ct.bin      |     1048894 |      8.39 s |    839.1 ms |      83.9 ms |
| img/client_share.bin |      524304 |      4.19 s |    419.4 ms |      41.9 ms |
| img/input_ct.bin     |    16777774 |    2.24 min |     13.42 s |       1.34 s |
| img/result_ct.bin    |     1048894 |      8.39 s |    839.1 ms |      83.9 ms |
