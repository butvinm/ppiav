# Eval summary — 20260516T002209Z

- batch dir: `/home/butvinm/Dev/ppiav/results/20260516T002209Z`
- images: 10
- keygen samples: 5

## Per-step time + memory by party

| party              | step                                  |   n | mean wall ms | p95 wall ms | mean delta RSS MiB | peak VM HWM MiB |
| ------------------ | ------------------------------------- | --: | -----------: | ----------: | -----------------: | --------------: |
| совместно          | генерация ключей (всего)              |   1 |    172729.64 |           - |                  - |               - |
| совместно          | &nbsp;&nbsp;инициализация сессии      |   1 |        41.17 |       41.17 |                0.0 |          1996.5 |
| совместно          | &nbsp;&nbsp;генерация pk              |   1 |       152.28 |      152.28 |                0.0 |          1996.7 |
| совместно          | &nbsp;&nbsp;генерация rlk, раунд 1    |   1 |       715.59 |      715.59 |              273.6 |          2270.3 |
| совместно          | &nbsp;&nbsp;генерация rlk, раунд 2    |   1 |       280.73 |      280.73 |              308.4 |          2578.7 |
| совместно          | &nbsp;&nbsp;генерация ключей вращения |   1 |    171539.87 |   171539.87 |            63489.5 |         66068.3 |
| клиент верификации | шифрование изображения                |  10 |       116.38 |      123.72 |               26.4 |           121.5 |
| сервис верификации | инференс                              |  10 |    247538.24 |   253777.96 |            73570.5 |        117946.9 |
| агент верификации  | аутентификация шифротекста            |  10 |      1298.91 |     1331.45 |                0.6 |         42817.3 |
| клиент верификации | частичная расшифровка                 |  10 |         4.16 |        4.28 |                0.4 |            77.8 |
| агент верификации  | окончательная расшифровка             |  10 |         7.34 |        7.86 |                0.7 |            77.8 |

_delta RSS = vm_hwm - pre_vm_hwm = the step's incremental memory growth. Peak VM HWM = high-water mark of the resident set at step exit. Keygen sub-rounds share one process, so each row's pre_vm_hwm is the previous row's vm_hwm; the delta for `keygen.galois` is the marginal cost of the Galois-key round on top of the prior PK + RLK state. Per-image steps each spawn a fresh process, so their delta RSS is the true per-call peak._

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

_Note: `glk_master.bin` and `glk_full.bin` are byte-identical today; they diverge after lattigo-hierkeys integration (master = compressed seed, full = expanded set)._

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
|   0 |       16.5628 |   356407533779.38 |
|   1 |     1216.9502 | 25275613883523.46 |
|   2 |       20.0280 |   466321021669.76 |
|   3 |      408.5040 |  8288938625556.57 |
|   4 |       10.6847 |   185564217739.82 |
|   5 |       13.1281 |   269400445269.99 |
|  24 |       33.4911 |   746551017348.64 |
|  25 |       26.9990 |   633277919280.26 |
|  35 |        7.7763 |   167396577552.53 |
|  43 |       78.8496 |  1623578095236.61 |

## Network wire time

| message              |       bytes | t @ 1 Mbps | t @ 10 Mbps | t @ 100 Mbps |
| -------------------- | ----------: | ---------: | ----------: | -----------: |
| keys/glk_full.bin    | 22284736438 |     2.06 d |      4.95 h |    29.71 min |
| keys/glk_master.bin  | 22284736438 |     2.06 d |      4.95 h |    29.71 min |
| keys/mac_key.bin     |         302 |     2.4 ms |      0.2 ms |       0.0 ms |
| keys/params.json     |         508 |     4.1 ms |      0.4 ms |       0.0 ms |
| keys/pk.bin          |    23069064 |   3.08 min |     18.46 s |       1.85 s |
| keys/rlk.bin         |    69207232 |   9.23 min |     55.37 s |       5.54 s |
| keys/sid.txt         |          32 |     0.3 ms |      0.0 ms |       0.0 ms |
| keys/sk_a.bin        |    11534528 |   1.54 min |      9.23 s |     922.8 ms |
| keys/sk_c.bin        |    11534528 |   1.54 min |      9.23 s |     922.8 ms |
| img/auth_ct.bin      |     1048894 |     8.39 s |    839.1 ms |      83.9 ms |
| img/client_share.bin |      524304 |     4.19 s |    419.4 ms |      41.9 ms |
| img/input_ct.bin     |    16777774 |   2.24 min |     13.42 s |       1.34 s |
| img/result_ct.bin    |     1048894 |     8.39 s |    839.1 ms |      83.9 ms |
