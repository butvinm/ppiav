# HTTP API

Карта эндпоинтов трёх сервисов протокола ppiav. **Документирует целевой
асинхронный протокол** (см. `docs/protocol-simple.puml`, секции 3 и 4).
Текущая имплементация частично синхронная: POST `/infer` блокируется до
окончания инференса, а `AuthenticatedResult` доставляется через
SSE-буфер VAgent вместо отдельного `GET /result`. Миграция к описанной
здесь форме — в backlog.

Источники истины: `internal/vservice/http.go`, `internal/vagent/http.go`,
`internal/rservice/http.go`, типы сообщений — `internal/protocol/wire.go`,
лимиты тел — `internal/httputil/`.

Используемые лимиты тела:

- `MaxJSONBody = 64 KiB` — JSON control-эндпоинты.
- `MaxShareBody = 128 MiB` — одиночные доли (pk-share, RLK round1/2, partial-decryption).
- `MaxGksSharesBody = 2 GiB` — агрегированный блок Galois-долей.
- `MaxEvalKeysBody = 3 GiB` — `InferEvalKeys` и зашифрованные изображения/результаты.

---

## VService

Внутренний сервис, к которому ходит VAgent server-to-server. Браузер сюда
не обращается.

| Точка API                        | Запрос           | Ответ                                                              |
| -------------------------------- | ---------------- | ------------------------------------------------------------------ |
| `GET /params`                    | —                | `Manifest`                                                         |
| `POST /sessions`                 | —                | `VerificationSession`                                              |
| `POST /sessions/{sid}/eval-keys` | `InferEvalKeys`  | —                                                                  |
| `POST /sessions/{sid}/infer`     | `EncryptedImage` | — (202; инференс запускается асинхронно)                           |
| `GET /sessions/{sid}/result`     | —                | `InferenceResult` (long-poll, блокируется до завершения инференса) |

---

## VAgent

Лицом к пользователю: отдаёт VClient SPA + WASM, принимает доли от
браузера, проксирует в VService, шлёт callback в RService.

Пер-роут дедлайны: `/eval-keys` — 10 мин, `/result` — 5 мин (long-poll на
VService `/result`), прочие server-to-server RPC — 30 с.

Любая ошибка с известным `sid` вызывает `rejectAndEvict` → callback
`VerdictReject` в RService + eviction сессии.

### Статика и SPA

| Точка API                                             | Ответ                              |
| ----------------------------------------------------- | ---------------------------------- |
| `GET /verify`                                         | `text/html` (VClient `index.html`) |
| `GET /dist/*`, `GET /wasm_exec.js`, `GET /styles.css` | ассеты VClient                     |
| `GET /ppiav.wasm`                                     | `application/wasm`                 |

### Stage 1 — открытие сессии

| Точка API        | Запрос | Ответ                 |
| ---------------- | ------ | --------------------- |
| `POST /sessions` | —      | `VerificationSession` |

### Stage 2 — keygen

| Точка API                         | Запрос                | Ответ             |
| --------------------------------- | --------------------- | ----------------- |
| `GET /sessions/{sid}/params`      | —                     | `Manifest`        |
| `POST /sessions/{sid}/pk-share`   | `VClientPKShare`      | `VAgentPKShare`   |
| `POST /sessions/{sid}/rlk/round1` | `VClientRLKRound1`    | `VAgentRLKRound1` |
| `POST /sessions/{sid}/rlk/round2` | `VClientRLKRound2`    | —                 |
| `POST /sessions/{sid}/gks-shares` | `VClientGaloisShares` | —                 |

### Stage 3 / 4 — инференс и финализация

| Точка API                                 | Запрос              | Ответ                                                                                       |
| ----------------------------------------- | ------------------- | ------------------------------------------------------------------------------------------- |
| `POST /sessions/{sid}/image`              | `EncryptedImage`    | — (202; форвардится в VService `/infer`)                                                    |
| `GET /sessions/{sid}/result`              | —                   | `AuthenticatedResult` (long-poll; внутри VAgent тянет VService `GET /result` и считает MAC) |
| `POST /sessions/{sid}/partial-decryption` | `PartialDecryption` | `FinalizeRedirect`                                                                          |

---

## RService

Защищаемый ресурс. Хранит cookie `sid` (`HttpOnly`), запускает Stage-1
редирект на VAgent, принимает финальный verdict.

| Точка API                        | Запрос                | Ответ                                                                                                                                                        |
| -------------------------------- | --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `GET /protected?sid=`            | —                     | без cookie / verdict=Unknown → **302** на `<vagent-public>/verify?sid=...` + `Set-Cookie sid`; иначе `text/html` (RClient SPA), при verdict=Reject — **403** |
| `POST /reset`                    | —                     | **303** → `/protected`, чистит cookie `sid`                                                                                                                  |
| `GET /dist/*`, `GET /styles.css` | —                     | ассеты RClient                                                                                                                                               |
| `POST /api/callback/{sid}`       | `VerdictNotification` | —                                                                                                                                                            |

---

## Типы сообщений

Все бинарные структуры реализуют `encoding.BinaryMarshaler` /
`encoding.BinaryUnmarshaler` (`internal/protocol/wire.go`).

**JSON**

- `VerificationSession` — `{ "session_id": "..." }`.
- `Manifest` — `ckks` + LLKN-расписание + параметры аутентификатора + `flood_sigma` + `extra_rotation_indices` + `input_level`; публичное декларативное описание параметров протокола, из которого каждая сторона локально пересобирает свой `protocol.Params`.
- `VerdictNotification` — `{ "verdict": "Accept"|"Reject" }`.
- `FinalizeRedirect` — `{ "redirect": "..." }`.

**Бинарные (`application/octet-stream`)**

- `VClientPKShare` / `VAgentPKShare` — dual share (eval + top).
- `VClientRLKRound1` / `VAgentRLKRound1` / `VClientRLKRound2`.
- `VClientGaloisShares` — агрегированный блок по `MasterAtoms`.
- `InferEvalKeys` — `{ RLK, PKTop, GKSMaster }`.
- `EncryptedImage`, `InferenceResult`, `AuthenticatedResult` — `*rlwe.Ciphertext`.
- `PartialDecryption` — обёртка над rlwe-share.
