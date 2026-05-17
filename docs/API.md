# HTTP API

Карта эндпоинтов трёх сервисов протокола ppiav. См. также
`docs/protocol-simple.puml` и `docs/DESIGN.md`. Протокол блокирующий:
`POST /infer` (и на VAgent, и на VService) удерживает соединение до
завершения инференса и возвращает результат в теле ответа — отдельного
канала доставки результата (SSE/long-poll) нет.

Источники истины: `internal/vservice/http.go`, `internal/vagent/http.go`,
`internal/rservice/http.go`; типы сообщений — `internal/protocol/wire.go`;
лимиты тел — `internal/httputil/`.

Лимиты тел:

- `MaxJSONBody = 64 KiB` — JSON control-эндпоинты.
- `MaxShareBody = 128 MiB` — одиночные доли (pk-share, RLK round1/2, partial-decryption).
- `MaxGksSharesBody = 2 GiB` — агрегированный блок Galois-долей.
- `MaxEvalKeysBody = 3 GiB` — `InferEvalKeys` и зашифрованные изображения/результаты.

---

## VService

Внутренний сервис, к которому ходит VAgent server-to-server. Браузер
сюда не обращается.

| Точка API                        | Запрос           | Ответ                 |
| -------------------------------- | ---------------- | --------------------- |
| `GET /params`                    | —                | `Manifest`            |
| `POST /sessions`                 | —                | `VerificationSession` |
| `POST /sessions/{sid}/eval-keys` | `InferEvalKeys`  | —                     |
| `POST /sessions/{sid}/infer`     | `EncryptedImage` | `InferenceResult`     |

`POST /infer` блокируется на время инференса и возвращает шифротекст
результата в теле ответа.

---

## VAgent

Лицом к пользователю: отдаёт VClient SPA + WASM, принимает доли от
браузера, проксирует в VService, шлёт callback в RService.

Пер-роут дедлайны при проксировании в VService: `/eval-keys` — 10 мин,
`/infer` — 5 мин (включает инференс + MPD-Auth), прочие server-to-server
RPC — 30 с.

Любая ошибка с известным `sid` вызывает `rejectAndEvict` → callback
`VerdictReject` в RService + eviction сессии (см. `docs/DESIGN.md`
§`Failure modes`, F2/F3). F1 (`Ver` вернул false) идёт через
`postVerdict(VerdictResultAuthFailed)`.

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

| Точка API                                 | Запрос              | Ответ                                                                                                                          |
| ----------------------------------------- | ------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `POST /sessions/{sid}/infer`              | `EncryptedImage`    | `AuthenticatedResult` (блокирующий: внутри VAgent проксирует в VService `/infer`, затем применяет MPD-Auth)                    |
| `POST /sessions/{sid}/partial-decryption` | `PartialDecryption` | `FinalizeRedirect` (JSON 200; redirect-URL для перехода на RClient). Параллельно отправляется `VerdictNotification` в RService |

---

## RService

Защищаемый ресурс. Хранит cookie `sid` (`HttpOnly`), запускает Stage-1
редирект на VAgent, принимает финальный verdict.

| Точка API                        | Запрос                | Ответ                                                                                                                                                          |
| -------------------------------- | --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GET /protected?sid=`            | —                     | без cookie / verdict=Unknown → **302** на `<vagent-public>/verify?sid=...` + `Set-Cookie sid`; иначе `text/html` (RClient SPA); при verdict ≠ Accept — **403** |
| `POST /reset`                    | —                     | **303** → `/protected`, чистит cookie `sid`                                                                                                                    |
| `GET /dist/*`, `GET /styles.css` | —                     | ассеты RClient                                                                                                                                                 |
| `POST /api/callback/{sid}`       | `VerdictNotification` | —                                                                                                                                                              |

---

## Типы сообщений

Все бинарные структуры реализуют `encoding.BinaryMarshaler` /
`encoding.BinaryUnmarshaler` (`internal/protocol/wire.go`).

**JSON**

- `VerificationSession` — `{ "session_id": "..." }`.
- `Manifest` — `ckks` + LLKN-расписание + параметры аутентификатора + `flood_sigma` + `extra_rotation_indices` + `input_level`; публичное декларативное описание параметров протокола, из которого каждая сторона локально пересобирает свой `protocol.Params`.
- `VerdictNotification` — `{ "verdict": <Verdict> }`, где `Verdict ∈ {Unknown(0), Accept(1), Reject(2), ResultAuthFailed(3)}` (на проводе — числовой `uint8`; `String()` см. в `internal/protocol/types.go`).
- `FinalizeRedirect` — `{ "redirect": "..." }`.

**Бинарные (`application/octet-stream`)**

- `VClientPKShare` / `VAgentPKShare` — dual share (eval + top).
- `VClientRLKRound1` / `VAgentRLKRound1` / `VClientRLKRound2`.
- `VClientGaloisShares` — агрегированный блок по `MasterAtoms`.
- `InferEvalKeys` — `{ RLK, PKTop, GKSMaster }`.
- `EncryptedImage`, `InferenceResult`, `AuthenticatedResult` — `*rlwe.Ciphertext`.
- `PartialDecryption` — обёртка над rlwe-share.
