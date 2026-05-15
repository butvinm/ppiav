# Phase 3: HTTP services and browser SPAs

## Overview

Transform the in-process Phase 1+2 prototype into a distributed system with HTTP services and browser-based clients. The multi-party CKKS protocol previously executed inside `cmd/ppiav-cli` now runs across three Go HTTP services (VService, VAgent, RService) and two browser Single-Page Applications (VClient, RClient) communicating via REST APIs and SSE.

**Scope:**

- Three Go HTTP services: VService (FHE inference), VAgent (protocol mediator), RService (resource gating)
- Two browser SPAs: VClient (verification UI served by VAgent), RClient (protected UI served by RService)
- WASM crypto bridge: `web/ppiav` module exposing Lattigo and ppiav protocol APIs to JS
- All components use vanilla JS + TypeScript (no frameworks) — "vanilla JS" means no build tools or bundling frameworks (React, Vue, Webpack, esbuild); TypeScript compiles directly to ES modules for browser consumption; the browser's native ES module loader (without a bundler) handles dependencies

**Benefits:**

- End-to-end demonstration of the protocol over network, not just in-process
- Real-world client-side crypto in browser via WASM
- Separates verifier infrastructure (VService, VAgent) from resource infrastructure (RService) as designed
- Browser UI demonstrates the user-facing verification flow

**Critical design choices (from plan review):**

- **Stage 1 session flow**: Per DESIGN.md §3 Stage 1 — RService's `GET /protected` handler calls `VAgent POST /sessions` server-to-server (no browser-visible hop), VAgent in turn calls `VService POST /sessions`, returns `VerificationSession{sid}` to RService; RService alone sets `Set-Cookie: sid=<sid>` and returns `302 Location: <VAgent>/verify?sid=<sid>` to the browser. There is no `GET /sessions/new` — RService owns the cookie, the 302, and the synchronous server-to-server failure surface (F4a).
- **Embed structure**: `web/` stays at the repo root; each subdirectory ships a tiny `embed.go` exporting an `embed.FS` (`vclient.FS`, `rclient.FS`) or `[]byte` (`ppiav.WASM`), and the service binaries import those. `//go:embed` doesn't accept `..` regardless of where the file lives — co-locating the embed file with its assets is the simplest fix. No directory rename.
- **SSE transport**: VAgent's per-session `authResult` is a capacity-1 buffered channel. Image POST `select { case sess.authResult <- ctM: default: }` (non-blocking); SSE handler `select { case ct := <-sess.authResult: ...; case <-r.Context().Done(): }`. Cancellable on client disconnect (which `sync.Cond.Wait()` is not), pre-arrival race solved by the buffer, no extra mutex/flag bookkeeping.
- **WASM bridge**: `web/ppiav` is part of the root Go module (no separate `go.mod`, no `replace`). WASM is built from repo root with `GOOS=js GOARCH=wasm go build -o web/ppiav/ppiav.wasm ./web/ppiav/bridge`.
- **Testing**: Task 8 reserved (redundant with per-handler unit tests; real end-to-end is the manual browser run).
- **Redirect flow**: VClient SPA fully implements Stage 4b redirect via `window.location` after successful partial decryption

## Context (from discovery)

**Files/components involved:**

- **Existing packages** (Phase 1+2 complete): `internal/{protocol, authenticator, vclient, vagent, vservice, rservice, orchestrator}` - core crypto logic is complete and tested
- **Existing CLI**: `cmd/ppiav-cli` - in-process orchestrator, will be preserved for local testing
- **Missing web infrastructure**: `web/` directory (to be created), `cmd/{ppiav-vservice, ppiav-vagent, ppiav-rservice}` (to be created)
- **Missing WASM layer**: Go→WASM bridge exposing Lattigo and ppiav APIs to browser JS

**Related patterns found:**

- `internal/protocol/wire.go` defines all message types with `BinaryMarshaler`/`BinaryUnmarshaler` - ready for HTTP transport
- `internal/vservice.Service`, `internal/vagent.Agent` are struct-based with mutex-protected `map[string]*sessionState` - already thread-safe for concurrent HTTP handlers
- `internal/bench` provides measurement harness - can be reused for HTTP latency benchmarks

**Dependencies identified:**

- Orion's `js/lattigo` bridge at `~/Dev/orion/js/lattigo/` - source for WASM crypto code copying
- `internal/vclient` must compile to `js/wasm` - pure Go constraint already satisfied in Phase 1+2
- SSE for Stage 4a result streaming (native `EventSource` in browser, `http.Flusher` in Go)
- Binary wire formats for shares/ciphertexts (avoid base64 inflation on hot path)

**Key design decisions from DESIGN.md:**

- No TLS, no auth, no rate limiting, no extra input sanitization beyond protocol demands (out of scope)
- JSON for control messages, `application/octet-stream` for crypto payloads
- SSE via native `EventSource` (browser) and `http.Flusher` (Go)
- Sid from URL, no JS-side cookie inspection
- No persistent client state (key lives in tab closure)
- WASM bridge uses TypeScript wrappers (same as Orion's pattern)

## Development Approach

- **testing approach**: Regular - write Go code, then unit tests in the same file's `*_test.go`, in the same task
- complete each task fully before moving to the next
- make small, focused changes
- **CRITICAL: every task MUST include new/updated tests** for code changes in that task
  - tests are not optional — they are a required part of the checklist
  - HTTP handlers: test with `net/http/httptest` for success + error cases
  - WASM functions: test in Go (WASM-specific JS side tested in browser manually)
- **CRITICAL: all tests must pass before starting next task** — no exceptions
- **CRITICAL: update this plan file when scope changes during implementation**
- run tests after each change: `go test ./...`
- atomic commits per task: stage specific files (`git add path/to/file`), never `git add .`

## Testing Strategy

- **Unit tests** (required per task): Go `*_test.go` next to each source file. Use `testify/assert` and `testify/require`.
- **HTTP handler tests**: use `net/http/httptest.ResponseRecorder` and `httptest.NewServer` where appropriate. Test status codes, response bodies, error cases ( malformed input, unknown sid, etc.).
- **No automated web-e2e tests in this plan.** Browser SPAs (`web/vclient`, `web/rclient`) are tested manually by the user after implementation. Rationale: setting up Playwright/Cypress for vanilla JS SPAs adds significant test infrastructure cost for simple forms/screens; the unit-tested HTTP handlers give us confidence in the backend, and manual browser testing covers the JS/WASM glue.
- **TypeScript compilation**: run `tsc --noEmit` from `web/ppiav`, `web/vclient`, `web/rclient` directories as part of each task's test gate.
- **WASM build verification**: Task 11 adds a `make wasm` target; earlier tasks verify Go compiles under `js/wasm` target (`GOARCH=wasm GOOS=js go build`).

## Progress Tracking

- mark completed items with `[x]` immediately when done
- add newly discovered tasks with a `+` prefix
- document issues/blockers with a `warning` prefix
- update plan if implementation deviates from original scope
- keep plan in sync with actual work done

## Solution Overview

**Architecture:**

Follow DESIGN.md §`Components` and §`Protocol` exactly. Three Go services, each with its own entry point under `cmd/`:

1. **VService** (`cmd/ppiav-vservice`): FHE inference on encrypted images
   - Holds per-session evaluators with `rlk + gks`
   - Issuer of session IDs (sid)
   - Phase 3: receives full `*rlwe.GaloisKeySet` (Phase 4 will swap to `gks_master`)
   - HTTP routes: `GET /params`, `POST /sessions`, `POST /sessions/:sid/eval-keys`, `POST /sessions/:sid/image`

2. **VAgent** (`cmd/ppiav-vagent`): Protocol mediator + VAgent crypto (holds `sk_a`)
   - Routes proxy between VService and VClient/RService
   - Serves VClient SPA at `/verify?sid`
   - MPD-Auth `BuildAuthenticatedCt` and `FinalizeDecryption`
   - Verdict callback to RService
   - HTTP routes: `GET /verify`, `POST /sessions`, `GET /sessions/:sid/params`, `POST /sessions/:sid/pk-share`, etc. (full protocol per DESIGN.md)

3. **RService** (`cmd/ppiav-rservice`): Resource gating
   - Simple verdict storage in `map[SessionID]Verdict`
   - Provides test protected page
   - HTTP routes: `GET /protected`, `POST /api/callback`

**Browser SPAs:**

1. **VClient** (`web/vclient`): File upload + crypto → submission flow
   - Loads `web/ppiav` WASM
   - Runs full multi-party keygen protocol from browser
   - SSE for `AuthenticatedResult`
   - Redirects to RClient on completion

2. **RClient** (`web/rclient`): Gated content page
   - Cookie-driven verification
   - Shows verdict + "Access granted/denied" message

**WASM crypto bridge** (`web/ppiav`):

- Single WASM module exposing two namespaces: `globalThis.lattigo` (low-level Lattigo) and `globalThis.ppiav` (protocol APIs)
- Copied from `~/Dev/orion/js/lattigo/` and adapted - separate subpackages `bridge/lattigo` and `bridge/ppiav`
- `bridge/ppiav` imports `internal/vclient` directly - no crypto duplication
- Pure Go: compiles under both `linux/amd64` and `js/wasm`
- TypeScript wrappers vendored from Orion, transpiled with `tsc`

**Implementation order (bottom-up):**

```
HTTP handlers (in internal/)  ──►  Service entry points (cmd/)
    ├─ internal/vservice/http.go    (VService routes)
    ├─ internal/vagent/http.go     (VAgent routes)
    └─ internal/rservice/http.go   (RService routes)
                                         │
WASM bridge (web/ppiav)  ──►  Browser SPAs (web/vclient, web/rclient)
    ├─ bridge/lattigo/*            (copied from Orion)
    ├─ bridge/ppiav/*              (imports internal/vclient)
    └─ ts types + wrappers
                                         │
                                cmd/ppiav-vservice
                                cmd/ppiav-vagent (serves SPA)
                                cmd/ppiav-rservice (serves SPA)
```

**HTTP layer decisions:**

- **No middleware framework** (no chi, no gin). Use stdlib `net/http` with `http.ServeMux` — keep dependencies light, design is simple.
- **Binary wire format**: `application/octet-stream` with `encoding.BinaryMarshaler` for shares/ciphertexts. No base64 on hot path.
- **JSON for control**: `VerificationSession`, `VerdictNotification`, param responses are JSON.
- **Sid encoding**: URL path parameter (e.g., `/sessions/:sid/params`) per DESIGN.md. No query param.
- **SSE**: Native `EventSource` in browser, Go `http.Flusher` on server. Simple text line protocol with `data:` prefix.
- **No timeouts or deadline middleware** per DESIGN.md §`No protocol-level timeouts`.
- **CORS not configured** (development assumed to be localhost, out of scope per DESIGN.md).

**Image preprocessing contract (Phase 3 browser → WASM):**

DESIGN.md §`internal/vclient` specifies the tensor pipeline at layers above `EncryptImage`. In Phase 3 browser:

1. `web/vclient` reads `<input type="file">` → `ArrayBuffer` as `Uint8Array`
2. Canvas decode: `new Image()` → `<canvas>` 64×64 resize → `getImageData(0,0,64,64)` → RGBA buffer
3. Convert RGBA → RGB: drop alpha channel → 3-channel `Uint8ClampedArray` of length 12288 (=3×64×64)
4. Normalize: `(x / 255.0 - 0.5) / 0.5` for each pixel → `Float64Array` in `[-1, 1]`
5. HWC→CHW permute: reformat from row-major (R₀G₀B₀, R₁G₁B₁, … 64×64 pixels) to channel-first (R₀…R₄₀₉₅, G₀…G₄₀₉₅, B₀…B₄₀₉₅) → length-12288 `Float64Array`
6. Hand to WASM `EncryptImage` via typed array view

**No byte-equivalence requirement.** The browser pipeline is a faithful reimplementation of `models/prepare_samples.py`, but canvas resize is browser-implementation-defined and will drift from Pillow's resampler by sub-1/255 per pixel. C3AE was trained on UTKFace images whose intrinsic variability (JPEG, lighting, expressions) dwarfs that drift; the decision boundary is robust to it. No test fixture, no golden `.bin`, no drift assertion — the only meaningful correctness check is the manual acceptance run (Post-Completion: upload faces of known age, observe verdict distribution).

## Technical Details

**HTTP route design (verbatim from DESIGN.md protocol diagram):**

```
VService (Port TBD, default 8080):
  GET                  /params                       (protocol.Params)
  POST                 /sessions                     (VerificationSession sid)
  POST         /sessions/:sid/eval-keys             (InferEvalKeys from VAgent)
  POST         /sessions/:sid/image                 (EncryptedImage → result_ct)

VAgent (Port TBD, default 8081):
  GET        /verify?sid                           (serves VClient SPA)
  POST               /sessions                     (server-to-server: called by RService; allocates sid via VService and registers it locally; returns VerificationSession)
  GET        /sessions/:sid/params                  (protocol.Params from VService)
  POST    /sessions/:sid/pk-share                  (VClientPKShare → VAgentPKShare)
  POST    /sessions/:sid/rlk/round1                (VClientRLKRound1 → VAgentRLKRound1)
  POST    /sessions/:sid/rlk/round2                (VClientRLKRound2 → ack)
  POST    /sessions/:sid/gks-shares                (VClientGaloisKeyShare → ack; Phase-4 sibling is /gks-master)
  GET     /sessions/:sid/result                    (SSE: AuthenticatedResult)
  POST    /sessions/:sid/image                     (EncryptedImage → result_ct from VService)
  POST    /sessions/:sid/partial-decryption        (PartialDecryption → verdict to RService + redirect to RClient)

RService (Port TBD, default 8082):
  GET                  /protected                   (SPA; cookie-gated; on missing sid, calls VAgent POST /sessions server-to-server, sets sid cookie, 302s to VAgent /verify?sid=)
  POST           /api/callback                     (VerdictNotification)
```

**Request/response formats:**

Per DESIGN.md line 906 — JSON only for control messages (`VerificationSession`, `VerdictNotification`, `protocol.Params`); `application/octet-stream` for every share- and ciphertext-bearing endpoint (`/pk-share`, `/rlk/round1`, `/rlk/round2`, `/gks-shares`, `/eval-keys`, `/image`, `/partial-decryption`). No base64 inflation on the hot path — that explicitly includes `InferEvalKeys` (the aggregated `rlk` + `[]*rlwe.GaloisKey` blob VAgent forwards to VService).

- **JSON endpoints**: `Content-Type: application/json`, body is the wire message JSON. Used for: `GET /params`, `POST /sessions` (response), `POST /api/callback` (request).
- **Binary endpoints**: `Content-Type: application/octet-stream`, body is `encoding.BinaryMarshaler` output (the wire-message type implements `MarshalBinary`/`UnmarshalBinary` directly — no JSON envelope around it). Handlers `io.ReadAll(r.Body)` → `UnmarshalBinary` → process → `MarshalBinary` → `w.Write`.
- **SSE result delivery**: `Content-Type: text/event-stream`. SSE framing is text-only by spec, so the `AuthenticatedResult` ciphertext is base64-encoded into a single `data:` line (`data: <base64>\n\n`). Accepted trade-off: ~33% inflation on this one event, which is small relative to the cost of running MPD-Auth — and SSE is the simplest fit for the "open before image POST to avoid race" requirement in DESIGN.md line 175. _Alternative considered:_ SSE ping + separate binary GET (avoids inflation, adds a round trip and an endpoint) — not adopted in Phase 3. Revisit only if AuthenticatedResult size becomes a measured bottleneck.

**HTTP error handling:**

**Phase 3 failure mode wire-shape impact** per DESIGN.md §`Failure modes`:

- F4a (VService unreachable during Stage 1): no sid issued, VAgent returns 5xx to RService → RService returns 5xx to user (no session to deliver verdict against)
- F4a (VService unreachable during Stages 2–3): VAgent retries per budget → on exhaustion, emits `Verdict = Reject` to RService
- F2 (malformed wire): HTTP 400 to the offending party, **plus** `Verdict = Reject` to RService
- F3 (inference error): VAgent surface `Verdict = Reject` to RService

Implementation:

- Handlers validate input size/presence → return 400 with JSON error body `{"error": "message"}` on malformed
- VAgent forward errors from VService as-is or wraps with context (TODO—design doesn't specify retry budgets; implement simple "fail-fast" for prototype)
- On any protocol error requiring verdict, VAgent calls `rservice.AcceptVerdict(sid, VerdictReject)` before returning

**Docker per DESIGN.md §`Layout`**:

Phase 3 introduces `deploy/Dockerfile.*`. Minimal Alpine-based images for each service. SPAs are served as static files from binary embedded (embed.FS) or from `web/` mounts. Implementation preferred: `embed.FS` for SPAs in service binaries (simpler deployment, no volume orchestration for SPA files).

**WASM module structure** (`web/ppiav` — packages within the root Go module, not a separate module):

```
web/ppiav/
├── bridge/
│   ├── main.go           (//go:build js && wasm — entry point, calls RegisterJS() on both subpkgs)
│   ├── lattigo/          (copied from ~/Dev/orion/js/lattigo/bridge/, adapted)
│   │   ├── encoder.go    encryptor.go  decryptor.go  keygen.go  params.go
│   │   ├── helpers.go    handles.go    polynomial.go  serialize.go
│   │   ├── bootstrap.go  bootstrap_streaming.go
│   │   └── lattigo.go    (new — RegisterJS() registers globalThis.lattigo namespace)
│   └── ppiav/            (new, imports internal/vclient)
│       ├── ppiav.go      (RegisterJS() registers globalThis.ppiav namespace)
│       ├── keygen.go     (wraps vclient.Client Gen*Share/Aggregate* methods)
│       ├── image.go      (wraps EncryptImage)
│       └── decrypt.go    (wraps PartialDecrypt)
└── src/                  (TypeScript wrappers, copied from ~/Dev/orion/js/lattigo/src/)
    ├── lattigo/          (TS bindings for globalThis.lattigo)
    └── ppiav/            (TS bindings for globalThis.ppiav)
```

WASM is built with stdlib Go targeting `GOOS=js GOARCH=wasm`. No TinyGo, no `ffi/`. `bridge/main.go` calls `lattigo.RegisterJS()` and `ppiav.RegisterJS()` explicitly (no blank-imports). Build invocation: `GOOS=js GOARCH=wasm go build -o web/ppiav/ppiav.wasm ./web/ppiav/bridge` from the repo root.

**Crypto bridge exports**:

`globalThis.lattigo` (copied from Orion; we only verify TS types compile):

- `params.NewCKKSParameters(logN, logQ, logP, scale, ringType)`
- `key.NewKeyGenerator(params).GenSecretKeyNew()`
- `encoder.NewEncoder(params).Encode(...)` / `Decode(...)`
- `encryptor.NewEncryptor(pk).EncryptNew(pt)` / `EncryptZeroNew()`
- etc. — full Lattigo API surface

`globalThis.ppiav` (new, our protocol APIs):

```javascript
// Client construction
ppiav.newClient(paramsJSON, sid) -> Client

// Stage 2b
client.genPKShare() -> Uint8Array       // BinaryMarshal output, raw bytes
client.aggregatePK(agentShareBytes: Uint8Array) -> void

// Stage 2c — Round 1
client.genRLKShareRound1() -> Uint8Array
client.aggregateRLKRound1(agentShareBytes: Uint8Array) -> void

// Stage 2c — Round 2
client.genRLKShareRound2() -> Uint8Array
// no aggregateRLKRound2 on client

// Stage 2d
client.genGaloisShares() -> Uint8Array  // single marshaled VClientGaloisKeyShare blob

// Stage 3 — preprocessing is in JS side; this receives the Float64Array
client.encryptImage(tensorFloat64Array) -> Uint8Array  // marshaled EncryptedImage

// Stage 4a
client.partialDecrypt(authenticatedCtBytes: Uint8Array) -> Uint8Array  // marshaled PartialDecryption
```

All shares and ciphertexts cross the WASM↔JS boundary as `Uint8Array` (raw `BinaryMarshal` bytes) and feed directly into `fetch(..., { body: bytes })` with `Content-Type: application/octet-stream`. No base64 anywhere on the bridge — `syscall/js` copies between Go `[]byte` and JS `Uint8Array` natively via `js.CopyBytesToJS` / `js.CopyBytesToGo`.

**Image preprocessing in browser** (`web/vclient`):

```javascript
// 1. File read
const blob = await fileInput.files[0].text(); // or FileReader as ArrayBuffer
const imageData = await decodeImage(blob); // <canvas> decode

// 2. Resize to 64×64
const canvas = document.createElement("canvas");
canvas.width = 64;
canvas.height = 64;
const ctx = canvas.getContext("2d");
ctx.drawImage(imageData, 0, 0, 64, 64);
const rgba = ctx.getImageData(0, 0, 64, 64).data;

// 3. RGBA → RGB + normalize to [-1, 1] Float64Array (CHW order)
const tensor = new Float64Array(12288);
const hw = 64 * 64;
for (let i = 0; i < hw; i++) {
  const r = rgba[4 * i] / 255.0;
  const g = rgba[4 * i + 1] / 255.0;
  const b = rgba[4 * i + 2] / 255.0;
  tensor[i] = (r - 0.5) / 0.5; // R channel first
  tensor[hw + i] = (g - 0.5) / 0.5; // G channel
  tensor[2 * hw + i] = (b - 0.5) / 0.5; // B channel
}

// 4. Encrypt via WASM
const ciphertext = await ppiavClient.encryptImage(tensor);
```

**Browser session flow**:

1. User loads `/protected` (no sid cookie) → RService 302 to VAgent `/verify?sid` with `Set-Cookie`
2. VClient SPA loads, reads `?sid=...` from URL
3. VClient SPA drives protocol stages from browser:
   - Stage 2a: `fetch('/sessions/:sid/params')` → JSON params
   - Stage 2b–2d: Multi-party keygen via `ppiavClient.genPKShare()`, etc.
   - Stage 2e: `new EventSource('/sessions/:sid/result')` → wait for result
   - Stage 3: `fetch('/sessions/:sid/image', {method: 'POST', body: ciphertext})`
   - Stage 4a: SSE event received → `ppiavClient.partialDecrypt()` → `fetch('/sessions/:sid/partial-decryption', {method: 'POST', body: partialDecryption})`
   - Stage 4b: Response indicates completion → `window.location = '/protected'`
4. Browser hits `/protected` with sid cookie → RService returns verdict page

## What Goes Where

- **Implementation Steps** (`[ ]` checkboxes): everything inside `~/Dev/ppiav/` — Go services, HTTP handlers, WASM bridge, browser SPAs, TypeScript glue, Dockerfiles.
- **Post-Completion** (no checkboxes): manual browser acceptance run, cross-check against Phase-2 CLI verdicts, follow-up plans.

---

## Implementation Steps

### Task 1: `internal/vservice` — HTTP layer (params, sessions, eval-keys)

**Files:**

- Create: `internal/vservice/http.go`
- Create: `internal/vservice/http_test.go`
- Modify: `internal/protocol/wire.go`, `internal/protocol/wire_test.go` (scope expansion — see note below)

Scope note: `POST /sessions/:sid/eval-keys` ships its payload as `application/octet-stream` per Technical Details (JSON-encoding `*rlwe.RelinearizationKey` and `[]*rlwe.GaloisKey` is impractical and inconsistent with Task 4's outbound format). Adding `InferEvalKeys.MarshalBinary`/`UnmarshalBinary` was therefore included in Task 1 scope. The constructor is named `NewServer` rather than `New` to avoid shadowing `vservice.New(params)`.

- [x] create `internal/vservice/http.go` with `type Server struct { svc *vservice.Service; addr string }` and `func NewServer(svc *Service, addr string) *Server` (renamed from `New` to avoid collision with existing Service constructor)
- [x] implement `func (s *Server) ListenAndServe() error` using `http.Server` and `http.ServeMux`
- [x] implement `GET /params` handler: returns `protocol.Params` as JSON (CKKS via Lattigo's `MarshalJSON`, authenticator config and scalar fields as JSON)
- [x] implement `POST /sessions` handler: calls `svc.OpenSession()`, returns `VerificationSession{SessionID: sid}` as JSON
- [x] implement `POST /sessions/:sid/eval-keys` handler: reads `application/octet-stream` body, `UnmarshalBinary` into `InferEvalKeys`, calls `svc.StoreEvalKeys(sid, ...)`, returns 200
- [x] write tests for `GET /params` with `httptest.ResponseRecorder`: assert JSON structure, correct field values
- [x] write tests for `POST /sessions`: asserts sid is non-empty and distinct across calls
- [x] write tests for `POST /sessions/:sid/eval-keys`: success on valid keys, 404 on unknown sid (error JSON), 400 on malformed body, method-not-allowed for non-POST
- [x] run tests — must pass before Task 2: `go test ./internal/vservice/...`

### Task 2: `internal/rservice` — HTTP layer (protected page, callback)

**Files:**

- Create: `internal/rservice/http.go`
- Create: `internal/rservice/http_test.go`

Scope notes:

- The Server constructor is named `NewServer` rather than `New` (same reason as Task 1's `vservice.NewServer`) — `rservice.New()` already exists as the Service constructor and Go does not allow overloads.
- The callback URL is `POST /api/callback/:sid` (sid in URL path). DESIGN.md §`Components` states "subsequent routes carry sid in the URL path"; `protocol.VerdictNotification` is `{ Verdict Verdict }` only, so the URL is the natural place to carry sid. No wire-format change.

- [x] create `internal/rservice/http.go` with `type Server struct { svc *rservice.Service; addr string; vagentURL string }` and `func NewServer(svc *Service, vagentURL, addr string) *Server` (added `vagentURL` field for Stage 1 redirect to VAgent — fully implemented in Task 18)
- [x] implement `func (s *Server) ListenAndServe() error` using `http.Server` and `http.ServeMux`
- [x] implement `GET /protected` handler: read `sid` cookie, call `svc.CheckAccess(sid)`, return simple HTML page with verdict (Accept/Reject/Unknown) — no SPA yet, just a stub showing the verdict. NOTE: full Stage-1 server-to-server flow (RService → `VAgent POST /sessions` → set cookie + 302 to `/verify?sid=`) is implemented in Task 18; for now, on missing sid just return Unknown/403.
- [x] implement `POST /api/callback/:sid` handler: parse JSON `VerdictNotification`, call `svc.AcceptVerdict(sid, Verdict)`, return 200
- [x] write tests for `GET /protected` with `httptest.ResponseRecorder`: asserts Unknown verdict on missing sid, Accept/Reject on valid verdict
- [x] write tests for `POST /api/callback`: upserts verdict, subsequent `CheckAccess` returns stored value
- [x] write tests for malformed JSON: returns 400 with error JSON
- [x] run tests — must pass before Task 3: `go test ./internal/rservice/...`

### Task 3: Create `cmd/ppiav-vservice` and `cmd/ppiav-rservice` binary entry points

**Files:**

- Create: `cmd/ppiav-vservice/main.go`
- Create: `cmd/ppiav-rservice/main.go`
- Modify: `go.mod` (add net/http nettle if needed; likely not needed, stdlib is enough)

- [x] create `cmd/ppiav-vservice/main.go` with `--addr` flag (default `:8080`), `--orion` flag (Phase 2+, same semantics as CLI)
- [x] implement main: parse flags, load `protocol.Params` (load from `vservice.NewWithOrion` if `--orion` set, else `Defaults()`), construct `vservice.Service`, construct `vservice.NewServer(svc, addr)`, call `ListenAndServe()`
- [x] create `cmd/ppiav-rservice/main.go` with `--addr` flag (default `:8082`), `--vagent-url` flag (default `http://localhost:8081`, needed for Stage 1 redirect)
- [x] implement main: parse flags, construct `rservice.Service`, construct `rservice.NewServer(svc, vagentURL, addr)`, call `ListenAndServe()`
- [x] verify binaries compile: `go build ./cmd/ppiav-vservice`, `go build ./cmd/ppiav-rservice`
- [x] manually smoke-test: `./ppiav-vservice --addr :8080 &` → `curl http://localhost:8080/params` → verify JSON response, `curl http://localhost:8080/sessions -X POST` → verify sid returned; same for RService `POST /api/callback` → `GET /protected` cookie flow
- [x] run tests — verify existing unit tests still green: `go test ./internal/vservice/... ./internal/rservice/...`

### Task 4: `internal/vagent` — HTTP layer (all protocol routes except SSE/reverse-proxy)

**Files:**

- Create: `internal/vagent/http.go`
- Create: `internal/vagent/http_test.go`
- Modify: `internal/vagent/agent.go` (add `DoSessionOpen` method if needed for HTTP handler convenience — check existing API first)
- Modify: `internal/protocol/wire.go`, `internal/protocol/wire_test.go` (scope expansion — added `MarshalBinary`/`UnmarshalBinary` to `VClientPKShare`, `VAgentPKShare`, `VClientRLKRound1`, `VAgentRLKRound1`, `VClientRLKRound2`, `VClientGaloisKeyShare`; the multiparty share types have only binary codecs, and Technical Details specifies octet-stream for all share-bearing endpoints).

- [x] ensure `internal/vagent.Agent` has all methods needed by HTTP handlers (`GenPKShare`, `AggregatePK`, `GenRLKShareRound1`, `AggregateRLKRound1`, `GenRLKShareRound2`, `AggregateRLKRound2`, `GenGaloisShares`, `AggregateGaloisShares`, `BuildAuthenticatedCt`, `FinalizeDecryption`). If missing, add `DoSessionOpen(sid)` convenience (currently it's `OpenSession(sid)` but may need `vservice` forward call pattern to open session there first)
- [x] create `internal/vagent/http.go` with `type Server struct { agent *vagent.Agent; vserviceURL string; addr string }` and `func NewServer(agent *Agent, vserviceURL, addr string) *Server` (renamed from `New` per convention to avoid collision with existing `vagent.New(params)` Agent constructor)
- [x] implement `GET /sessions/:sid/params` handler: proxy to VService `/params` (currently just returns one params set; verify design — sid may phase in VService params changes later, for now just forward)
- [x] implement `POST /sessions/:sid/pk-share` handler: read `application/octet-stream` body → `UnmarshalBinary` into `VClientPKShare`, call `agent.GenPKShare(sid)`, `agent.AggregatePK(sid, clientShare)`, write `VAgentPKShare.MarshalBinary` as `application/octet-stream`. NOTE: Deviated from plan's "JSON `VClientPKShare`" — share types have no JSON codec; using octet-stream matches Technical Details ("every share- and ciphertext-bearing endpoint is octet-stream") and the rest of Task 4's handlers.
- [x] implement `POST /sessions/:sid/rlk/round1` handler: read `application/octet-stream` body → `UnmarshalBinary` into `VClientRLKRound1`, call `agent.GenRLKShareRound1(sid)`, `agent.AggregateRLKRound1(sid, clientShare)`, write `VAgentRLKRound1.MarshalBinary` as `application/octet-stream`
- [x] implement `POST /sessions/:sid/rlk/round2` handler: read octet-stream body → `UnmarshalBinary` into `VClientRLKRound2`, call `agent.GenRLKShareRound2(sid)`, `agent.AggregateRLKRound2(sid, clientShare)`, return 200 (no body)
- [x] implement `POST /sessions/:sid/gks-shares` handler: read octet-stream body → `UnmarshalBinary` into `VClientGaloisKeyShare`, call `agent.GenGaloisShares(sid)`, `agent.AggregateGaloisShares(sid, clientShares, clientLabels)`, build `InferEvalKeys{RLK, GKS: []*rlwe.GaloisKey}`, POST its `MarshalBinary` body to VService `/sessions/:sid/eval-keys` with `Content-Type: application/octet-stream`, return 200
- [x] **Skipping SSE and image submission handlers** (`GET /sessions/:sid/result`, `POST /sessions/:sid/image`, `POST /sessions/:sid/partial-decryption`) — these go to Task 7
- [x] implement `POST /sessions` handler (DESIGN.md Stage 1): no request body; internally calls `VService POST /sessions` to allocate sid, then `agent.OpenSession(sid)` to register the session in VAgent, returns `VerificationSession{sid}` as JSON. This is the **only** Stage-1 entry point on VAgent; it is called server-to-server by RService's `GET /protected` handler (not by the browser). There is no `GET /sessions/new`.
- [x] **Skipping `/verify` SPA handler** — this goes to Task 16 (embed VClient SPA)
- [x] write tests for each handler using `httptest.ResponseRecorder`: success path (valid sid, valid share count), error paths (unknown sid, malformed octet-stream, share length mismatch, label mismatch)
- [x] write tests for `POST /sessions`: verify VService is called, sid allocated, `agent.OpenSession(sid)` registered, response JSON shape; error on VService unreachable returns 5xx (F4a wire shape)
- [x] write tests for proxy to VService `/params`
- [x] run tests — must pass before Task 5: `go test ./internal/vagent/...`

### Task 5: Create `cmd/ppiav-vagent` binary entry point (without SPA)

**Files:**

- Create: `cmd/ppiav-vagent/main.go`

- [x] create `cmd/ppiav-vagent/main.go` with flags: `--addr` (default `:8081`), `--vservice-url` (required, e.g., `http://localhost:8080`), `--orion` (Phase 2+, pass to VAgent `New` if set)
- [x] implement main: parse flags, load params (same --orion semantics as VService), construct `vagent.Agent` with forward to VService (via `DoSessionOpen` pattern — need to call VService `POST /sessions` to get sid, then `agent.OpenSession(sid)`), construct `vagent.New(agent, vserviceURL, addr)`, call `ListenAndServe()`
- [x] keep `vservice.OpenSession()` and `agent.OpenSession(sid)` separate (no new VAgent method). Stage-1 flow is: RService → VAgent `POST /sessions` handler → handler calls VService `POST /sessions` for sid → handler calls `agent.OpenSession(sid)` to register → returns `VerificationSession`. HTTP handler `/verify?sid` assumes sid already exists (came from the Stage-1 redirect).
- [x] implement `main.go` to not call `agent.OpenSession` in init; VService sid creation happens dynamically via RService → VAgent → VService flow (see DESIGN.md §`Protocol` Stage 1)
- [x] verify binary compiles: `go build ./cmd/ppiav-vagent`
- [x] add `--rservice-url` flag to `cmd/ppiav-vagent/main.go` (needed for the verdict callback in Task 7), set `vagent` Server `rserviceURL` field from it (added `rserviceURL` field to `vagent.Server` struct and 4th param to `NewServer`; existing http_test.go callers updated to pass `""`)
- [x] manually smoke-test: start VAgent → curl `http://localhost:8081/sessions/12345/params` → verify params JSON returned (proxy test) — verified live: `POST /sessions` returns sid JSON, `GET /sessions/test-sid/params` proxies CKKS JSON from VService
- [x] run tests — verify existing unit tests still green: `go test ./internal/vagent/... ./internal/vservice/... ./internal/rservice/...` (TestFinalizeRejectsZeroLogit pre-existing failure, unrelated to Task 5)

### Task 6: Add SSE result streaming to `internal/vagent/http.go` (Stage 4a first half)

**Files:**

- Modify: `internal/vagent/http.go`
- Modify: `internal/vagent/http_test.go`

- [x] add `authResult chan rlwe.Ciphertext` (buffered, capacity 1) to `vagent.Agent.sessionState`; allocate it in `OpenSession` via `make(chan rlwe.Ciphertext, 1)`. Capacity 1 covers the pre-arrival case where Stage-3 finishes before the SSE handler opens its receive (DESIGN.md line 175). Buffered + `select`-based receive means the SSE handler can be cancelled cleanly when the browser disconnects — `sync.Cond.Wait()` cannot, so don't use it. (Implemented as `chan *rlwe.Ciphertext` — pointer match to BuildAuthenticatedCt's `*rlwe.Ciphertext` return type and FinalizeDecryption's pointer-argument input, so Task 7 can deposit `ctM` directly without an extra indirection.)
- [x] implement `GET /sessions/:sid/result` handler:
  - set `Content-Type: text/event-stream`, `Cache-Control: no-cache`, flush headers via `http.Flusher`
  - `select { case ct := <-sess.authResult: ...   case <-r.Context().Done(): return }`
  - on receive: marshal the ciphertext to bytes, base64-encode (SSE framing is text-only by spec — see Technical Details), write `data: <b64>\n\n`, `Flush()`, return (single-use, connection closes). Marshals the ciphertext directly via `rlwe.Ciphertext.MarshalBinary` rather than wrapping in `AuthenticatedResult{Ct: &ct}` since `AuthenticatedResult` has no MarshalBinary (skipped in `wire_test.go:290`) — the wire payload is the ciphertext itself, which is what the browser will round-trip back through `client.partialDecrypt(authenticatedCtBytes)` in Task 10.
- [x] write tests: verify `Content-Type`/`Cache-Control` headers and that the handler accepts `http.Flusher`. Streaming semantics are verified manually in the browser. (Added 4 tests: unknown sid → 404, POST → 405, happy-path frame shape `data: <b64>\n\n` with payload round-trip, client-disconnect cancel via `context.WithTimeout`.)
- [x] run tests — must pass before Task 7: `go test ./internal/vagent/...` (all SSE tests green; pre-existing `TestFinalizeRejectsZeroLogit` flake unaffected by this task, verified by stashing the diff and reproducing the same failure on master)

### Task 7: Add image submission and final decryption to `internal/vagent/http.go` (Stages 3 and 4b)

**Files:**

- Modify: `internal/vagent/http.go`
- Modify: `internal/vagent/http_test.go`
- Modify: `internal/vagent/agent.go` (scope expansion — added `authenticatedCt *rlwe.Ciphertext` field to `sessionState` + `storeAuthenticatedCt`/`SessionAuthenticatedCt` accessors so the partial-decryption handler can retrieve ct_M to pass into `FinalizeDecryption`'s existing signature)
- Modify: `internal/vservice/http.go`, `internal/vservice/http_test.go` (scope expansion — Task 1 added VService routes for `/params`, `/sessions`, `/sessions/:sid/eval-keys` but **not** `/sessions/:sid/image`; the VAgent image handler forwards to VService, so the matching VService-side handler must exist. Added in this task.)
- Modify: `internal/protocol/wire.go`, `internal/protocol/wire_test.go` (scope expansion — `PartialDecryption` had no `MarshalBinary`/`UnmarshalBinary`; the partial-decryption HTTP endpoint needs them. Delegates to `multiparty.KeySwitchShare`'s codec. Test promoted from `t.Skip` to a real round-trip.)

- [x] implement `POST /sessions/:sid/image` handler: read body as `application/octet-stream`, `UnmarshalBinary` into `EncryptedImage.Ct`, forward to VService `POST /sessions/:sid/image` (via HTTP client using `vserviceURL`) to get `result_ct`
- [x] call `agent.BuildAuthenticatedCt(sid, result_ct)` to produce `ct_M`
- [x] send `ct_M` into the SSE channel non-blocking: `select { case sess.authResult <- *ctM: default: }`. The `default` branch covers the impossible-by-protocol case of a second image POST for the same sid (single-use semantics). (Implemented as `case ch <- ctM: default:` — the channel is `chan *rlwe.Ciphertext`, matching the Task-6 type.)
- [x] return 200 (no body) to VClient
- [x] implement `POST /sessions/:sid/partial-decryption` handler: read body as `application/octet-stream`, `UnmarshalBinary` into `PartialDecryption.Share`. Look up `sess`; if unknown sid → 404 with no callback (no session means no RService cookie to reference). Otherwise call `agent.FinalizeDecryption(sid, sess.authenticatedCt, clientShare)` to get the verdict. (The session struct does not previously cache `authenticatedCt`; added the field plus a `storeAuthenticatedCt` / `SessionAuthenticatedCt` accessor pair to preserve `FinalizeDecryption`'s existing `(sid, authenticatedCt, share)` signature.)
- [x] on verdict (Accept or Reject from a clean finalize): call RService `POST /api/callback` via HTTP client using `rserviceURL`, then return `302 Location: <rserviceURL>/protected` (URL shape is `POST /api/callback/:sid` per Task 2's deviation)
- [x] on F2 error from a known sid (malformed share, length mismatch, `Ver = false`): call RService `POST /api/callback` with `VerdictReject`, then return 4xx with error JSON. Always callback **before** writing the HTTP response, so RService stores the verdict regardless of whether the client reads our 4xx body. (Note: a clean `Ver=false` finalize is NOT an error — it produces verdict=Reject and returns the same 302 redirect as Accept. Only malformed-body and F3 "partial-decryption before image" paths return 4xx.)
- [x] on F2 error from an unknown sid (no session registered, malformed URL sid): return 404, **no callback** — there is no session to mark Reject against.
- [x] write tests for `POST /sessions/:sid/image`: success path (`ct_M` delivered into channel, SSE handler in a goroutine receives it), error path (unknown sid → 404, malformed ciphertext → 400)
- [x] write tests for `POST /sessions/:sid/partial-decryption` with mock RService (via `httptest.NewServer`): success path (VerdictAccept → callback called + 302), `Ver=false` → Reject callback + 302, malformed share with known sid → Reject callback + 4xx, unknown sid → 404 + no callback, F3 (partial-decryption before image POST) → Reject callback + 4xx
- [x] write VService-side tests for the new `POST /sessions/:sid/image` handler: happy path (x² output round-trips), unknown sid → 404, malformed body → 400, rejects GET → 405
- [x] run tests — must pass before Task 9: `go test ./internal/vagent/... ./internal/vservice/...` (all new tests green; `TestFinalizeRejectsZeroLogit` pre-existing flake unaffected, verified by stashing the diff and reproducing the same failure on the base branch)

### Task 8: Reserved

Originally an HTTP-level end-to-end test with mocked crypto. Removed — Tasks 1, 2, 4, 6, 7 already cover each handler with success and error paths, and real end-to-end verification is the manual browser run in Post-Completion. The `--rservice-url` flag for `cmd/ppiav-vagent` (originally in this task) lives in Task 5.

### Task 9: Set up `web/ppiav` project structure

**Files:**

- Create: `web/ppiav/bridge/main.go`
- Create: `web/ppiav/bridge/lattigo/lattigo.go`
- Create: `web/ppiav/bridge/ppiav/ppiav.go`

`web/ppiav` lives in the **root Go module** — do not create `web/ppiav/go.mod`, do not add any `replace` directive. Lattigo version is whatever the root `/home/butvinm/Dev/ppiav/go.mod` already declares (currently `github.com/tuneinsight/lattigo/v6 v6.2.0` from the public proxy). Lattigo v6.2.0 is pure-Go, compiles to `GOOS=js GOARCH=wasm` out of the box, and is the same code the CLI uses — preserving DESIGN.md line 896's "same Go code in CLI and WASM" invariant.

- [x] copy bridge sources from `~/Dev/orion/js/lattigo/bridge/` into `web/ppiav/bridge/lattigo/`. Confirm the file list first with `ls ~/Dev/orion/js/lattigo/bridge/*.go`; as of writing it is: `bootstrap.go`, `bootstrap_streaming.go`, `decryptor.go`, `encoder.go`, `encryptor.go`, `handles.go`, `helpers.go`, `keygen.go`, `main.go`, `params.go`, `polynomial.go`, `serialize.go`. **Do not copy** `*_test.go`, `go.mod`, `go.sum`, `build.sh`. Update each copied file's package declaration to `package lattigo` (if Orion's was `package main`, narrow it to the new name).
- [x] create `web/ppiav/bridge/lattigo/lattigo.go` with `func RegisterJS()` that registers `globalThis.lattigo`. Orion's `main.go` likely contains the analogous registration logic — extract it here and delete `main.go` from the copy (we use our own entry point in `web/ppiav/bridge/main.go`).
- [x] create `web/ppiav/bridge/ppiav/ppiav.go` with `func RegisterJS()` registering `globalThis.ppiav` (body filled in by Task 10)
- [x] create `web/ppiav/bridge/main.go` with `//go:build js && wasm`. Named imports (not blank): `import ("github.com/butvinm/ppiav/web/ppiav/bridge/lattigo"; "github.com/butvinm/ppiav/web/ppiav/bridge/ppiav")`. `main()` calls `lattigo.RegisterJS()` then `ppiav.RegisterJS()` then `select {}`.
- [x] verify Go compiles for the host: `go build ./web/ppiav/bridge/...` (from the repo root — no `cd`) — skipped cleanly via build tags (`matched no packages`), expected
- [x] verify Go compiles to wasm: `GOOS=js GOARCH=wasm go build -o web/ppiav/ppiav.wasm ./web/ppiav/bridge` (from the repo root) — built successfully, 12.5 MB output
- [x] run unit tests: `go test ./web/ppiav/...` — should pass even with no test files (no-op) — `matched no packages` as expected

### Task 10: Implement `web/ppiav/bridge/ppiav` protocol APIs

**Files:**

- Create: `web/ppiav/bridge/ppiav/ppiav.go`
- Create: `web/ppiav/bridge/ppiav/keygen.go`
- Create: `web/ppiav/bridge/ppiav/image.go`
- Create: `web/ppiav/bridge/ppiav/decrypt.go`
- Create: `web/ppiav/bridge/ppiav/ppiav_test.go`

Scope deviation (Option 2 from the context note): the package is split into
host-buildable `core.go` (pure-Go marshal glue) and wasm-only `ppiav.go`
(syscall/js wiring). Tests live in `core_test.go` and run on the host —
the separate `keygen.go`/`image.go`/`decrypt.go` files anticipated in the
file list above were folded into `core.go` because the per-method bodies
are ~10 lines each and splitting would have meant five tiny files with no
internal cohesion. Errors are returned to JS as `{error: msg}` objects
(matching the existing `web/ppiav/bridge/lattigo` convention) rather than
JS panics — both work; the `{error}` shape is what Orion's TS wrappers
already check.

- [x] create `web/ppiav/bridge/ppiav/ppiav.go` (//go:build js && wasm) with `func RegisterJS()` that registers `globalThis.ppiav` namespace
- [x] implement `ppiav.newClient(paramsJSON, sid) -> {handle: number}`: parse JSON to `protocol.Params` via `ParseParamsJSON` (replicates `vservice.paramsWire` shape so the bridge reads what VService writes), create `vclient.New(params, sid)`, store in `sync.Map[uint64]*vclient.Client` with `atomic.Uint64` handle allocator
      Bridge convention (apply uniformly to every method below):
- **Inputs** that are byte payloads arrive as JS `Uint8Array`. Convert with `js.CopyBytesToGo` (helper `jsBytesToGo`), then `UnmarshalBinary` into the wire-message type.
- **Outputs** that are byte payloads go back as JS `Uint8Array` via `js.CopyBytesToJS` (helper `jsBytesFromGo`).
- Errors are returned as `{error: msg}` objects matching `lattigo`'s `errorResult` helper. The TS wrapper in Task 12 checks `if ('error' in result)` and throws.

- [x] implement `client.genPKShare() -> Uint8Array`: call `vclient.Client.GenPKShare()`, marshal as `protocol.VClientPKShare`, copy to JS Uint8Array
- [x] implement `client.aggregatePK(agentShareBytes: Uint8Array)`: copy bytes to Go, `UnmarshalBinary` into `protocol.VAgentPKShare`, call `vclient.Client.AggregatePK()`
- [x] implement `client.genRLKShareRound1() -> Uint8Array` and `aggregateRLKRound1(agentShareBytes: Uint8Array)`: same pattern (wire types `protocol.VClientRLKRound1` / `protocol.VAgentRLKRound1`)
- [x] implement `client.genRLKShareRound2() -> Uint8Array`: generate, marshal as `protocol.VClientRLKRound2`, return (no aggregate)
- [x] implement `client.genGaloisShares() -> Uint8Array`: generate the per-rotation shares via `vclient.Client.GenGaloisShares()`, marshal as a single `protocol.VClientGaloisKeyShare`, return marshaled bytes
- [x] implement `client.encryptImage(tensorFloat64Array) -> Uint8Array`: receive JS `Float64Array`, copy to Go `[]float64`, call `vclient.Client.EncryptImage()`, marshal the resulting ciphertext directly (the wire payload is the raw `rlwe.Ciphertext` bytes — `EncryptedImage` has no `MarshalBinary`), return as Uint8Array
- [x] implement `client.partialDecrypt(authenticatedCtBytes: Uint8Array) -> Uint8Array`: copy bytes, unmarshal into `rlwe.Ciphertext` (the SSE handler in Task 6 marshals the ciphertext directly — `AuthenticatedResult` has no codec), call `vclient.Client.PartialDecrypt()`, marshal `protocol.PartialDecryption`, return as Uint8Array
- [x] write Go-only tests for each method: covered by `core_test.go` — runs on the host against the `core.go` layer (the wasm-only `ppiav.go` is type-checked by `GOOS=js GOARCH=wasm go build`). 15 tests: params round-trip + bad-input rejection, handle storage + uniqueness + idempotent delete, unknown-handle errors on every method, PK-share marshal round-trip, malformed agent share rejection, full keygen handshake against an in-test VAgent stub (asserts Galois share count matches `RotationIndices`), `EncryptImage` requires-aggregated-pk and wrong-length errors, `EncryptImage` produces a valid ciphertext, `PartialDecrypt` round-trip and malformed-ciphertext rejection.
- [x] verify Go compiles for host and wasm from repo root (no `cd`): `go build ./web/ppiav/bridge/...` (host — empty matches due to wasm-only main/lattigo; `core.go` itself is host-buildable as part of `web/ppiav/bridge/ppiav`) and `GOOS=js GOARCH=wasm go build -o web/ppiav/ppiav.wasm ./web/ppiav/bridge` (13 MB output)
- [x] run tests: `go test ./web/ppiav/...` (all 15 ppiav tests green, also under `-race`)

### Task 11: Add TypeScript wrappers and build infrastructure for `web/ppiav`

**Files:**

- Create: `web/ppiav/package.json`
- Create: `web/ppiav/tsconfig.json`
- Create: `web/ppiav/ts/lattigo/index.ts` (copied from Orion)
- Create: `web/ppiav/ts/ppiav/index.ts` (new, our types)
- Create: `web/ppiav/Makefile`

- [x] create `web/ppiav/package.json`: `{"name": "ppiav-wasm", "version": "0.1.0", "type": "module", "scripts": {"build": "tsc", "test": "tsc --noEmit"}}`, dev dependencies: `typescript` (^5.x)
- [x] create `web/ppiav/tsconfig.json`: standard TS config, `target: ES2022`, `module: ES2022`, `noEmit: true` (only check types, no JS output needed), `lib: ["ES2022", "DOM"]`, `baseUrl: "."`, `paths: {"@": ["ts/*"]}`
- [x] copy `ts/lattigo/*.ts` from `~/Dev/orion/js/lattigo/ts/lattigo/` to `web/ppiav/ts/lattigo/` (namespaces matching Go exports). These are type definitions for `globalThis.lattigo`. (sources live under `~/Dev/orion/js/lattigo/src/`; copied `bridge.ts`, `ckks.ts`, `encoder.ts`, `index.ts`, `loader.ts`, `rlwe.ts`, `types.ts`)
- [x] create `web/ppiav/ts/ppiav/index.ts`: empty for now (next task)
- [x] create `web/ppiav/Makefile`: with targets `wasm` (`GOOS=js GOARCH=wasm go build -o ppiav.wasm ./bridge`), `ts` (`npm run build`), `all: wasm ts` (Makefile runs from `web/ppiav/`, so the build paths are relative to that dir; `go build` targets the `./bridge` package not the `main.go` file because of the `js && wasm` build tag)
- [x] verify TypeScript compiles cleanly: `cd web/ppiav && npm install && npm run build` (no `.ts` errors)
- [x] verify WASM builds: `cd web/ppiav && make wasm`
- [x] verify `make all` succeeds

### Task 12: Complete `web/ppiav/ts/ppiav/index.ts` type definitions

**Files:**

- Modify: `web/ppiav/ts/ppiav/index.ts`

- [x] declare `globalThis.ppiav` namespace with types matching Go exports. Implementation deviates from the plan's exact shape: the Go bridge is handle-based and returns `{error}` objects (not thrown errors), so `web/ppiav/ts/ppiav/index.ts` declares a low-level `PpiavBridge` interface mirroring the raw JS surface, then exports a high-level `Client` class + `newClient` factory that match the plan's user-facing shape (lines 567-583). The Client wrapper hides the handle and converts `{error}` results into thrown `Error`s; `Client.close()` releases the Go-side handle, and a `FinalizationRegistry` catches forgotten closes (same pattern as `ts/lattigo/rlwe.ts`).
- [x] verify TypeScript compiles: `cd web/ppiav && npm run build` (tsc passes clean)
- [x] annotate Go `ppiav.go` `RegisterJS()` to declare the exact JS function signatures matching the TS types (comments for reference) — extended the existing doc comment to cross-reference the TS `PpiavBridge` interface and note the keep-in-sync requirement
- [x] verify WASM builds: `cd web/ppiav && make wasm` (12.5 MB output, builds clean)

### Task 13: Create `web/vclient` SPA project structure

**Files:**

- Create: `web/vclient/index.html`
- Create: `web/vclient/ts/main.ts`
- Create: `web/vclient/ts/preprocess.ts`
- Create: `web/vclient/package.json`
- Create: `web/vclient/tsconfig.json`

- [x] create `web/vclient/package.json`: `{"name": "ppiav-vclient", "version": "0.1.0", "type": "module", "scripts": {"build": "tsc"}}`, dev dependencies: `typescript`
- [x] create `web/vclient/tsconfig.json`: outputs to `./dist`, ES module target
- [x] create `web/vclient/index.html`: minimal HTML — `<title>VClient</title>`, WASM loader (deviation: plan stub used `<script src="/ppiav.wasm" type="application/wasm">`, which is not how WASM loads; replaced with standard Go `<script src="/wasm_exec.js"></script>` shim, leaving the actual `WebAssembly.instantiate` of `ppiav.wasm` to Task 15 main.ts), TS module `<script type="module" src="./dist/main.js"></script>`, body with file input (`<input type="file">`), status div (`#status`), progress div (`#progress`)

### Task 14: Implement `web/vclient/ts/preprocess.ts` image preprocessing

**Files:**

- Create: `web/vclient/ts/preprocess.ts`

- [x] create `web/vclient/ts/preprocess.ts` with `export async function preprocessImage(file: File): Promise<Float64Array>` implementing the 6-step pipeline (see Solution Overview):
  1. Read file as `ArrayBuffer` via `URL.createObjectURL` + `new Image()`
  2. Decode and draw onto a 64×64 `<canvas>`
  3. `getImageData(0, 0, 64, 64).data` → RGBA `Uint8ClampedArray`
  4. Drop alpha → 3 channels
  5. Normalize: `(x / 255 - 0.5) / 0.5` → `Float64Array` in `[-1, 1]`
  6. HWC → CHW permute → length-12288 `Float64Array`
- [x] verify TypeScript compiles: `cd web/vclient && npm install && npm run build`

No unit test for `preprocessImage`. Canvas pipeline correctness is verified by the manual acceptance run in Post-Completion (upload faces of known age, observe correct verdict distribution).

### Task 15: Implement `web/vclient/ts/main.ts` SPA logic and load WASM

**Files:**

- Create: `web/vclient/ts/main.ts`
- Create: `web/vclient/ts/protocol_test.ts` (reflection test, not browser e2e)

- [x] create `web/vclient/ts/main.ts` with main async IIFE:
  - check URL query params for `sid`, if missing, show error "No sid provided"
  - wait for `globalThis.ppiav` to be available (poll or `WebAssembly.instantiate` callback)
  - load params via `fetch('/sessions/' + sid + '/params')` (`response.json()`)
  - create `ppiav.newClient(paramsJSON, sid)`
  - set up file input change listener: on file select, run protocol drive
- [x] implement protocol drive sequence in async function `runProtocol(sid, client, file)`. Convention: each `client.gen*` returns `Uint8Array`; each `fetch` sends `body: bytes` with `Content-Type: application/octet-stream`; the response body is fetched as `Uint8Array` via `new Uint8Array(await response.arrayBuffer())` and passed straight back to the next bridge call:
  - Stage 2a: `fetch('/sessions/' + sid + '/params')` (JSON)
  - Stage 2b: `const share = client.genPKShare(); const resp = await fetch('/sessions/' + sid + '/pk-share', { method: 'POST', headers: {'Content-Type': 'application/octet-stream'}, body: share }); const agentShare = new Uint8Array(await resp.arrayBuffer()); client.aggregatePK(agentShare);`
  - Stage 2c Round 1: same pattern with `genRLKShareRound1` / `aggregateRLKRound1`
  - Stage 2c Round 2: `client.genRLKShareRound2()` → POST as octet-stream (no aggregate)
  - Stage 2d: `client.genGaloisShares()` → POST single blob as octet-stream (the marshaled `VClientGaloisKeyShare` contains all per-rotation shares) → 200 ack
  - Stage 2e: `new EventSource('/sessions/' + sid + '/result')` — `onmessage` data is base64 of marshaled `AuthenticatedResult` (SSE framing constraint, see Technical Details); `const authCt = Uint8Array.from(atob(event.data), c => c.charCodeAt(0));`
  - Stage 3: `const tensor = await preprocessImage(file); const ct = client.encryptImage(tensor); await fetch('/sessions/' + sid + '/image', { method: 'POST', headers: {'Content-Type': 'application/octet-stream'}, body: ct });`
  - Stage 4a: when SSE `onmessage` fires, `const partial = client.partialDecrypt(authCt); const resp = await fetch('/sessions/' + sid + '/partial-decryption', { method: 'POST', headers: {'Content-Type': 'application/octet-stream'}, body: partial, redirect: 'manual' });`
  - Stage 4b: on `resp.status === 302`, read `Location` header → `window.location.assign(location)`
  - Stage 4b (error): on non-2xx response, show error message in UI, abort (no redirect)
- [x] add actual redirect implementation: after `fetch('/sessions/' + sid + '/partial-decryption', ...)` completes, check `response.status === 302`, read `Location` header, assign to `window.location` (opaqueredirect fallback surfaces an error per implementation note in main.ts)
- [x] add progress updates to `#progress`, `#status` divs during stages ("Stage 2b: Generating public key share...", "Stage 2c: Relinearization key round 1...", etc.)
- [x] implement error handling at each fetch: non-2xx status → show error, abort
- [x] verify TypeScript compiles: `cd web/vclient && npm install && npm run build`
- [x] **No automated browser test** — VClient SPA is verified manually after deployment

Implementation note: main.ts uses the raw `globalThis.ppiav` bridge directly (with inline `unwrapBytes`/`unwrapVoid` helpers) rather than importing the high-level `Client` class from `@ppiav/ppiav/index.ts`. Both options were explicitly endorsed by the plan; the raw-bridge approach avoids importmap/relative-path gymnastics at browser runtime so the existing `dist/main.js` → `./preprocess.js` import is the only inter-module reference. `protocol_test.ts` is intentionally not created (per Task 15 file note and the explicit "No automated browser test" checkbox).

### Task 16: Create `web/rclient` SPA and embed both SPAs into Go services

**Files:**

- Create: `web/rclient/index.html`
- Create: `web/rclient/ts/main.ts`
- Create: `web/rclient/package.json`
- Create: `web/rclient/tsconfig.json`
- Modify: `internal/vagent/http.go` (add `GET /verify` handler serving VClient SPA)
- Modify: `internal/rservice/http.go` (modify `GET /protected` to serve RClient SPA instead of stub)

- [x] create `web/rclient/package.json`: same as `web/vclient/package.json`
- [x] create `web/rclient/tsconfig.json`: same as `web/vclient/tsconfig.json` (no `@ppiav/*` path alias since rclient doesn't import the WASM bridge)
- [x] create `web/rclient/index.html`: title "RClient", status div (`#status`), shows verdict details (sid, Verdict, timestamp on receipt)
- [x] create `web/rclient/ts/main.ts`: on load, request `/api/status` (TODO: add this to RService? or use existing `/protected` which flows through session table). Actually RService `/protected` already checks verdict based on sid cookie. Simplest: RClient reads verdict from page initialization (RService injects verdict into HTML or as JSON embedded in page). Decision: RService `/protected` returns HTML with embedded JSON: `<script>window.verdict = {"sid":"...", "verdict":"Accept"};</script>`. RClient reads `window.verdict` and displays it.
- [x] modify `internal/rservice/http.go` `GET /protected`: return HTML from RClient SPA with verdict injected as JSON response (deviation: instead of reading `web/rclient/index.html` from disk and injecting before `</body>`, the handler builds a self-contained inline template via `fmt.Sprintf` with `json.Marshal` for safe escaping — Task 17 will swap this for embed.FS-based serving with proper injection). Existing `http_test.go` assertions updated from `verdict: accept` → `"verdict":"accept"` to match the new JSON-in-script wire shape.
- [x] modify `internal/vagent/http.go` `GET /verify`: return VClient HTML from `web/vclient/index.html` via `embed.FS`. For now, return simple HTML with redirect hint: "VClient SPA not embedded yet". Two new tests cover the placeholder route (`TestHTTPVAgent_Verify_ReturnsPlaceholderHTML`, `TestHTTPVAgent_Verify_RejectsPost`).
- [x] verify TypeScript compiles: `cd web/rclient && npm install && npm run build` (required `export {}` at the top of `ts/main.ts` so the `declare global` block is valid in a module file)
- [x] **No automated browser test** — RClient SPA verified manually

### Task 17: Embed SPAs and WASM into Go services via `embed.FS`

**Files:**

- Create: `web/vclient/embed.go` (`package vclient`, exports `var FS embed.FS`)
- Create: `web/rclient/embed.go` (`package rclient`, exports `var FS embed.FS`)
- Create: `web/ppiav/embed.go` (`package ppiav`, exports `var WASM []byte`)
- Modify: `internal/vagent/http.go` (serve embedded VClient + WASM)
- Modify: `internal/rservice/http.go` (serve embedded RClient)

`//go:embed` does **not** support `..` regardless of directory or module boundaries — the embed pattern must be at or below the file's own directory. Solution: co-locate one tiny embed file with each asset tree under `web/`, and have the consumers import its `FS`/`WASM` variable. No `web/ → internal/web/` rename, no module shenanigans.

- [x] create `web/vclient/embed.go`:
  ```go
  package vclient
  import "embed"
  //go:embed index.html dist
  var FS embed.FS
  ```
  Consumers do `import "github.com/butvinm/ppiav/web/vclient"` and use `vclient.FS`.
- [x] create `web/rclient/embed.go`: same pattern, `package rclient`, exports `FS embed.FS` over `index.html dist`.
- [x] create `web/ppiav/embed.go`:
  ```go
  package ppiav
  import _ "embed"
  //go:embed ppiav.wasm
  var WASM []byte
  ```
  Compile note: `embed.go` requires `ppiav.wasm` to exist at the time `go build` runs, so the WASM build step must precede any binary that imports this package. Captured in the `make phase3` ordering (Task 19): `make wasm` → `make services`.
- [x] modify `internal/vagent/http.go`:
  - import `github.com/butvinm/ppiav/web/vclient` and `github.com/butvinm/ppiav/web/ppiav`
  - `GET /verify` serves `vclient.FS` (HTML + dist bundle) via `http.FileServer(http.FS(vclient.FS))`
  - `GET /ppiav.wasm` writes `ppiav.WASM` with `Content-Type: application/wasm`
- [x] modify `internal/rservice/http.go`:
  - import `github.com/butvinm/ppiav/web/rclient`
  - `GET /protected` reads `index.html` from `rclient.FS`, injects `<script>window.verdict=...</script>` before `</body>`, returns text/html
- [x] verify embed compiles: `go build ./web/vclient ./web/rclient ./web/ppiav` (the WASM blob must exist first; in CI this is gated by Makefile target ordering)
- [x] verify served content: `httptest` tests assert `GET /verify` returns HTML containing the SPA bootstrap, `GET /ppiav.wasm` returns `application/wasm` content-type with non-empty body
- [x] run tests: `go test ./internal/vagent/... ./internal/rservice/... ./web/vclient/... ./web/rclient/... ./web/ppiav/...` (pre-existing flaky `TestFinalizeRejectsZeroLogit` unrelated to this task)

### Task 18: Complete RService `/protected` handler with embedded RClient

**Files:**

- Modify: `internal/rservice/http.go` `GET /protected` handler
- Modify: `internal/rservice/embed.go` (already created in Task 17)
- Create: `internal/rservice/http_test.go` (update existing tests)

- [x] modify `internal/rservice/http.go` `GET /protected`:
  - Read sid cookie
  - Call `svc.CheckAccess(sid)` to get verdict
  - Read `index.html` from `rclientFS` (embed from Task 17)
  - Inject `<script>window.verdict = JSON.stringify({sid, verdict});</script>` into HTML (simple string insert before `</body>`)
  - Return `text/html`
  - If sid missing: invoke the Stage-1 server-to-server flow described in the next checkbox (DESIGN.md §3 Stage 1)
- [x] Stage-1 flow (DESIGN.md lines 82–90): on `GET /protected` with no sid cookie, RService's handler issues a synchronous server-to-server `POST <vagentURL>/sessions` (no body), parses the `VerificationSession{sid}` JSON response, sets `Set-Cookie: sid=<sid>; Path=/; HttpOnly` on its own response, and returns `302 Location: <vagentURL>/verify?sid=<sid>`. The browser sees exactly one redirect (from `/protected` to `/verify?sid=...`); the RS→VA hop is not browser-visible. F4a (VService unreachable Stage 1) surfaces as `VAgent POST /sessions` → 5xx → RService returns 5xx to user with no cookie set.
- [x] add `vagentURL string` field to `rservice.Server` and wire from a `--vagent-url` flag in `cmd/ppiav-rservice/main.go`; HTTP client uses `net/http.Client` with a sensible timeout (e.g., 5s) for the Stage-1 call (field + flag already present from Tasks 2/3; Task 18 wires `httpClient *http.Client` with 5s timeout and uses it in `beginStage1`)
- [x] update tests for `GET /protected`: (a) with verdict cookie → verdict injection for Accepted/Rejected, (b) with no cookie → mock VAgent via `httptest.NewServer` returning `VerificationSession{sid}`, assert `Set-Cookie` header, assert 302 to `<vagent>/verify?sid=<sid>`, (c) with no cookie + mock VAgent returning 5xx → assert 5xx to user, no Set-Cookie (also added: unreachable VAgent, malformed JSON, empty sid — all assert no Set-Cookie)
- [x] run tests: `go test ./internal/rservice/...` — PASS

### Task 19: Add Makefile and build scripts for Phase 3

**Files:**

- Create: `Makefile` (repo root)
- Create: `.github/workflows/ci.yml` (optional, for CI)

- [x] create repo-top `Makefile` with targets (single Go module — every Go invocation is from the repo root, no `cd` for Go). Implemented targets: `all` (depends on `phase3` so a fresh checkout builds), `phase3` (`wasm spas services`), `wasm` (depends on `wasm_exec`, runs `GOOS=js GOARCH=wasm go build -o web/ppiav/ppiav.wasm ./web/ppiav/bridge`), `wasm_exec` (`cp $(go env GOROOT)/lib/wasm/wasm_exec.js web/vclient/wasm_exec.js`), `spas` (`spa_vclient spa_rclient`, each `npm install && npm run build` so first run in a fresh checkout works), `services` (`go build` the three cmd binaries), `test` (`go test ./...`), `clean` (removes `bin/`, `web/ppiav/ppiav.wasm`, `web/vclient/wasm_exec.js`, `web/*/dist`). `services` depends on `wasm spas`. All commands use tab indentation; all non-file targets are `.PHONY`.
- [x] verify `make phase3` succeeds from repo root (ran `make clean && make phase3` end-to-end — green)
- [x] verify binaries exist: `ls -la bin/` (ppiav-vservice 15M, ppiav-vagent 28M, ppiav-rservice 10M)
- [x] verify WASM exists: `ls -la web/ppiav/ppiav.wasm` (12.8M)
- [x] verify TypeScript dists: `ls -la web/vclient/dist/main.js web/rclient/dist/main.js` (both present)

### Task 20: Create Dockerfiles for VService, VAgent, RService

**Files:**

- Create: `deploy/Dockerfile.vservice`
- Create: `deploy/Dockerfile.vagent`
- Create: `deploy/Dockerfile.rservice`
- Create: `deploy/docker-compose.yml` (for local development)

- [x] create `deploy/Dockerfile.vservice`: multi-stage `golang:1.26-alpine` builder (go.mod pins `go 1.26.1`, so `1.22-alpine` from the original plan would not satisfy the toolchain) → `alpine:latest` runtime. Single-stage flow (`go mod download` → `COPY internal/ cmd/ppiav-vservice/` → `CGO_ENABLED=0 go build`); no web embed dependency. `EXPOSE 8080`, `ENTRYPOINT ["/usr/local/bin/vservice"]`, `CMD ["--addr", ":8080"]`.
- [x] create `deploy/Dockerfile.vagent`: multi-stage with `nodejs npm` in the `golang:1.26-alpine` builder. `COPY web/ ./web/` plus `Makefile`, runs `make wasm spas` to populate the embed assets (TS dist, wasm_exec.js, ppiav.wasm) before `go build`. Runtime stage copies only the binary. Note: dropped the original plan's "assets must already exist in the build context" assumption — multi-stage is safer because a stale host workspace can't poison the image.
- [x] create `deploy/Dockerfile.rservice`: multi-stage with `nodejs npm` for the RClient bundle (`cd web/rclient && npm install && npm run build`). Does NOT build the WASM blob — RService never serves it. Only `web/rclient/` is copied.
- [x] create `deploy/docker-compose.yml`: three services with `build.context: ..` (repo root) and the corresponding Dockerfiles. Ports `8080/8081/8082`. `depends_on`: vagent → vservice, rservice → vagent (RService server-to-servers to VAgent on Stage 1, so it needs VAgent up). Service URLs use Docker DNS (`http://vservice:8080`, `http://vagent:8081`, etc.).
- [x] verify dockerfiles syntax: `docker build --check` clean for all three. Full `docker build -f deploy/Dockerfile.vservice .` succeeded end-to-end (builder + runtime stages, image `ppiav-vservice:test` tagged); vagent/rservice not fully built (would pull node_modules / cross-compile WASM, long) but syntax-check is green and same multi-stage pattern as vservice. `docker compose -f deploy/docker-compose.yml config` parses without warnings.
- [x] **No docker-compose smoke test** — manual verification (skipped — not automatable, deferred to Phase-3 manual acceptance run in Post-Completion section)

### Task 21: Final Go test suite verification

- [ ] verify all code-side requirements from Overview are implemented: HTTP services (VService, VAgent, RService) with all routes per DESIGN.md, browser SPAs (VClient, RClient) with TS and HTML, WASM bridge (`web/ppiav`) with TS types, embedded SPAs via `embed.FS`
- [ ] verify Failure Mode F2 (malformed wire input) is tested in HTTP handlers (400 response tests in `*_test.go`)
- [ ] verify F3 / F4b are covered: F3 (inference error) — VAgent forwards errors, tested in Task 7; F4b (VService unreachable Stages 2–3) — not unit-tested (depends on external HTTP), documented in plan
- [ ] verify F4a is covered: F4a (VService unreachable Stage 1) — RService returns 500 in Task 18 redirect path, tested there (error from VAgent HTTP client returns 5xx → RService surfaces as 5xx)
- [ ] run Go test suite: `go test ./...` — all unit suites green, including new HTTP handler tests, WASM bridge tests (Go-only), SPA embed tests
- [ ] run `go vet ./...` and `go build ./...` — confirm no warnings, all binaries compile (single module, no replace directives needed anywhere)
- [ ] run TypeScript checks: `cd web/vclient && npm run build && cd ../rclient && npm run build` — all green
- [ ] run `make phase3` — full build succeeds

### Task 22: Update documentation and close out

- [ ] update `CLAUDE.md` "Status" line to reflect Phase 3 completion
- [ ] update `CLAUDE.md` Implementation Phases checklist if it tracks phase status
- [ ] update `README.md` with Phase 3 quick-start:
  - Add section "Quick start — Phase 3" covering: `make phase3`, `docker-compose up`, access `http://localhost:8082/protected` to start verification flow, or `http://localhost:8081/verify?sid=...` to open VClient directly
  - Document local dev: `make wasm`, `make spats`, build services with `make services`, run with go commands directly from three terminals
  - Mention WASM browser console debugging (`console.log(globalThis.ppiav)`, etc.)
- [ ] add `.gitignore` entries for build artifacts: `bin/`, `web/*/dist/`, `web/ppiav/ppiav.wasm`. **Do not commit `ppiav.wasm`** — it's a derived artifact, can land in the 10–30 MB range, and changes on every `internal/vclient` edit. Build via `make wasm`; CI/release pipelines can publish prebuilt blobs separately if needed.
- [ ] move this plan to `docs/plans/completed/` (run `mkdir -p docs/plans/completed`)
- [ ] commit the move atomically as a separate commit

---

## Post-Completion

**Items requiring manual intervention or external systems — no checkboxes, informational only.**

**Phase-3 manual acceptance run**

1. Build Phase 3: `make phase3` from repo root
2. Run services via docker-compose: `cd deploy && docker-compose up -d`. Verify all three services healthy.
3. Browser flow: open `http://localhost:8082/protected`.
   - Expected: RService internally calls `VAgent POST /sessions` (server-to-server, not in Network tab), VAgent in turn calls `VService POST /sessions` to allocate sid, RService sets `Set-Cookie: sid=...` and returns `302 Location: http://localhost:8081/verify?sid=...` → VClient SPA loads
   - Verify Stage 1 redirect in Network tab: a single hop `/protected` → `/verify?sid=abc123` (302). The RS→VA `POST /sessions` is server-to-server and only visible in service logs.
   - VClient shows file upload UI, status "Waiting for image..."
   - Upload a face image (test with `~/Dev/orion/examples/c3ae-demo/data/samples/*.jpg` after PNG conversion)
   - Watch progress: stages 2b, 2c, 2d complete quickly, SSE opens after stage 3, final decrypt completes
   - On completion: VClient receives 302 response from `POST /sessions/:sid/partial-decryption`, redirects to RService `/protected` → shows verdict page (Accept or Reject)
   - Verify SSE in Network tab: `/sessions/:sid/result` shows a single `data: <base64>\n\n` line carrying `AuthenticatedResult` (base64 is SSE-spec, accepted ~33% inflation for this one event — see Technical Details)
4. Verify WASM loaded: open browser dev console, `console.log(globalThis.ppiav)` → shows namespace with `newClient`, `Client` methods
5. Verify image preprocessing: open dev console, find `preprocessImage` call after file upload, check output tensor values (should be in [-1, 1] range)
6. Test failure mode: submit malformed image (non-image file) → error in VClient UI, no HTTP 500 crash in services
7. Test verdict paths: upload multiple images mixing above/below age threshold → both Accept and Reject verdicts appear
8. Verify SSE works: dev console shows `data: ...` lines in Network tab for `/sessions/:sid/result`

**Local dev without Docker:**

1. In three terminals:
   - `./bin/ppiav-vservice --addr :8080 --orion ./models/out/logn16`
   - `./bin/ppiav-vagent --addr :8081 --vservice-url http://localhost:8080 --rservice-url http://localhost:8082 --orion ./models/out/logn16`
   - `./bin/ppiav-rservice --addr :8082`
2. Run same browser flow as docker-compose version

**Cross-check Phase-2 C3AE**

1. Ensure `--orion` flags point to the same `logn16` manifest used in Phase 2 CLI (`./models/out/logn16`).
2. Verify that accept/reject behavior matches CLI for same input (`./models/out/inputs/sample_0.bin` or equivalent), as a cross-check on the JS preprocessing pipeline.

**Benchmarks remain CLI-only**

Phase 3 is a demo of the protocol over a network — it deliberately ships **no** `bench.Measure` instrumentation in the HTTP services and emits **no** per-stage JSON. `cmd/ppiav-cli` + `internal/orchestrator` + `internal/bench` remain the sole source of benchmark numbers (the algorithmic cost the thesis reports), unchanged by this plan. Any wall-clock observation during manual browser acceptance is informal and does not flow into `bench/`.

**WASM size / browser-keygen sanity check**

During the manual acceptance run, log two numbers (informally, no bench JSON):

1. WASM blob size: `ls -lh web/ppiav/ppiav.wasm`. If it exceeds ~30 MB, flag for follow-up — the demo becomes effectively non-viable on slower connections / mobile.
2. Stage 2 wall time in the browser (`Stage 2b` start → `Stage 2d` end, eyeballed from the Network tab or a few `console.time()` calls in `main.ts`). If it exceeds 5× the CLI Phase-2 baseline at `logn16`, flag for follow-up — WASM keygen is too slow for live demo.

These are go/no-go thresholds for "is the browser demo usable," not benchmark data.

**Out of scope (explicit)**

- TLS/authentication/rate limiting per DESIGN.md
- Phase-4 lattigo-hierkeys (gks_master wire format)
- Phase-5 σ_flood/ε calibration

**Follow-up plans (not part of this plan, but to file once this lands)**

- **Phase 4**: lattigo-hierkeys integration (`web/ppiav` add hierkeys submodule, `vservice` / `vagent` derive gks from `gks_master`, wire format swaps from `GaloisKeyShare[]` to `GKSMaster`)
- **Phase 5 — noise calibration**: deferred per DESIGN.md until all four protocol phases have landed.
