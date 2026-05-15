// VClient SPA entry point.
//
// On load: parse sid from URL, instantiate the ppiav WASM module (Go +
// wasm_exec.js shim), fetch params for the session, build a client via
// the raw `globalThis.ppiav` bridge, and wire the file input to drive the
// full multi-party protocol (Stages 2b..4b).
//
// At the end of Stage 4b the VAgent returns
// `200 {"redirect": "<rservicePublicURL>/protected"}` — we read the URL
// and call `window.location.assign`. JSON 200 (rather than 302) is the
// canonical pattern: `fetch(redirect: "manual")` always produces an
// opaqueredirect response whose Location header is unreadable per the
// Fetch spec, and `redirect: "follow"` would force a second POST of the
// single-shot partial-decryption (which 404s).
//
// This file uses the raw `globalThis.ppiav` namespace directly rather
// than importing the high-level Client wrapper from `@ppiav/ppiav`. The
// raw bridge avoids any module-resolution gymnastics at browser runtime
// (no importmap, no relative paths into a sibling package). Each call
// returns either a raw value (Uint8Array, null) or an `{error: string}`
// object — we unwrap inline.

import { preprocessImage } from "./preprocess.js";

// wasm_exec.js installs this constructor on globalThis once loaded.
interface GoRuntime {
  importObject: WebAssembly.Imports;
  run(instance: WebAssembly.Instance): Promise<void>;
}
interface GoRuntimeConstructor {
  new (): GoRuntime;
}

// Raw ppiav bridge surface (matches web/ppiav/ts/ppiav/index.ts).
interface ErrorResult {
  error: string;
}
interface HandleResult {
  handle: number;
}
interface PpiavBridge {
  __ready: boolean;
  newClient(paramsJSON: string, sid: string): HandleResult | ErrorResult;
  deleteClient(handle: number): null;
  genPKShare(handle: number): Uint8Array | ErrorResult;
  aggregatePK(handle: number, agentShareBytes: Uint8Array): null | ErrorResult;
  genRLKShareRound1(handle: number): Uint8Array | ErrorResult;
  aggregateRLKRound1(
    handle: number,
    agentShareBytes: Uint8Array,
  ): null | ErrorResult;
  genRLKShareRound2(handle: number): Uint8Array | ErrorResult;
  genGaloisShares(handle: number): Uint8Array | ErrorResult;
  encryptImage(handle: number, tensor: Float64Array): Uint8Array | ErrorResult;
  partialDecrypt(
    handle: number,
    authenticatedCtBytes: Uint8Array,
  ): Uint8Array | ErrorResult;
}

declare global {
  // eslint-disable-next-line no-var
  var Go: GoRuntimeConstructor | undefined;
  // eslint-disable-next-line no-var
  var ppiav: PpiavBridge;
}

const WASM_URL = "/ppiav.wasm";
const READY_TIMEOUT_MS = 10_000;
const READY_POLL_MS = 20;

function isError(v: unknown): v is ErrorResult {
  return (
    typeof v === "object" &&
    v !== null &&
    typeof (v as { error?: unknown }).error === "string"
  );
}

function unwrapBytes(v: Uint8Array | ErrorResult, op: string): Uint8Array {
  if (isError(v)) {
    throw new Error("ppiav." + op + ": " + v.error);
  }
  return v;
}

function unwrapVoid(v: null | ErrorResult, op: string): void {
  if (isError(v)) {
    throw new Error("ppiav." + op + ": " + v.error);
  }
}

function setStatus(msg: string): void {
  const el = document.getElementById("status");
  if (el !== null) {
    el.textContent = msg;
  }
}

function setProgress(msg: string): void {
  const el = document.getElementById("progress");
  if (el !== null) {
    el.textContent = msg;
  }
}

function showError(msg: string): void {
  setStatus("Error: " + msg);
  console.error("[vclient]", msg);
}

async function loadWasm(): Promise<void> {
  if (typeof globalThis.Go === "undefined") {
    throw new Error(
      "Go WASM runtime not found — wasm_exec.js must load before main.js",
    );
  }
  const existing = globalThis.ppiav as { __ready?: boolean } | undefined;
  if (existing?.__ready === true) {
    return;
  }
  const go = new globalThis.Go();
  let instance: WebAssembly.Instance;
  if (typeof WebAssembly.instantiateStreaming === "function") {
    const result = await WebAssembly.instantiateStreaming(
      fetch(WASM_URL),
      go.importObject,
    );
    instance = result.instance;
  } else {
    const response = await fetch(WASM_URL);
    const buf = await response.arrayBuffer();
    const result = await WebAssembly.instantiate(buf, go.importObject);
    instance = result.instance;
  }
  // Non-blocking — Go's main runs select{} to keep the runtime alive.
  void go.run(instance);
  // Poll for readiness: ppiav.RegisterJS sets __ready = true last.
  const deadline = Date.now() + READY_TIMEOUT_MS;
  while (Date.now() < deadline) {
    const bridge = globalThis.ppiav as { __ready?: boolean } | undefined;
    if (bridge?.__ready === true) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, READY_POLL_MS));
  }
  throw new Error(
    "ppiav WASM bridge did not become ready within " +
      READY_TIMEOUT_MS +
      "ms",
  );
}

function getSidFromURL(): string | null {
  const params = new URLSearchParams(window.location.search);
  const sid = params.get("sid");
  if (sid === null || sid === "") {
    return null;
  }
  return sid;
}

async function fetchParams(sid: string): Promise<string> {
  const resp = await fetch("/sessions/" + sid + "/params");
  if (!resp.ok) {
    throw new Error(
      "fetch params: HTTP " + resp.status + " " + (await resp.text()),
    );
  }
  // Pass raw JSON text to the WASM bridge; no need to parse here.
  return await resp.text();
}

async function postBinary(url: string, body: Uint8Array): Promise<Response> {
  // new Uint8Array(body) coerces Uint8Array<ArrayBufferLike> (the WASM
  // bridge's return type) into the Uint8Array<ArrayBuffer> that Fetch
  // BodyInit accepts under TS 5.9+.
  return await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/octet-stream" },
    body: new Uint8Array(body),
  });
}

async function expectOkBinary(
  url: string,
  body: Uint8Array,
): Promise<Uint8Array> {
  const resp = await postBinary(url, body);
  if (!resp.ok) {
    throw new Error(
      "POST " + url + ": HTTP " + resp.status + " " + (await resp.text()),
    );
  }
  return new Uint8Array(await resp.arrayBuffer());
}

async function expectOkAck(url: string, body: Uint8Array): Promise<void> {
  const resp = await postBinary(url, body);
  if (!resp.ok) {
    throw new Error(
      "POST " + url + ": HTTP " + resp.status + " " + (await resp.text()),
    );
  }
  // Drain body so the connection can be reused.
  await resp.arrayBuffer();
}

/**
 * Open the SSE result stream and resolve with the marshaled
 * AuthenticatedResult bytes when the single `data:` event arrives.
 *
 * Per DESIGN.md §3 Stage 2e/4a, the stream is opened *before* the image
 * POST so the ct_M deposit can never miss the receiver.
 */
function openResultStream(sid: string): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    const url = "/sessions/" + sid + "/result";
    const es = new EventSource(url);
    let settled = false;
    es.onmessage = (event: MessageEvent<string>) => {
      try {
        // SSE framing is text-only: AuthenticatedResult is base64.
        const binStr = atob(event.data);
        const bytes = new Uint8Array(binStr.length);
        for (let i = 0; i < binStr.length; i++) {
          bytes[i] = binStr.charCodeAt(i);
        }
        settled = true;
        es.close();
        resolve(bytes);
      } catch (err) {
        settled = true;
        es.close();
        reject(err instanceof Error ? err : new Error(String(err)));
      }
    };
    es.addEventListener("error", (_ev: Event) => {
      // EventSource fires "error" both on transient disconnects and on
      // the final close after the one-shot event. Only surface a failure
      // if we never received the data event.
      if (!settled && es.readyState === EventSource.CLOSED) {
        reject(new Error("SSE stream closed before AuthenticatedResult"));
      }
    });
  });
}

async function runProtocol(
  sid: string,
  handle: number,
  file: File,
): Promise<void> {
  const bridge = globalThis.ppiav;

  // Stage 2b — public key share.
  setProgress("Stage 2b: Generating public key share...");
  const pkShare = unwrapBytes(bridge.genPKShare(handle), "genPKShare");
  const agentPK = await expectOkBinary(
    "/sessions/" + sid + "/pk-share",
    pkShare,
  );
  unwrapVoid(bridge.aggregatePK(handle, agentPK), "aggregatePK");

  // Stage 2c round 1.
  setProgress("Stage 2c: Relinearization key round 1...");
  const rlk1 = unwrapBytes(
    bridge.genRLKShareRound1(handle),
    "genRLKShareRound1",
  );
  const agentRLK1 = await expectOkBinary(
    "/sessions/" + sid + "/rlk/round1",
    rlk1,
  );
  unwrapVoid(
    bridge.aggregateRLKRound1(handle, agentRLK1),
    "aggregateRLKRound1",
  );

  // Stage 2c round 2.
  setProgress("Stage 2c: Relinearization key round 2...");
  const rlk2 = unwrapBytes(
    bridge.genRLKShareRound2(handle),
    "genRLKShareRound2",
  );
  await expectOkAck("/sessions/" + sid + "/rlk/round2", rlk2);

  // Stage 2d — Galois key shares (single blob, all rotations).
  setProgress("Stage 2d: Galois key shares...");
  const gks = unwrapBytes(bridge.genGaloisShares(handle), "genGaloisShares");
  await expectOkAck("/sessions/" + sid + "/gks-shares", gks);

  // Stage 2e — open SSE before image POST (Stage 3) so ct_M cannot be lost
  // to a pre-arrival race.
  setProgress("Stage 2e: Opening result stream...");
  const resultPromise = openResultStream(sid);

  // Stage 3 — preprocess and encrypt the image, POST to VAgent.
  setProgress("Stage 3: Preprocessing image...");
  const tensor = await preprocessImage(file);
  setProgress("Stage 3: Encrypting image...");
  const ct = unwrapBytes(bridge.encryptImage(handle, tensor), "encryptImage");
  setProgress("Stage 3: Submitting encrypted image...");
  await expectOkAck("/sessions/" + sid + "/image", ct);

  // Stage 4a — wait for AuthenticatedResult, run partial decryption.
  setProgress("Stage 4a: Waiting for authenticated result...");
  const authCt = await resultPromise;
  setProgress("Stage 4a: Computing partial decryption...");
  const partial = unwrapBytes(
    bridge.partialDecrypt(handle, authCt),
    "partialDecrypt",
  );

  // Stage 4b — POST partial decryption; server replies 200 with
  // `{"redirect": "<url>"}`. JSON 200 (rather than 302) is intentional —
  // see the file header for the spec-level rationale.
  setProgress("Stage 4b: Submitting partial decryption...");
  const redirect = await postPartialDecryption(sid, partial);
  window.location.assign(redirect);
}

// postPartialDecryption returns the `redirect` URL from VAgent's JSON 200
// reply. Distinct from `postBinary` because the response is JSON, not
// Uint8Array — see the file header for why we don't use a 302.
async function postPartialDecryption(
  sid: string,
  partial: Uint8Array,
): Promise<string> {
  const resp = await postBinary("/sessions/" + sid + "/partial-decryption", partial);
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error("partial-decryption: HTTP " + resp.status + " " + text);
  }
  const body = (await resp.json()) as { redirect?: unknown };
  if (typeof body.redirect !== "string" || body.redirect === "") {
    throw new Error(
      "partial-decryption: response missing 'redirect' field: " +
        JSON.stringify(body),
    );
  }
  return body.redirect;
}

async function main(): Promise<void> {
  const sid = getSidFromURL();
  if (sid === null) {
    showError("No sid provided in URL (expected ?sid=<id>)");
    return;
  }
  setStatus("Loading WASM...");
  try {
    await loadWasm();
  } catch (err) {
    showError(
      "WASM load failed: " +
        (err instanceof Error ? err.message : String(err)),
    );
    return;
  }
  setStatus("Fetching session parameters...");
  let paramsJSON: string;
  try {
    paramsJSON = await fetchParams(sid);
  } catch (err) {
    showError(
      "Could not load session params: " +
        (err instanceof Error ? err.message : String(err)),
    );
    return;
  }
  const bridge = globalThis.ppiav;
  const created = bridge.newClient(paramsJSON, sid);
  if (isError(created)) {
    showError("Could not construct ppiav client: " + created.error);
    return;
  }
  const handle = created.handle;
  setStatus("Ready. Select an image to verify.");
  setProgress("");

  const input = document.getElementById("image-input");
  if (!(input instanceof HTMLInputElement)) {
    showError("Missing #image-input file input");
    return;
  }
  input.addEventListener("change", () => {
    const file = input.files?.[0];
    if (file === undefined) {
      return;
    }
    input.disabled = true;
    setStatus("Running verification protocol...");
    runProtocol(sid, handle, file)
      .catch((err: unknown) => {
        showError(
          "Protocol failed: " +
            (err instanceof Error ? err.message : String(err)),
        );
        input.disabled = false;
      })
      .finally(() => {
        // Best-effort cleanup; ignored if redirect already navigated away.
        try {
          bridge.deleteClient(handle);
        } catch {
          // ignore
        }
      });
  });
}

void main();
