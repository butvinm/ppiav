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
import {
  ProgressTracker,
  type StepHandle,
  type StepSpec,
} from "./progress.js";
import {
  postBinaryFetch,
  postBinaryFetchJSON,
  postBinaryXHR,
} from "./net.js";

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
// XHR threshold: bodies larger than this go through XMLHttpRequest so the
// upload bar can be driven by upload.onprogress. Below this, plain fetch
// fills the bar to 100% on resolve — the byte total is still shown.
const XHR_THRESHOLD = 1024 * 1024;

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

function setStatus(msg: string, error = false): void {
  const el = document.getElementById("status");
  if (el !== null) {
    el.textContent = msg;
    el.classList.toggle("error", error);
  }
}

function showError(msg: string): void {
  setStatus("Error: " + msg, true);
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

const STEP_SPECS: StepSpec[] = [
  { id: "pk-gen", label: "Generate PK share", kind: "wasm" },
  { id: "pk-exchange", label: "Exchange PK share", kind: "network" },
  { id: "pk-aggregate", label: "Aggregate PK", kind: "wasm" },
  { id: "rlk1-gen", label: "Generate RLK round-1 share", kind: "wasm" },
  { id: "rlk1-exchange", label: "Exchange RLK round-1 share", kind: "network" },
  { id: "rlk1-aggregate", label: "Aggregate RLK round-1", kind: "wasm" },
  { id: "rlk2", label: "Send RLK round-2 share", kind: "network" },
  { id: "gks", label: "Send Galois key shares", kind: "network" },
  { id: "encrypt", label: "Preprocess and encrypt image", kind: "wasm" },
  { id: "image", label: "Submit encrypted image", kind: "network" },
  { id: "wait", label: "Awaiting authenticated result", kind: "sse" },
  { id: "partial", label: "Compute partial decryption", kind: "wasm" },
  { id: "redirect", label: "Submit partial decryption", kind: "network" },
];

async function runWasmStep<T>(
  tracker: ProgressTracker,
  id: string,
  op: string,
  fn: () => T,
  summarize?: (out: T) => string,
): Promise<T> {
  const step = tracker.start(id);
  try {
    // Yield once so the bar renders before the (blocking) WASM call. Without
    // this, large key-gen calls freeze the paint loop and the indeterminate
    // animation looks dead.
    await new Promise((r) => setTimeout(r, 0));
    const out = fn();
    if (summarize !== undefined) {
      step.summarize(op + " · " + summarize(out));
    } else {
      step.summarize(op);
    }
    step.success();
    return out;
  } catch (e) {
    step.error(e);
    throw e;
  }
}

async function uploadAndDownload(
  tracker: ProgressTracker,
  id: string,
  url: string,
  body: Uint8Array,
): Promise<Uint8Array> {
  const step = tracker.start(id);
  step.setSize(body.byteLength, "out=");
  try {
    const resp =
      body.byteLength > XHR_THRESHOLD
        ? await postBinaryXHR(url, body, step)
        : await postBinaryFetch(url, body, step);
    if (resp.status < 200 || resp.status >= 300) {
      throw new Error(
        "POST " + url + ": HTTP " + resp.status + " " + resp.responseText(),
      );
    }
    step.summarize(
      "in=" +
        fmtBytes(resp.body.byteLength) +
        " out=" +
        fmtBytes(body.byteLength),
    );
    step.success();
    return resp.body;
  } catch (e) {
    step.error(e);
    throw e;
  }
}

async function uploadAck(
  tracker: ProgressTracker,
  id: string,
  url: string,
  body: Uint8Array,
): Promise<void> {
  const step = tracker.start(id);
  step.setSize(body.byteLength, "out=");
  try {
    const resp =
      body.byteLength > XHR_THRESHOLD
        ? await postBinaryXHR(url, body, step)
        : await postBinaryFetch(url, body, step);
    if (resp.status < 200 || resp.status >= 300) {
      throw new Error(
        "POST " + url + ": HTTP " + resp.status + " " + resp.responseText(),
      );
    }
    step.summarize("out=" + fmtBytes(body.byteLength));
    step.success();
  } catch (e) {
    step.error(e);
    throw e;
  }
}

async function uploadJSON<T>(
  tracker: ProgressTracker,
  id: string,
  url: string,
  body: Uint8Array,
): Promise<T> {
  const step = tracker.start(id);
  step.setSize(body.byteLength, "out=");
  try {
    const resp = await postBinaryFetchJSON<T>(url, body, step);
    if (!resp.ok) {
      throw new Error("POST " + url + ": HTTP " + resp.status + " " + resp.raw);
    }
    if (resp.body === null) {
      throw new Error("POST " + url + ": non-JSON response: " + resp.raw);
    }
    step.summarize("out=" + fmtBytes(body.byteLength) + " · json");
    step.success();
    return resp.body;
  } catch (e) {
    step.error(e);
    throw e;
  }
}

function fmtBytes(n: number): string {
  if (n < 1024) {
    return n + " B";
  }
  if (n < 1024 * 1024) {
    return (n / 1024).toFixed(1) + " KB";
  }
  if (n < 1024 * 1024 * 1024) {
    return (n / (1024 * 1024)).toFixed(2) + " MB";
  }
  return (n / (1024 * 1024 * 1024)).toFixed(2) + " GB";
}

async function awaitResult(
  tracker: ProgressTracker,
  resultPromise: Promise<Uint8Array>,
): Promise<Uint8Array> {
  const step = tracker.start("wait");
  step.showElapsed();
  try {
    const out = await resultPromise;
    step.summarize("in=" + fmtBytes(out.byteLength));
    step.success();
    return out;
  } catch (e) {
    step.error(e);
    throw e;
  }
}

async function runProtocol(
  tracker: ProgressTracker,
  sid: string,
  handle: number,
  file: File,
): Promise<void> {
  const bridge = globalThis.ppiav;

  // Stage 2b — public key share.
  const pkShare = await runWasmStep(
    tracker,
    "pk-gen",
    "genPKShare",
    () => unwrapBytes(bridge.genPKShare(handle), "genPKShare"),
    (out) => "out=" + fmtBytes(out.byteLength),
  );
  const agentPK = await uploadAndDownload(
    tracker,
    "pk-exchange",
    "/sessions/" + sid + "/pk-share",
    pkShare,
  );
  await runWasmStep(
    tracker,
    "pk-aggregate",
    "aggregatePK",
    () => unwrapVoid(bridge.aggregatePK(handle, agentPK), "aggregatePK"),
  );

  // Stage 2c round 1.
  const rlk1 = await runWasmStep(
    tracker,
    "rlk1-gen",
    "genRLKShareRound1",
    () =>
      unwrapBytes(bridge.genRLKShareRound1(handle), "genRLKShareRound1"),
    (out) => "out=" + fmtBytes(out.byteLength),
  );
  const agentRLK1 = await uploadAndDownload(
    tracker,
    "rlk1-exchange",
    "/sessions/" + sid + "/rlk/round1",
    rlk1,
  );
  await runWasmStep(
    tracker,
    "rlk1-aggregate",
    "aggregateRLKRound1",
    () =>
      unwrapVoid(
        bridge.aggregateRLKRound1(handle, agentRLK1),
        "aggregateRLKRound1",
      ),
  );

  // Stage 2c round 2 (gen + send into one user-visible step).
  const rlk2 = unwrapBytes(
    bridge.genRLKShareRound2(handle),
    "genRLKShareRound2",
  );
  await uploadAck(
    tracker,
    "rlk2",
    "/sessions/" + sid + "/rlk/round2",
    rlk2,
  );

  // Stage 2d — Galois key shares (single blob).
  const gks = unwrapBytes(bridge.genGaloisShares(handle), "genGaloisShares");
  await uploadAck(tracker, "gks", "/sessions/" + sid + "/gks-shares", gks);

  // Stage 2e — open SSE before image POST so ct_M can't be lost to a race.
  const resultPromise = openResultStream(sid);

  // Stage 3 — preprocess + encrypt + POST. preprocess is async (decode +
  // canvas), so we drive this step manually instead of via runWasmStep.
  const encryptStep = tracker.start("encrypt");
  let ctReal: Uint8Array;
  try {
    const tensor = await preprocessImage(file);
    ctReal = unwrapBytes(bridge.encryptImage(handle, tensor), "encryptImage");
    encryptStep.summarize(
      "tensor=" +
        tensor.length +
        " float64 · ct=" +
        fmtBytes(ctReal.byteLength),
    );
    encryptStep.success();
  } catch (e) {
    encryptStep.error(e);
    throw e;
  }
  await uploadAck(tracker, "image", "/sessions/" + sid + "/image", ctReal);

  // Stage 4a — wait for AuthenticatedResult, then partial-decrypt.
  const authCt = await awaitResult(tracker, resultPromise);
  const partial = await runWasmStep(
    tracker,
    "partial",
    "partialDecrypt",
    () => unwrapBytes(bridge.partialDecrypt(handle, authCt), "partialDecrypt"),
    (out) => "out=" + fmtBytes(out.byteLength),
  );

  // Stage 4b — POST partial decryption, expect JSON 200 with redirect.
  const body = await uploadJSON<{ redirect?: unknown }>(
    tracker,
    "redirect",
    "/sessions/" + sid + "/partial-decryption",
    partial,
  );
  if (typeof body.redirect !== "string" || body.redirect === "") {
    throw new Error(
      "partial-decryption: response missing 'redirect' field: " +
        JSON.stringify(body),
    );
  }
  window.location.assign(body.redirect);
}

function mustElement<T extends HTMLElement>(
  id: string,
  ctor: new () => T,
): T {
  const el = document.getElementById(id);
  if (!(el instanceof ctor)) {
    throw new Error("missing or wrong-type element #" + id);
  }
  return el;
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

  const stepsHost = mustElement("steps", HTMLDivElement);
  const macroEl = mustElement("macro", HTMLParagraphElement);
  const devlogHost = mustElement("devlog", HTMLElement);
  const devlogToggle = mustElement("devlog-toggle", HTMLButtonElement);
  const tracker = new ProgressTracker({
    stepsHost,
    macroEl,
    devlogHost,
    devlogToggle,
    specs: STEP_SPECS,
  });

  const input = mustElement("image-input", HTMLInputElement);
  input.disabled = false;
  input.addEventListener("change", () => {
    const file = input.files?.[0];
    if (file === undefined) {
      return;
    }
    input.disabled = true;
    setStatus("Running verification protocol...");
    runProtocol(tracker, sid, handle, file)
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
