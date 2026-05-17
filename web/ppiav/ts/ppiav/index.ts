// Type definitions and TS wrappers for globalThis.ppiav.
//
// The Go WASM bridge in web/ppiav/bridge/ppiav/ppiav.go registers a
// handle-based namespace on globalThis.ppiav. Every Go function returns a
// raw value (Uint8Array, {handle}, null) on success or {error: string} on
// failure — matching the convention used by globalThis.lattigo.
//
// This module exposes a higher-level Client class that hides the integer
// handle and converts {error} results into thrown JS Errors, so callers
// can write straight-line async/await code without manually checking each
// bridge response. The plan's public surface (newClient + Client interface)
// lives at the bottom of this file.

import type { ErrorResult, HandleResult } from "../lattigo/types.js";
import { isError } from "../lattigo/types.js";

// --- Raw Go bridge surface (globalThis.ppiav) ---

/**
 * Typed view of `globalThis.ppiav`. Every method either returns its happy-
 * path value or an `{error: string}` object — never throws. The TS Client
 * wrapper below converts those into Errors.
 */
export interface PpiavBridge {
  /** Readiness flag set true once RegisterJS finishes. */
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
  var ppiav: PpiavBridge;
}

function getBridge(): PpiavBridge {
  if (typeof globalThis.ppiav === "undefined" || !globalThis.ppiav.__ready) {
    throw new Error(
      "ppiav WASM bridge not loaded. Load ppiav.wasm and wait for __ready.",
    );
  }
  return globalThis.ppiav;
}

function unwrapBytes(result: Uint8Array | ErrorResult, op: string): Uint8Array {
  if (isError(result)) {
    throw new Error(`ppiav.${op}: ${result.error}`);
  }
  return result;
}

function unwrapVoid(result: null | ErrorResult, op: string): void {
  if (result !== null && isError(result)) {
    throw new Error(`ppiav.${op}: ${result.error}`);
  }
}

// --- High-level Client wrapper ---

/**
 * High-level wrapper around a Go-side *vclient.Client. The Go bridge
 * returns an integer handle from newClient; this class stores it and
 * passes it back on every subsequent call, exposing the protocol-level
 * verbs from DESIGN.md §`internal/vclient` directly.
 *
 * Each method maps 1:1 to a Go bridge function and throws on
 * `{error: msg}` responses. Call .close() when finished to release the
 * Go-side handle; otherwise the FinalizationRegistry below cleans up
 * when this object is GCed.
 */
export class Client {
  private _handle: number;

  constructor(handle: number) {
    this._handle = handle;
    clientRegistry.register(this, handle, this);
  }

  get handle(): number {
    return this._handle;
  }

  /** Stage 2b: produce VClientPKShare bytes. */
  genPKShare(): Uint8Array {
    return unwrapBytes(getBridge().genPKShare(this._handle), "genPKShare");
  }

  /** Stage 2b: fold VAgentPKShare bytes into the client's pk aggregate. */
  aggregatePK(agentShareBytes: Uint8Array): void {
    unwrapVoid(
      getBridge().aggregatePK(this._handle, agentShareBytes),
      "aggregatePK",
    );
  }

  /** Stage 2c round 1: produce VClientRLKRound1 bytes. */
  genRLKShareRound1(): Uint8Array {
    return unwrapBytes(
      getBridge().genRLKShareRound1(this._handle),
      "genRLKShareRound1",
    );
  }

  /** Stage 2c round 1: fold VAgentRLKRound1 bytes. */
  aggregateRLKRound1(agentShareBytes: Uint8Array): void {
    unwrapVoid(
      getBridge().aggregateRLKRound1(this._handle, agentShareBytes),
      "aggregateRLKRound1",
    );
  }

  /** Stage 2c round 2: produce VClientRLKRound2 bytes. */
  genRLKShareRound2(): Uint8Array {
    return unwrapBytes(
      getBridge().genRLKShareRound2(this._handle),
      "genRLKShareRound2",
    );
  }

  /** Stage 2d: produce VClientGaloisKeyShare bytes (one blob, all rotations). */
  genGaloisShares(): Uint8Array {
    return unwrapBytes(
      getBridge().genGaloisShares(this._handle),
      "genGaloisShares",
    );
  }

  /**
   * Stage 3: encrypt the preprocessed image tensor. `tensor` must be the
   * length-12288 Float64Array produced by web/vclient's preprocess.ts.
   * Returns the raw rlwe.Ciphertext MarshalBinary blob (EncryptedImage
   * has no codec — the wire payload is the ciphertext itself).
   */
  encryptImage(tensor: Float64Array): Uint8Array {
    return unwrapBytes(
      getBridge().encryptImage(this._handle, tensor),
      "encryptImage",
    );
  }

  /**
   * Stage 4a: produce PartialDecryption bytes for the SSE-delivered
   * authenticated ciphertext (raw rlwe.Ciphertext.MarshalBinary bytes,
   * matching the VAgent SSE handler's wire shape).
   */
  partialDecrypt(authenticatedCtBytes: Uint8Array): Uint8Array {
    return unwrapBytes(
      getBridge().partialDecrypt(this._handle, authenticatedCtBytes),
      "partialDecrypt",
    );
  }

  /** Free the Go-side handle. Idempotent. */
  close(): void {
    if (this._handle !== 0) {
      clientRegistry.unregister(this);
      getBridge().deleteClient(this._handle);
      this._handle = 0;
    }
  }
}

const clientRegistry = new FinalizationRegistry((handleId: number) => {
  // Safe to access ppiav directly here — FinalizationRegistry only fires
  // after the bridge is loaded (Client construction requires it).
  if (typeof globalThis.ppiav !== "undefined") {
    globalThis.ppiav.deleteClient(handleId);
  }
});

/**
 * Construct a new vclient.Client on the Go side and return a TS wrapper.
 *
 * @param paramsJSON - JSON bytes from `GET /sessions/:sid/params` (matches
 *   the `protocol.Manifest` wire shape published by VService).
 * @param sid - Session ID assigned by VService and embedded in the
 *   `/verify?sid=` URL.
 */
export function newClient(paramsJSON: string, sid: string): Client {
  const result = getBridge().newClient(paramsJSON, sid);
  if (isError(result)) {
    throw new Error(`ppiav.newClient: ${result.error}`);
  }
  return new Client(result.handle);
}
