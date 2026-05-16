// Network helpers with progress reporting.
//
// - postBinaryXHR / getBinaryXHR: XMLHttpRequest with upload.onprogress and
//   onprogress. Used for large POSTs (>1 MB) so the user can watch bytes
//   leave the browser. Fetch's request body is not observable in any
//   stable browser API as of 2026, so XHR is the only path.
// - postBinaryFetch: small POSTs with a determinate bar that fills on
//   resolve. Body total is known, percent fill is binary (0 -> 100) but the
//   byte readout is honest.
// - readStreamedResponse: drives a download bar via Response.body.getReader()
//   when we want chunk-level visibility (large agent responses).

import type { StepHandle } from "./progress.js";

export interface BinaryResponse {
  status: number;
  body: Uint8Array;
  responseText: () => string;
}

// XHR upload + raw arraybuffer response. The upload bar is driven by
// upload.onprogress; once the request has flushed the body, the download
// bar reuses the same row to show response bytes.
export function postBinaryXHR(
  url: string,
  body: Uint8Array,
  step: StepHandle,
): Promise<BinaryResponse> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", url, true);
    xhr.setRequestHeader("Content-Type", "application/octet-stream");
    xhr.responseType = "arraybuffer";
    const totalUp = body.byteLength;
    step.setDeterminate();
    step.update(0, totalUp);
    xhr.upload.onprogress = (e: ProgressEvent): void => {
      const total = e.lengthComputable && e.total > 0 ? e.total : totalUp;
      step.update(e.loaded, total);
    };
    xhr.upload.onload = (): void => {
      step.update(totalUp, totalUp);
    };
    xhr.onprogress = (e: ProgressEvent): void => {
      // Reset readout to download side as soon as the first response byte
      // lands. Without a Content-Length, total is 0 here.
      if (e.lengthComputable && e.total > 0) {
        step.update(e.loaded, e.total);
      } else {
        step.update(e.loaded, 0);
      }
    };
    xhr.onerror = (): void => {
      reject(new Error("POST " + url + ": network error"));
    };
    xhr.ontimeout = (): void => {
      reject(new Error("POST " + url + ": timeout"));
    };
    xhr.onload = (): void => {
      const buf = xhr.response as ArrayBuffer | null;
      const bytes = buf !== null ? new Uint8Array(buf) : new Uint8Array(0);
      resolve({
        status: xhr.status,
        body: bytes,
        responseText: () => {
          try {
            return new TextDecoder().decode(bytes);
          } catch {
            return "";
          }
        },
      });
    };
    xhr.send(new Uint8Array(body));
  });
}

// fetch-based POST with a determinate bar that fills on resolve. Used for
// payloads <1 MB where streaming upload progress would be noise.
export async function postBinaryFetch(
  url: string,
  body: Uint8Array,
  step: StepHandle,
): Promise<BinaryResponse> {
  const total = body.byteLength;
  step.setDeterminate();
  step.update(0, total);
  const resp = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/octet-stream" },
    body: new Uint8Array(body),
  });
  step.update(total, total);
  const buf = new Uint8Array(await resp.arrayBuffer());
  return {
    status: resp.status,
    body: buf,
    responseText: () => {
      try {
        return new TextDecoder().decode(buf);
      } catch {
        return "";
      }
    },
  };
}

// JSON-returning variant of postBinaryFetch.
export async function postBinaryFetchJSON<T>(
  url: string,
  body: Uint8Array,
  step: StepHandle,
): Promise<{ status: number; ok: boolean; body: T | null; raw: string }> {
  const total = body.byteLength;
  step.setDeterminate();
  step.update(0, total);
  const resp = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/octet-stream" },
    body: new Uint8Array(body),
  });
  step.update(total, total);
  const raw = await resp.text();
  let parsed: T | null = null;
  try {
    parsed = JSON.parse(raw) as T;
  } catch {
    parsed = null;
  }
  return { status: resp.status, ok: resp.ok, body: parsed, raw };
}
