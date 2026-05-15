// RClient SPA entry point. RService's `GET /protected` handler injects a
// `<script>window.verdict = {sid, verdict}</script>` block into the served
// HTML before the </body> tag. This module reads window.verdict and renders
// the result into the page.
//
// Receipt timestamp is captured on script load (best-effort proxy for "when
// the user saw the verdict").

// Force this file to be a module so the `declare global` block below is
// allowed (a top-level `declare global` requires at least one
// import/export in the file).
export {};

interface VerdictInjection {
  sid: string;
  verdict: string;
}

declare global {
  interface Window {
    verdict?: VerdictInjection;
  }
}

const receivedAt = new Date().toISOString();

function render(): void {
  const status = document.getElementById("status");
  if (!status) {
    return;
  }
  const v = window.verdict;
  if (!v) {
    status.textContent = "no verdict injected by server";
    return;
  }
  // Use textContent for each line to avoid HTML injection from sid/verdict.
  status.textContent = "";
  const sidLine = document.createElement("p");
  sidLine.textContent = "sid: " + v.sid;
  const verdictLine = document.createElement("p");
  verdictLine.textContent = "verdict: " + v.verdict;
  const tsLine = document.createElement("p");
  tsLine.textContent = "received: " + receivedAt;
  status.appendChild(sidLine);
  status.appendChild(verdictLine);
  status.appendChild(tsLine);
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", render);
} else {
  render();
}
