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

// classifyVerdict returns the CSS modifier + human label for a verdict
// string. The wire format mirrors protocol.Verdict.String(): "Accept",
// "Reject", "Unknown".
function classifyVerdict(v: string): {
  cls: "accept" | "reject" | "unknown";
  label: string;
} {
  switch (v.toLowerCase()) {
    case "accept":
      return { cls: "accept", label: "verified" };
    case "reject":
      return { cls: "reject", label: "rejected" };
    default:
      return { cls: "unknown", label: "unknown" };
  }
}

function render(): void {
  const status = document.getElementById("status");
  if (status === null) {
    return;
  }
  const v = window.verdict;
  if (v === undefined) {
    status.textContent = "no verdict injected by server";
    status.classList.add("error");
    return;
  }
  status.replaceChildren();

  const { cls, label } = classifyVerdict(v.verdict);

  const verdictRow = document.createElement("div");
  verdictRow.className = "verdict";
  const pill = document.createElement("span");
  pill.className = "pill " + cls;
  pill.textContent = label;
  const verdictLabel = document.createElement("span");
  verdictLabel.className = "verdict-label";
  verdictLabel.textContent =
    cls === "accept"
      ? "Access granted."
      : cls === "reject"
        ? "Access denied."
        : "Verdict unavailable.";
  verdictRow.appendChild(pill);
  verdictRow.appendChild(verdictLabel);

  const meta = document.createElement("dl");
  meta.className = "meta";
  const rows: [string, string][] = [
    ["sid", v.sid],
    ["verdict", v.verdict],
    ["received", receivedAt],
  ];
  for (const [k, val] of rows) {
    const dt = document.createElement("dt");
    dt.textContent = k;
    const dd = document.createElement("dd");
    dd.textContent = val;
    meta.appendChild(dt);
    meta.appendChild(dd);
  }

  status.appendChild(verdictRow);
  status.appendChild(meta);
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", render);
} else {
  render();
}
