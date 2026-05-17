// ProgressTracker — visible per-step bars + dev log.
//
// Steps are declared up front so the macro indicator can show "N / total".
// Each step exposes start/finish (success or error) and, while active, a
// stream of either determinate updates (loaded/total) or indeterminate
// elapsed ticks. Every event also appends to the dev log panel.

export type StepKind = "wasm" | "network" | "compute";

export interface StepSpec {
  id: string;
  label: string;
  kind: StepKind;
}

interface StepRow {
  spec: StepSpec;
  root: HTMLDivElement;
  labelEl: HTMLSpanElement;
  sizeEl: HTMLSpanElement;
  bar: HTMLDivElement;
  fill: HTMLDivElement;
  startedAt: number | null;
  finishedAt: number | null;
  intervalId: number | null;
}

function fmtBytes(n: number): string {
  if (!Number.isFinite(n) || n < 0) {
    return "—";
  }
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

function fmtClock(ms: number): string {
  const d = new Date(ms);
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  const mmm = String(d.getMilliseconds()).padStart(3, "0");
  return hh + ":" + mm + ":" + ss + "." + mmm;
}

export class ProgressTracker {
  private readonly stepsHost: HTMLElement;
  private readonly macroEl: HTMLElement;
  private readonly devlogHost: HTMLElement;
  private readonly devlogToggle: HTMLButtonElement;
  private readonly specs: StepSpec[];
  private readonly rows: Map<string, StepRow> = new Map();
  private current = 0;
  private devlogOpen = false;

  constructor(opts: {
    stepsHost: HTMLElement;
    macroEl: HTMLElement;
    devlogHost: HTMLElement;
    devlogToggle: HTMLButtonElement;
    specs: StepSpec[];
  }) {
    this.stepsHost = opts.stepsHost;
    this.macroEl = opts.macroEl;
    this.devlogHost = opts.devlogHost;
    this.devlogToggle = opts.devlogToggle;
    this.specs = opts.specs;
    this.render();
    this.wireDevlog();
  }

  private render(): void {
    this.stepsHost.replaceChildren();
    for (const spec of this.specs) {
      const root = document.createElement("div");
      root.className = "step";
      root.dataset["id"] = spec.id;

      const label = document.createElement("div");
      label.className = "step-label";
      const labelEl = document.createElement("span");
      labelEl.textContent = spec.label;
      const sizeEl = document.createElement("span");
      sizeEl.className = "size";
      label.appendChild(labelEl);
      label.appendChild(sizeEl);

      const bar = document.createElement("div");
      bar.className = "bar";
      const fill = document.createElement("div");
      fill.className = "bar-fill";
      bar.appendChild(fill);

      root.appendChild(label);
      root.appendChild(bar);
      this.stepsHost.appendChild(root);

      this.rows.set(spec.id, {
        spec,
        root,
        labelEl,
        sizeEl,
        bar,
        fill,
        startedAt: null,
        finishedAt: null,
        intervalId: null,
      });
    }
    this.macroEl.hidden = false;
    this.macroEl.textContent = "шаг 0 / " + this.specs.length;
    this.devlogToggle.hidden = false;
  }

  private wireDevlog(): void {
    const persisted = (() => {
      try {
        return window.sessionStorage.getItem("ppiav.devlog") === "1";
      } catch {
        return false;
      }
    })();
    if (persisted) {
      this.openDevlog();
    }
    this.devlogToggle.addEventListener("click", () => {
      if (this.devlogOpen) {
        this.closeDevlog();
      } else {
        this.openDevlog();
      }
    });
  }

  private openDevlog(): void {
    this.devlogOpen = true;
    this.devlogHost.hidden = false;
    this.devlogToggle.textContent = "[ скрыть журнал ]";
    try {
      window.sessionStorage.setItem("ppiav.devlog", "1");
    } catch {
      // ignore
    }
  }

  private closeDevlog(): void {
    this.devlogOpen = false;
    this.devlogHost.hidden = true;
    this.devlogToggle.textContent = "[ журнал ]";
    try {
      window.sessionStorage.removeItem("ppiav.devlog");
    } catch {
      // ignore
    }
  }

  private logRow(opts: {
    msg: string;
    meta?: string;
    cls?: "start" | "ok" | "err";
  }): void {
    const row = document.createElement("div");
    row.className = "devlog-row " + (opts.cls ?? "ok");
    const ts = document.createElement("span");
    ts.className = "ts";
    ts.textContent = fmtClock(Date.now());
    const msg = document.createElement("span");
    msg.className = "msg";
    msg.textContent = opts.msg;
    const meta = document.createElement("span");
    meta.className = "meta";
    meta.textContent = opts.meta ?? "";
    row.appendChild(ts);
    row.appendChild(msg);
    row.appendChild(meta);
    this.devlogHost.appendChild(row);
    this.devlogHost.scrollTop = this.devlogHost.scrollHeight;
  }

  private updateMacro(): void {
    this.macroEl.textContent =
      "шаг " + this.current + " / " + this.specs.length;
  }

  // start a step. Returns a handle bound to that step.
  start(id: string): StepHandle {
    const row = this.rows.get(id);
    if (row === undefined) {
      throw new Error("progress: unknown step " + id);
    }
    this.current += 1;
    this.updateMacro();
    row.startedAt = performance.now();
    row.bar.classList.remove("done");
    row.bar.classList.add("indeterminate");
    this.logRow({
      msg: row.spec.label,
      meta: "начало (" + row.spec.kind + ")",
      cls: "start",
    });
    return new StepHandle(this, row);
  }

  // called by StepHandle.success — finalise visual + log a duration row.
  _finishOk(row: StepRow, summary: string): void {
    row.finishedAt = performance.now();
    row.bar.classList.remove("indeterminate");
    row.bar.classList.add("done");
    row.fill.style.width = "100%";
    if (row.intervalId !== null) {
      window.clearInterval(row.intervalId);
      row.intervalId = null;
    }
    const dur = Math.round(
      (row.finishedAt ?? 0) - (row.startedAt ?? row.finishedAt ?? 0),
    );
    this.logRow({
      msg: row.spec.label,
      meta: "готово · " + dur + " мс" + (summary ? " · " + summary : ""),
      cls: "ok",
    });
  }

  _finishErr(row: StepRow, err: unknown): void {
    row.finishedAt = performance.now();
    row.bar.classList.remove("indeterminate");
    if (row.intervalId !== null) {
      window.clearInterval(row.intervalId);
      row.intervalId = null;
    }
    const dur = Math.round(
      (row.finishedAt ?? 0) - (row.startedAt ?? row.finishedAt ?? 0),
    );
    const m = err instanceof Error ? err.message : String(err);
    this.logRow({
      msg: row.spec.label,
      meta: "ошибка · " + dur + " мс · " + m,
      cls: "err",
    });
  }
}

// StepHandle is the public surface a step's caller uses to drive its bar
// + dev log between start and finish.
export class StepHandle {
  private readonly tracker: ProgressTracker;
  private readonly row: StepRow;
  private summary = "";
  private settled = false;

  constructor(tracker: ProgressTracker, row: StepRow) {
    this.tracker = tracker;
    this.row = row;
  }

  // setSize attaches a known byte total to the row's label (e.g.
  // "Sending RLK round-1 (240.1 MB)").
  setSize(bytes: number, prefix?: string): void {
    const p = prefix ?? "";
    this.row.sizeEl.textContent = " " + p + fmtBytes(bytes);
  }

  // determinate mode: switch the bar away from the indeterminate animation.
  setDeterminate(): void {
    this.row.bar.classList.remove("indeterminate");
  }

  // update(loaded, total) drives a determinate fill. total may be 0 if
  // unknown (e.g. chunked download with no Content-Length) — caller should
  // either skip or use loaded only.
  update(loaded: number, total: number): void {
    this.row.bar.classList.remove("indeterminate");
    if (total > 0) {
      const pct = Math.max(0, Math.min(100, (loaded / total) * 100));
      this.row.fill.style.width = pct.toFixed(2) + "%";
    }
    this.row.sizeEl.textContent =
      " " + fmtBytes(loaded) + (total > 0 ? " / " + fmtBytes(total) : "");
  }

  // summarize stores text appended to the dev log on success (e.g. "out=83 KB"
  // for crypto ops, or "in=240 MB out=240 MB" for network steps).
  summarize(s: string): void {
    this.summary = s;
  }

  // tickElapsed: optional periodic dev-log tick. Currently unused but kept
  // so SSE wait can show seconds in the visible row.
  showElapsed(intervalMs = 250): void {
    if (this.row.intervalId !== null) {
      return;
    }
    const start = this.row.startedAt ?? performance.now();
    const tick = (): void => {
      const sec = Math.floor((performance.now() - start) / 1000);
      this.row.sizeEl.textContent = " " + sec + " с";
    };
    tick();
    this.row.intervalId = window.setInterval(tick, intervalMs);
  }

  success(): void {
    if (this.settled) {
      return;
    }
    this.settled = true;
    this.tracker._finishOk(this.row, this.summary);
  }

  error(e: unknown): void {
    if (this.settled) {
      return;
    }
    this.settled = true;
    this.tracker._finishErr(this.row, e);
  }
}
