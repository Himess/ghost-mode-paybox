// Browser entry of the Ghost Mode disclosure verification page. Bundled into a single inline
// IIFE by src/verify/build.ts. Reads the package from #pkg=<base64url(JSON)>, a pasted JSON
// or a dropped .json file, and verifies it against Base via public JSON-RPC only.
import {
  OFFICIAL_POOLS, PackageError, decodePackageParam, parsePackage, verifyPackage, type Check, type Verification,
} from "./core.js";
import { JsonRpcReader, defaultRpcUrls } from "./rpc.js";

// Extra official pools injected at build time (GHOST_KNOWN_POOLS="chainId:0xpool,…"), e.g. local anvil.
declare const __GHOST_EXTRA_POOLS__: string;

const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;

function el(tag: string, cls?: string, text?: string): HTMLElement {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

function extraPools(): Record<number, string[]> {
  const out: Record<number, string[]> = {};
  const raw = typeof __GHOST_EXTRA_POOLS__ === "string" ? __GHOST_EXTRA_POOLS__ : "";
  for (const item of raw.split(",").map((s) => s.trim()).filter(Boolean)) {
    const [chain, addr] = item.split(":");
    if (!chain || !addr) continue;
    const id = Number(chain);
    out[id] = [...(OFFICIAL_POOLS[id] ?? []), ...(out[id] ?? []), addr];
  }
  return out;
}

function readFragment(): Record<string, string> {
  const out: Record<string, string> = {};
  const hash = location.hash.replace(/^#/, "");
  for (const part of hash.split("&")) {
    const eq = part.indexOf("=");
    if (eq > 0) out[part.slice(0, eq)] = part.slice(eq + 1);
  }
  return out;
}

const ICON: Record<Check["status"], string> = { pass: "✓", fail: "✗", error: "✗", info: "i" };

function renderRow(c: Check): HTMLElement {
  const li = el("li");
  const det = el("details", `row ${c.status}`) as HTMLDetailsElement;
  if (c.status === "fail" || c.status === "error") det.open = true;
  const sum = el("summary");
  const icon = el("span", "icon", ICON[c.status]);
  icon.setAttribute("aria-label", c.status === "pass" ? "verified" : c.status === "info" ? "information" : c.status === "error" ? "could not verify" : "failed");
  const body = el("div");
  body.append(el("div", "row-title", c.title), el("div", "row-summary", c.summary));
  sum.append(icon, body);
  det.append(sum);
  if (c.details.length) {
    const dl = el("dl");
    for (const d of c.details) dl.append(el("dt", undefined, d.label), el("dd", d.mono ? "mono" : undefined, d.value));
    det.append(dl);
  }
  li.append(det);
  return li;
}

function showVerdict(state: "busy" | "pass" | "fail" | "error", text: string, meta = "", scope = "") {
  const v = $("verdict");
  v.className = `card verdict ${state}`;
  const icon = $("verdict-icon");
  icon.textContent = "";
  if (state === "busy") icon.append(el("span", "spin", "◌"));
  else icon.textContent = state === "pass" ? "✓" : "✗";
  $("verdict-text").textContent = text;
  $("verdict-meta").textContent = meta;
  $("verdict-scope").textContent = scope;
}

function render(result: Verification) {
  const rows = $("rows");
  rows.textContent = "";
  for (const c of result.checks) rows.append(renderRow(c));
  const { pass, fail, error } = result.counts;
  const total = pass + fail + error;
  const state = result.ok ? "pass" : fail ? "fail" : "error";
  const meta = `${pass} of ${total} checks passed${fail ? `, ${fail} failed` : ""}${error ? `, ${error} could not be checked` : ""} · read from ${result.rpc} at ${new Date().toISOString().slice(0, 19).replace("T", " ")} UTC`;
  showVerdict(state, result.headline, meta, result.scope ?? "");
}

let running = 0;

async function run(text: string, rpcOverride?: string) {
  const errBox = $("input-error");
  errBox.textContent = "";
  let pkg;
  try {
    pkg = parsePackage(JSON.parse(text));
  } catch (e) {
    errBox.textContent = e instanceof PackageError ? e.message : e instanceof SyntaxError ? `Not valid JSON: ${e.message}` : String(e);
    $("input").classList.remove("hidden");
    $("result").classList.add("hidden");
    return;
  }
  const ticket = ++running;
  $("input").classList.add("hidden");
  $("result").classList.remove("hidden");
  $("rows").textContent = "";
  $("raw").textContent = JSON.stringify(pkg, null, 2);

  const warn = $("rpc-warning");
  warn.classList.add("hidden");
  warn.textContent = "";
  let urls = defaultRpcUrls(pkg.chainId);
  if (rpcOverride) {
    urls = [rpcOverride];
    warn.append(
      el("strong", undefined, "Custom RPC endpoint. "),
      document.createTextNode(`This link asks the page to read chain data from ${rpcOverride}. A dishonest RPC node can fake chain data; for an independent check remove "rpc=…" from the link so the public Base RPC is used.`),
    );
    warn.classList.remove("hidden");
  }
  if (!urls.length) {
    showVerdict("error", `No public RPC is known for chain ${pkg.chainId}. Add #rpc=<url> to the link to choose one.`);
    return;
  }
  showVerdict("busy", "Verifying against the chain…", `Reading ${urls[0]}`);
  const reader = new JsonRpcReader(urls, {
    onRequest: (n, url) => {
      if (ticket === running) $("verdict-meta").textContent = `Reading ${url} · ${n} request${n === 1 ? "" : "s"}`;
    },
  });
  try {
    const result = await verifyPackage(pkg, reader, { officialPools: extraPools() });
    if (ticket === running) render(result);
  } catch (e) {
    if (ticket === running) showVerdict("error", `Verification stopped unexpectedly: ${e instanceof Error ? e.message : String(e)}`);
  }
}

function startFromFragment(): boolean {
  const frag = readFragment();
  if (!frag.pkg) return false;
  let text: string;
  try {
    text = JSON.stringify(decodePackageParam(frag.pkg));
  } catch (e) {
    $("input-error").textContent = e instanceof Error ? e.message : String(e);
    return false;
  }
  void run(text, frag.rpc ? decodeURIComponent(frag.rpc) : undefined);
  return true;
}

function init() {
  const textarea = $<HTMLTextAreaElement>("pkg-text");
  const rpcFromHash = () => {
    const r = readFragment().rpc;
    return r ? decodeURIComponent(r) : undefined;
  };
  $("verify-btn").addEventListener("click", () => void run(textarea.value, rpcFromHash()));
  const loadFile = (file: File | undefined) => {
    if (!file) return;
    file.text().then((t) => {
      textarea.value = t;
      void run(t, rpcFromHash());
    }, (e) => ($("input-error").textContent = `Could not read file: ${String(e)}`));
  };
  $<HTMLInputElement>("pkg-file").addEventListener("change", (e) => loadFile((e.target as HTMLInputElement).files?.[0]));
  const drop = $("drop");
  const stop = (e: Event) => {
    e.preventDefault();
    e.stopPropagation();
  };
  for (const ev of ["dragenter", "dragover"]) document.addEventListener(ev, (e) => (stop(e), drop.classList.add("over")));
  for (const ev of ["dragleave", "drop"]) document.addEventListener(ev, (e) => (stop(e), drop.classList.remove("over")));
  document.addEventListener("drop", (e) => loadFile((e as DragEvent).dataTransfer?.files?.[0]));
  $("again").addEventListener("click", () => {
    running++;
    if (location.hash.includes("pkg=")) history.replaceState(null, "", location.pathname + location.search + (rpcFromHash() ? `#rpc=${encodeURIComponent(rpcFromHash()!)}` : ""));
    $("result").classList.add("hidden");
    $("input").classList.remove("hidden");
    textarea.focus();
  });
  window.addEventListener("hashchange", () => void startFromFragment());
  startFromFragment();
}

if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
else init();
