// Server-side access to the built disclosure verification page (src/verify/dist/verify.html).
// Build it first with: npx tsx src/verify/build.ts
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { encodePackageParam } from "./core.js";

export const VERIFY_PAGE_FILE = fileURLToPath(new URL("./dist/verify.html", import.meta.url));

let cached: string | undefined;

/** The self-contained verification page HTML (read once, then cached). */
export function verifyPageHtml(): string {
  if (cached !== undefined) return cached;
  if (!existsSync(VERIFY_PAGE_FILE))
    throw new Error(`Ghost Mode verify page is not built (${VERIFY_PAGE_FILE} is missing). Run "npx tsx src/verify/build.ts" in ghost-mode/service.`);
  cached = readFileSync(VERIFY_PAGE_FILE, "utf8");
  return cached;
}

/**
 * The page's own Content-Security-Policy (from its <meta> tag, script pinned by sha256). If the
 * server sends a CSP header for this route, send exactly this value, or the inline script is blocked.
 */
export function verifyPageCsp(): string {
  const m = /<meta http-equiv="Content-Security-Policy" content="([^"]+)">/.exec(verifyPageHtml());
  if (!m) throw new Error("Built verify page has no CSP meta tag; rebuild it.");
  return m[1]!;
}

/** Builds a shareable link: `${pageUrl}#pkg=<base64url(JSON)>` (optionally `&rpc=<url>` for local tests). */
export function verifyLink(pageUrl: string, pkg: unknown, rpc?: string): string {
  const base = pageUrl.split("#")[0];
  return `${base}#pkg=${encodePackageParam(pkg)}${rpc ? `&rpc=${encodeURIComponent(rpc)}` : ""}`;
}

export { encodePackageParam } from "./core.js";
export type { ReceiptPackage, ReportPackage, ReportNote, DisclosurePackage } from "./core.js";
