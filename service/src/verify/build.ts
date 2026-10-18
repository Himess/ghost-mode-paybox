// Builds the self-contained disclosure verification page:
//   npx tsx src/verify/build.ts            (from ghost-mode/service)
// Bundles src/verify/client.ts (viem + poseidon-lite inlined) into one IIFE, inlines it into
// src/verify/page.html, pins it with a CSP script hash and writes src/verify/dist/verify.html.
// Optional: GHOST_KNOWN_POOLS="31337:0xPool,…" adds extra trusted pools (local test chains).
import { build } from "esbuild";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
export const VERIFY_DIST = resolve(here, "dist", "verify.html");
const BUNDLE_MARK = "/*__GHOST_VERIFY_BUNDLE__*/";
const HASH_MARK = "'__GHOST_VERIFY_SCRIPT_HASH__'";

export async function buildVerifyPage(opts: { extraPools?: string; outFile?: string } = {}): Promise<{ file: string; bytes: number }> {
  const extraPools = opts.extraPools ?? process.env.GHOST_KNOWN_POOLS ?? "";
  if (extraPools && !/^(\d+:0x[0-9a-fA-F]{40})(,\d+:0x[0-9a-fA-F]{40})*$/.test(extraPools))
    throw new Error('GHOST_KNOWN_POOLS must look like "31337:0xPoolAddress,8453:0xOther".');
  const result = await build({
    entryPoints: [resolve(here, "client.ts")],
    bundle: true,
    format: "iife",
    platform: "browser",
    target: ["es2022"],
    minify: true,
    write: false,
    legalComments: "none",
    charset: "utf8",
    define: { __GHOST_EXTRA_POOLS__: JSON.stringify(extraPools) },
    logLevel: "warning",
  });
  let js = result.outputFiles[0]!.text.trim();
  // Keep the inline script inert for the HTML parser.
  js = js.replace(/<\/(script)/gi, "<\\/$1");
  if (/<!--|<script/i.test(js)) throw new Error("Bundle contains '<!--' or '<script', which cannot be inlined safely.");
  if (/\bimport\(/.test(js)) throw new Error("Bundle still contains a dynamic import(); the page must be self-contained.");

  const template = readFileSync(resolve(here, "page.html"), "utf8");
  if (!template.includes(BUNDLE_MARK) || !template.includes(HASH_MARK)) throw new Error("page.html is missing the bundle or CSP placeholder.");
  const hash = createHash("sha256").update(js, "utf8").digest("base64");
  const html = template.split(HASH_MARK).join(`'sha256-${hash}'`).split(BUNDLE_MARK).join(js);

  // Self-containment guard: no external scripts, styles, images or fonts.
  if (/<(script|link|img|iframe)[^>]+(src|href)=/i.test(html)) throw new Error("Page references an external resource.");

  const file = opts.outFile ?? VERIFY_DIST;
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, html, "utf8");
  return { file, bytes: Buffer.byteLength(html) };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  buildVerifyPage().then(
    ({ file, bytes }) => console.log(`verify page written: ${file} (${(bytes / 1024).toFixed(1)} KiB)`),
    (e) => {
      console.error(e instanceof Error ? e.message : e);
      process.exit(1);
    },
  );
}
