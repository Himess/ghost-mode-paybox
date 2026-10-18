// noir_wasm's Node file manager breaks on Windows drive paths. Compile from an
// in-memory POSIX file system instead: /transact (the circuit) and /lib (vendored deps).
import { readdirSync, readFileSync, statSync } from "node:fs";
import { createRequire } from "node:module";
import { join, relative } from "node:path";

const require = createRequire(import.meta.url);

function collect(dir: string, mountAt: string, files: Map<string, Uint8Array>) {
  for (const entry of readdirSync(dir)) {
    if (entry === "target" || entry === ".git") continue;
    const full = join(dir, entry);
    const rel = relative(dir, full).split("\\").join("/");
    if (statSync(full).isDirectory()) collect(full, `${mountAt}/${rel}`, files);
    else files.set(`${mountAt}/${rel}`, new Uint8Array(readFileSync(full)));
  }
}

export async function compileNoir(circuitsDir: string, project: string) {
  const files = new Map<string, Uint8Array>();
  collect(join(circuitsDir, project), `/${project}`, files);
  collect(join(circuitsDir, "lib"), "/lib", files);

  const isDir = (p: string) => [...files.keys()].some((k) => k.startsWith(p.endsWith("/") ? p : `${p}/`));
  const memFs = {
    existsSync: (p: string) => files.has(p) || isDir(p),
    mkdir: async () => {},
    writeFile: async (p: string, data: Uint8Array) => void files.set(p, data),
    readFile: async (p: string, encoding?: "utf-8") => {
      const data = files.get(p);
      if (!data) throw new Error(`ENOENT: ${p}`);
      return encoding ? new TextDecoder().decode(data) : data;
    },
    rename: async (a: string, b: string) => {
      const data = files.get(a);
      if (data) { files.delete(a); files.set(b, data); }
    },
    readdir: async (p: string, opts?: { recursive: boolean }) => {
      const prefix = p.endsWith("/") ? p : `${p}/`;
      const out = new Set<string>();
      for (const key of files.keys()) {
        if (!key.startsWith(prefix)) continue;
        // Recursive mode mirrors noir_wasm's readdirRecursive: absolute file paths only.
        if (opts?.recursive) out.add(key);
        else out.add(key.slice(prefix.length).split("/")[0]!);
      }
      return [...out];
    },
  };

  // Force POSIX path semantics while noir_wasm runs, then restore. Node's own
  // module loader shares this object, so load noir_wasm before patching.
  const noir = require("@noir-lang/noir_wasm");
  const nodePath = require("path");
  const saved = { ...nodePath };
  Object.assign(nodePath, nodePath.posix);
  try {
    const probe = noir.createFileManager("/");
    const FileManager = Object.getPrototypeOf(probe).constructor;
    const fm = new FileManager(memFs, "/");
    return await noir.compile_program(fm, `/${project}`, () => {}, () => {});
  } finally {
    Object.assign(nodePath, saved);
  }
}
