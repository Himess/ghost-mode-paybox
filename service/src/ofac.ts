// OFAC SDN pre-screening. The list is vendored in data/ofac-eth.txt (first line: "# ... Source: <url> (fetched <iso date>)")
// so screening never depends on a network call. Refresh it by re-downloading the source URL.
// Standalone on purpose (no config import): config.ts merges these addresses into the ASP denylist.
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const LIST_FILE = resolve(dirname(fileURLToPath(import.meta.url)), "../data/ofac-eth.txt");

let cache: { addresses: Set<string>; source: string; fetchedAt: string } | undefined;

function load() {
  if (cache) return cache;
  const addresses = new Set<string>();
  let source = "unavailable";
  let fetchedAt = "";
  if (existsSync(LIST_FILE)) {
    for (const raw of readFileSync(LIST_FILE, "utf8").split(/\r?\n/)) {
      const line = raw.trim();
      if (line.startsWith("#")) {
        const m = /Source:\s*(\S+)\s*\(fetched\s+([^)]+)\)/.exec(line);
        if (m) { source = m[1]!; fetchedAt = m[2]!.trim(); }
        continue;
      }
      if (/^0x[0-9a-fA-F]{40}$/.test(line)) addresses.add(line.toLowerCase());
    }
  } else {
    console.error("[ofac] data/ofac-eth.txt missing: OFAC pre-screening disabled");
  }
  cache = { addresses, source, fetchedAt };
  return cache;
}

/** Lower-cased sanctioned addresses (for merging into the ASP denylist). */
export function sanctionedAddresses(): string[] {
  return [...load().addresses];
}

export function isSanctioned(address: string): boolean {
  return load().addresses.has(String(address).trim().toLowerCase());
}

export function ofacListInfo(): { count: number; source: string; fetchedAt: string } {
  const { addresses, source, fetchedAt } = load();
  return { count: addresses.size, source, fetchedAt };
}
