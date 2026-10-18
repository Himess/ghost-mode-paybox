// Extra routes owned separately from server.ts: single-signature shield (GhostPool v2) and the
// public disclosure verification page. Return true when handled.
import type { IncomingMessage, ServerResponse } from "node:http";
import { backupKey, recoverKeys } from "./keys.js";
import { getShieldJob, shieldInfo, shieldPrepare, shieldSubmit } from "./shield.js";

const json = (res: ServerResponse, status: number, body: unknown) => {
  res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" });
  res.end(JSON.stringify(body, (_k, v) => (typeof v === "bigint" ? v.toString() : v)));
};

async function readBody(req: IncomingMessage): Promise<any> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > 256 * 1024) throw new Error("Request body too large.");
    chunks.push(chunk as Buffer);
  }
  return chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : {};
}

export async function extraRoute(req: IncomingMessage, res: ServerResponse, url: URL): Promise<boolean> {
  if (req.method === "GET" && (url.pathname === "/verify" || url.pathname === "/verify/")) {
    try {
      const page: any = await import("./verify/index" + ".js");
      res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "referrer-policy": "no-referrer" });
      res.end(page.verifyPageHtml());
    } catch {
      res.writeHead(503, { "content-type": "text/plain" });
      res.end("Verification page not built yet.");
    }
    return true;
  }
  if (req.method === "POST" && url.pathname === "/v1/keys/backup") {
    json(res, 200, await backupKey(await readBody(req)));
    return true;
  }
  if (req.method === "POST" && url.pathname === "/v1/keys/recover") {
    json(res, 200, await recoverKeys(await readBody(req)));
    return true;
  }
  if (req.method === "GET" && url.pathname === "/v1/shield/info") {
    json(res, 200, await shieldInfo());
    return true;
  }
  if (req.method === "POST" && url.pathname === "/v1/shield/prepare") {
    json(res, 200, await shieldPrepare(await readBody(req)));
    return true;
  }
  if (req.method === "POST" && url.pathname === "/v1/shield/submit") {
    json(res, 200, await shieldSubmit(await readBody(req)));
    return true;
  }
  const m = /^\/v1\/shield\/jobs\/(sjob_[0-9a-f]{24})$/.exec(url.pathname);
  if (req.method === "GET" && m) {
    const job = getShieldJob(m[1]!);
    json(res, job ? 200 : 404, job ?? { error: "unknown shield job" });
    return true;
  }
  return false;
}
