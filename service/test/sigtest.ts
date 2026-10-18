import { hexToBytes, serializeCompactSignature, parseSignature, type Hex } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { signatureToCircuit } from "../../plugin/src/core/spend.js";
const acct = privateKeyToAccount(generatePrivateKey());
let ok = 0;
for (let i = 0; i < 20; i++) {
  const sig = await acct.signMessage({ message: `m${i}` }) as Hex;
  const p = parseSignature(sig);
  const compact = serializeCompactSignature({ r: p.r, yParityAndS: (() => { const s = BigInt(p.s) | (BigInt(p.yParity ?? 0) << 255n); return `0x${s.toString(16).padStart(64, "0")}` as Hex; })() });
  const a = signatureToCircuit(sig).join(","), b = signatureToCircuit(compact).join(",");
  if (a === b && hexToBytes(sig).length === 65 && hexToBytes(compact).length === 64) ok++;
}
console.log(ok === 20 ? "compact == full for 20 signatures" : `MISMATCH ${ok}/20`);
