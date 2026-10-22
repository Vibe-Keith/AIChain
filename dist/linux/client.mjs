// src/crypto.ts
import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";

// src/shared/canon.ts
var canon = (o) => JSON.stringify(o, (_k, v) => v && typeof v === "object" && !Array.isArray(v) ? Object.fromEntries(Object.entries(v).sort(([a], [b]) => a < b ? -1 : 1)) : v);

// src/crypto.ts
var sha256 = (...parts) => {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return h.digest("hex");
};
var PKCS8 = Buffer.from("302e020100300506032b657004220420", "hex");
var SPKI = Buffer.from("302a300506032b6570032100", "hex");
function walletFromSeed(seed) {
  const raw = createHash("sha256").update(seed).digest();
  const key = createPrivateKey({ key: Buffer.concat([PKCS8, raw]), format: "der", type: "pkcs8" });
  const pub = createPublicKey(key).export({ format: "der", type: "spki" });
  return { address: pub.subarray(-32).toString("hex"), key };
}
function makeTx(w2, body) {
  const id = sha256(canon(body));
  return { ...body, id, sig: sign(null, Buffer.from(id), w2.key).toString("hex") };
}

// src/client.ts
var args = process.argv.slice(2);
var flag = (k, d) => {
  const i = args.indexOf("--" + k);
  return i >= 0 ? args[i + 1] : d;
};
var node = flag("node", "http://localhost:3001");
var w = walletFromSeed(flag("seed", "devnet-faucet"));
var sleep = (ms) => new Promise((r) => setTimeout(r, ms));
var get = async (p) => (await fetch(node + p)).json();
var post = async (tx) => (await fetch(node + "/tx", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(tx) })).json();
var addr = (x) => /^[0-9a-f]{64}$/.test(x) ? x : walletFromSeed(x).address;
var job = (prompt, nonce) => makeTx(w, {
  type: "job",
  from: w.address,
  prompt,
  maxTokens: Number(flag("tokens", "64")),
  fee: Number(flag("fee", "2")),
  nonce
});
var [cmd, a1, a2] = args;
if (cmd === "ask") {
  const tx = job(a1 ?? "hello", (await get(`/account/${w.address}`)).pendingNonce);
  console.log("submitted", tx.id.slice(0, 12), await post(tx));
  for (; ; ) {
    const j = await get(`/job/${tx.id}`);
    if (j.status === "done") {
      console.log(`answered in block #${j.height}:
${j.output}`);
      break;
    }
    await sleep(1e3);
  }
} else if (cmd === "load") {
  const n = Number(a1 ?? 50), every = Number(flag("every", "1000"));
  let nonce = (await get(`/account/${w.address}`)).pendingNonce;
  for (let i = 0; i < n; i++) {
    const r = await post(job(`query ${i} ${Math.random().toString(36).slice(2)}`, nonce++));
    console.log(`job ${i}`, r.ok ? "ok" : r.error);
    await sleep(every);
  }
} else if (cmd === "send") {
  const nonce = (await get(`/account/${w.address}`)).pendingNonce;
  console.log(await post(makeTx(w, { type: "transfer", from: w.address, to: addr(a1), amount: Number(a2), fee: 1, nonce })));
} else if (cmd === "account") {
  const x = addr(a1 ?? w.address);
  console.log(x, await get(`/account/${x}`));
} else if (cmd === "status") {
  console.log(await get("/status"));
} else {
  console.log(`usage:
  client ask "<prompt>" [--tokens 64] [--fee 2]   submit query, wait for answer
  client load [n] [--every ms]                    generate demand (miners need jobs)
  client send <seed|addr> <amount>                transfer coin
  client account [seed|addr]                      balance + nonce
  client status
  flags: --node http://localhost:3001  --seed devnet-faucet`);
}
