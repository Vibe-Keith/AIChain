// src/pool.ts
import http from "node:http";
import { readFileSync, existsSync } from "node:fs";
import { join, basename, extname } from "node:path";
import { fileURLToPath } from "node:url";

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
function verifySig(address, msg, sig) {
  try {
    const pub = createPublicKey({ key: Buffer.concat([SPKI, Buffer.from(address, "hex")]), format: "der", type: "spki" });
    return verify(null, Buffer.from(msg), pub, Buffer.from(sig, "hex"));
  } catch {
    return false;
  }
}
function makeTx(w, body) {
  const id = sha256(canon(body));
  return { ...body, id, sig: sign(null, Buffer.from(id), w.key).toString("hex") };
}

// src/model.ts
import { createHash as createHash2 } from "node:crypto";
var D = 128;
var V = 256;
var LO = 32;
var HI = 126;
function xorshift(seed) {
  let s = seed >>> 0 || 1;
  return () => {
    s ^= s << 13;
    s >>>= 0;
    s ^= s >>> 17;
    s ^= s << 5;
    s >>>= 0;
    return s;
  };
}
var wr = xorshift(12648430);
var fill = (n) => {
  const a = new Int8Array(n);
  for (let i = 0; i < n; i++) a[i] = wr() % 16 - 8;
  return a;
};
var E = fill(V * D);
var Wh = fill(D * D);
var Wo = fill(D * V);
var MODEL_ID = sha256(new Uint8Array(E.buffer), new Uint8Array(Wh.buffer), new Uint8Array(Wo.buffer)).slice(0, 16);
function runJob(prompt, maxTokens, seedHex, target, shareTarget) {
  const seed = Buffer.from(seedHex, "hex");
  const h = new Int32Array(D), nx = new Int32Array(D), hb = new Uint8Array(D);
  for (let i = 0; i < D; i++) h[i] = seed[i % 32] - 128;
  let s = 0, win = -1;
  const shares = [];
  const step = (tok) => {
    const eo = tok * D;
    for (let i = 0; i < D; i++) {
      let acc = E[eo + i] * 64;
      const ro = i * D;
      for (let j = 0; j < D; j++) acc += Wh[ro + j] * h[j];
      acc >>= 6;
      nx[i] = acc > 127 ? 127 : acc < -127 ? -127 : acc;
    }
    h.set(nx);
    if (win < 0 || shareTarget !== void 0) {
      for (let i = 0; i < D; i++) hb[i] = h[i] & 255;
      const t = BigInt("0x" + createHash2("sha256").update(seed).update(String(s)).update(hb).digest("hex"));
      if (win < 0 && t < target) win = s;
      if (shareTarget !== void 0 && t < shareTarget) shares.push(s);
    }
    s++;
  };
  for (const b of Buffer.from(prompt, "utf8")) step(b);
  const rng = xorshift(seed.readUInt32LE(0));
  let out = "";
  for (let k = 0; k < maxTokens; k++) {
    let best = -Infinity, tok = LO;
    for (let v = LO; v <= HI; v++) {
      let l = rng() % 4096;
      for (let i = 0; i < D; i++) l += Wo[i * V + v] * h[i];
      if (l > best) {
        best = l;
        tok = v;
      }
    }
    out += String.fromCharCode(tok);
    step(tok);
  }
  return { output: out, win, steps: s, shares };
}

// src/chain.ts
var BLOCK_REWARD = 50;
var TWO256 = 1n << 256n;
var INITIAL_TARGET = TWO256 / 40000n;
var FAUCET = walletFromSeed("devnet-faucet");
var blockHash = (b) => {
  const { hash, txs, results, ...hdr } = b;
  return sha256(canon({ ...hdr, txRoot: sha256(canon(txs)), resRoot: sha256(canon(results)) }));
};
var jobSeed = (prev, miner, jobId, attempt) => sha256(`${prev}|${miner}|${jobId}|${attempt}`);

// src/pool.ts
var arg = (k, d) => {
  const i = process.argv.indexOf("--" + k);
  return i > 0 ? process.argv[i + 1] : d;
};
var port = Number(arg("port", "4000"));
var nodeUrl = arg("node", "http://localhost:3001");
var pool = walletFromSeed(arg("seed", "pool-1"));
var webDir = [arg("web", ""), fileURLToPath(new URL("./web/", import.meta.url)), "dist/web"].find((d) => d && existsSync(join(d, "index.html")));
var MIME = { ".html": "text/html", ".js": "text/javascript", ".wasm": "application/wasm", ".json": "application/json" };
var FEE_PCT = 2;
var SHARE_MULT = 64n;
var CHECK_RATE = 0.1;
var PPLNS_N = 2e3;
var PAYOUT_MIN = 10;
var CONFIRMS = 3;
var ATTEMPTS_PER_WORK = 8;
var current = null;
var templates = /* @__PURE__ */ new Map();
var ranges = /* @__PURE__ */ new Map();
var seen = /* @__PURE__ */ new Set();
var workers = /* @__PURE__ */ new Map();
var window = [];
var pending = [];
var found = [];
var log = (...a) => console.log("[pool]", ...a);
var w8 = (addr) => {
  let x = workers.get(addr);
  if (!x) workers.set(addr, x = { shares: 0, owed: 0, paid: 0, banned: false, blocks: 0 });
  return x;
};
var nodeGet = async (p) => (await fetch(nodeUrl + p)).json();
function ban(addr, why) {
  w8(addr).banned = true;
  window = window.filter((a) => a !== addr);
  log(`BANNED ${addr.slice(0, 8)}: ${why}`);
}
async function refreshTemplate() {
  try {
    const t = await nodeGet(`/template?miner=${pool.address}`);
    const jobs = t.txs.filter((x) => x.type === "job");
    if (!jobs.length) {
      current = null;
      return;
    }
    const workId = sha256(t.prevHash + t.txs.map((x) => x.id).join()).slice(0, 16);
    if (current?.workId === workId) return;
    const target = BigInt("0x" + t.target);
    current = { workId, height: t.height, prevHash: t.prevHash, prevTimestamp: t.prevTimestamp, target, shareTarget: target * SHARE_MULT, txs: t.txs, jobs, next: 0 };
    for (const [id, tp] of templates) if (tp.prevHash !== t.prevHash) templates.delete(id);
    templates.set(workId, current);
  } catch {
  }
}
var blockReward = (txs) => BLOCK_REWARD + txs.reduce((s, t) => s + (t.type === "job" ? t.fee - Math.floor(t.fee / 2) : t.fee), 0);
function pplnsSplit(reward) {
  const dist = reward - Math.floor(reward * FEE_PCT / 100);
  const counts = /* @__PURE__ */ new Map();
  for (const a of window) counts.set(a, (counts.get(a) ?? 0) + 1);
  const split = /* @__PURE__ */ new Map();
  for (const [a, c] of counts) split.set(a, Math.floor(dist * c / window.length));
  return split;
}
async function handleSubmit(sub) {
  const { sig, ...body } = sub;
  if (!verifySig(sub.worker, sha256(canon(body)), sig)) return { error: "bad sig" };
  const wk = w8(sub.worker);
  if (wk.banned) return { error: "banned" };
  const tp = templates.get(sub.workId);
  if (!tp || tp.prevHash !== current?.prevHash) return { stale: true };
  if (!(ranges.get(`${sub.workId}|${sub.worker}`) ?? []).some(([a, b2]) => sub.attempt >= a && sub.attempt < b2))
    return { error: "attempt not assigned to you" };
  if (sub.shares.length && Math.random() < CHECK_RATE) {
    const jobId = sub.shares[0].jobId, job = tp.jobs.find((j) => j.id === jobId);
    if (!job) {
      ban(sub.worker, "unknown job");
      return { error: "banned" };
    }
    const run = runJob(job.prompt, job.maxTokens, jobSeed(tp.prevHash, pool.address, job.id, sub.attempt), tp.target, tp.shareTarget);
    const claimed = sub.shares.filter((s) => s.jobId === jobId);
    if (!claimed.every((s) => run.shares.includes(s.step))) {
      ban(sub.worker, "fake share");
      return { error: "banned" };
    }
  }
  let credited = 0;
  for (const s of sub.shares) {
    const key = `${sub.workId}|${sub.attempt}|${s.jobId}|${s.step}`;
    if (seen.has(key) || !tp.jobs.some((j) => j.id === s.jobId)) continue;
    seen.add(key);
    window.push(sub.worker);
    wk.shares++;
    credited++;
  }
  if (window.length > PPLNS_N) window = window.slice(-PPLNS_N);
  if (!sub.win) return { ok: true, credited };
  const idx = tp.txs.findIndex((t) => t.id === sub.win.jobId);
  if (idx < 0) {
    ban(sub.worker, "bad win job");
    return { error: "banned" };
  }
  const txs = tp.txs.slice(0, idx + 1);
  const b = {
    height: tp.height,
    prevHash: tp.prevHash,
    timestamp: Math.max(Date.now(), tp.prevTimestamp + 1),
    miner: pool.address,
    target: tp.target.toString(16),
    attempt: sub.attempt,
    proof: { jobId: sub.win.jobId, step: sub.win.step },
    txs,
    results: sub.win.results,
    hash: ""
  };
  b.hash = blockHash(b);
  const r = await (await fetch(nodeUrl + "/block", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(b) })).json();
  if (!String(r.result).startsWith("added")) {
    ban(sub.worker, `invalid block (${r.result})`);
    return { error: "banned" };
  }
  const reward = blockReward(txs);
  pending.push({ hash: b.hash, height: b.height, split: pplnsSplit(reward) });
  found.push({ height: b.height, hash: b.hash, reward });
  wk.blocks++;
  log(`BLOCK #${b.height} found by ${sub.worker.slice(0, 8)}, reward ${reward}, pending ${CONFIRMS} confirmations`);
  await refreshTemplate();
  return { ok: true, credited, block: b.hash };
}
async function settle() {
  for (const p of [...pending]) {
    try {
      const c = await nodeGet(`/confirm/${p.hash}`);
      if (c.confirmations >= CONFIRMS) {
        for (const [a, amt] of p.split) w8(a).owed += amt;
        pending.splice(pending.indexOf(p), 1);
      } else if (c.confirmations < 0 && c.tipHeight >= p.height + CONFIRMS) {
        pending.splice(pending.indexOf(p), 1);
        log(`block #${p.height} orphaned, no payout`);
      }
    } catch {
    }
  }
}
async function payout() {
  try {
    const acct = await nodeGet(`/account/${pool.address}`);
    let nonce = acct.pendingNonce, bal = acct.balance;
    for (const [addr, wk] of workers) {
      if (wk.banned || wk.owed < PAYOUT_MIN || bal < wk.owed + 1) continue;
      const tx = makeTx(pool, { type: "transfer", from: pool.address, to: addr, amount: wk.owed, fee: 1, nonce });
      const r = await (await fetch(nodeUrl + "/tx", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(tx) })).json();
      if (!r.ok) continue;
      log(`paid ${wk.owed} to ${addr.slice(0, 8)}`);
      bal -= wk.owed + 1;
      wk.paid += wk.owed;
      wk.owed = 0;
      nonce++;
    }
  } catch {
  }
}
http.createServer(async (req, res) => {
  res.setHeader("access-control-allow-origin", "*");
  res.setHeader("access-control-allow-headers", "content-type");
  if (req.method === "OPTIONS") {
    res.writeHead(204);
    return res.end();
  }
  const send = (o, code = 200) => {
    res.writeHead(code, { "content-type": "application/json" });
    res.end(JSON.stringify(o));
  };
  try {
    const url = new URL(req.url, "http://x");
    if (req.method === "GET" && webDir && !["/work", "/stats"].includes(url.pathname)) {
      const file = join(webDir, url.pathname === "/" ? "index.html" : basename(url.pathname));
      if (existsSync(file)) {
        res.writeHead(200, { "content-type": MIME[extname(file)] ?? "application/octet-stream" });
        return res.end(readFileSync(file));
      }
    }
    if (url.pathname === "/work") {
      const worker = url.searchParams.get("worker") ?? "";
      if (!/^[0-9a-f]{64}$/.test(worker)) return send({ error: "worker address required" }, 400);
      if (!current) return send({ idle: true });
      const from = current.next;
      current.next += ATTEMPTS_PER_WORK;
      const k = `${current.workId}|${worker}`;
      ranges.set(k, [...ranges.get(k) ?? [], [from, from + ATTEMPTS_PER_WORK]]);
      return send({
        modelId: MODEL_ID,
        workId: current.workId,
        prevHash: current.prevHash,
        miner: pool.address,
        target: current.target.toString(16),
        shareTarget: current.shareTarget.toString(16),
        jobs: current.jobs,
        attemptFrom: from,
        attemptTo: from + ATTEMPTS_PER_WORK
      });
    }
    if (url.pathname === "/submit" && req.method === "POST") {
      let d = "";
      for await (const c of req) d += c;
      return send(await handleSubmit(JSON.parse(d)));
    }
    if (url.pathname === "/stats") {
      return send({
        pool: pool.address,
        feePct: FEE_PCT,
        window: window.length,
        blocksFound: found.length,
        pendingBlocks: pending.length,
        workers: Object.fromEntries([...workers].map(([a, w]) => [a.slice(0, 12), w]))
      });
    }
    send({ error: "not found" }, 404);
  } catch (e) {
    send({ error: String(e) }, 500);
  }
}).listen(port, () => log(`pool up on :${port}, node ${nodeUrl}, address ${pool.address.slice(0, 12)}${webDir ? `, web miner at http://localhost:${port}/` : ""}`));
setInterval(refreshTemplate, 1e3);
setInterval(settle, 5e3);
setInterval(payout, 1e4);
