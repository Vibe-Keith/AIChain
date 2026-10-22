// src/node.ts
import http from "node:http";

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
var MAX_JOBS = 8;
var MAX_TOKENS = 128;
var MAX_PROMPT = 512;
var TARGET_BLOCK_MS = 1e4;
var RETARGET = 6;
var TWO256 = 1n << 256n;
var INITIAL_TARGET = TWO256 / 40000n;
var FAUCET = walletFromSeed("devnet-faucet");
var txId = (tx) => {
  const { id, sig, ...body } = tx;
  return sha256(canon(body));
};
var blockHash = (b) => {
  const { hash, txs, results, ...hdr } = b;
  return sha256(canon({ ...hdr, txRoot: sha256(canon(txs)), resRoot: sha256(canon(results)) }));
};
var jobSeed = (prev, miner, jobId, attempt) => sha256(`${prev}|${miner}|${jobId}|${attempt}`);
var credit = (s, addr, n) => {
  const a = s.get(addr) ?? { balance: 0, nonce: 0 };
  s.set(addr, { balance: a.balance + n, nonce: a.nonce });
};
function checkTx(tx) {
  if (txId(tx) !== tx.id) return "bad id";
  if (!verifySig(tx.from, tx.id, tx.sig)) return "bad sig";
  if (!Number.isInteger(tx.fee) || tx.fee < 1) return "bad fee";
  if (!Number.isInteger(tx.nonce) || tx.nonce < 0) return "bad nonce";
  if (tx.type === "job") {
    if (!Number.isInteger(tx.maxTokens) || tx.maxTokens < 1 || tx.maxTokens > MAX_TOKENS) return "bad maxTokens";
    if (typeof tx.prompt !== "string" || tx.prompt.length > MAX_PROMPT) return "bad prompt";
  } else if (tx.type === "transfer") {
    if (!Number.isInteger(tx.amount) || tx.amount < 1 || !/^[0-9a-f]{64}$/.test(tx.to)) return "bad transfer";
  } else return "bad type";
  return null;
}
function applyTx(s, tx, miner) {
  const a = s.get(tx.from) ?? { balance: 0, nonce: 0 };
  if (tx.nonce !== a.nonce) return "nonce";
  const cost = tx.fee + (tx.type === "transfer" ? tx.amount : 0);
  if (a.balance < cost) return "funds";
  s.set(tx.from, { balance: a.balance - cost, nonce: a.nonce + 1 });
  if (tx.type === "transfer") credit(s, tx.to, tx.amount);
  credit(s, miner, tx.type === "job" ? tx.fee - Math.floor(tx.fee / 2) : tx.fee);
  return null;
}
var Chain = class {
  entries = /* @__PURE__ */ new Map();
  tip;
  constructor() {
    const g = {
      height: 0,
      prevHash: "0".repeat(64),
      timestamp: 0,
      miner: "",
      target: INITIAL_TARGET.toString(16),
      attempt: 0,
      proof: { jobId: "", step: 0 },
      txs: [],
      results: [],
      hash: ""
    };
    g.hash = blockHash(g);
    this.entries.set(g.hash, { block: g, state: /* @__PURE__ */ new Map([[FAUCET.address, { balance: 1e6, nonce: 0 }]]), work: 0n });
    this.tip = g.hash;
  }
  get tipEntry() {
    return this.entries.get(this.tip);
  }
  ancestor(hash, height) {
    let e = this.entries.get(hash);
    while (e.block.height > height) e = this.entries.get(e.block.prevHash);
    return e.block;
  }
  nextTarget(parent) {
    const p = parent.block, t = BigInt("0x" + p.target);
    if ((p.height + 1) % RETARGET !== 0 || p.height < RETARGET) return t;
    const first = this.ancestor(p.hash, p.height - RETARGET + 1);
    const expected = (RETARGET - 1) * TARGET_BLOCK_MS;
    const actual = Math.min(Math.max(p.timestamp - first.timestamp, expected / 4), expected * 4);
    const nt = t * BigInt(Math.round(actual)) / BigInt(expected);
    return nt >= TWO256 ? TWO256 - 1n : nt < 1n ? 1n : nt;
  }
  addBlock(b) {
    if (this.entries.has(b.hash)) return "known";
    if (blockHash(b) !== b.hash) return "invalid: hash";
    const parent = this.entries.get(b.prevHash);
    if (!parent) return "orphan";
    const res = this.validate(b, parent);
    if (typeof res === "string") return "invalid: " + res;
    const work = parent.work + TWO256 / (BigInt("0x" + b.target) + 1n);
    this.entries.set(b.hash, { block: b, state: res, work });
    if (work > this.tipEntry.work) {
      this.tip = b.hash;
      return "added-tip";
    }
    return "added";
  }
  validate(b, parent) {
    const p = parent.block;
    if (b.height !== p.height + 1) return "height";
    const target = this.nextTarget(parent);
    if (b.target !== target.toString(16)) return "target";
    if (b.timestamp <= p.timestamp || b.timestamp > Date.now() + 15e3) return "timestamp";
    if (!/^[0-9a-f]{64}$/.test(b.miner)) return "miner";
    if (!Number.isInteger(b.attempt) || b.attempt < 0) return "attempt";
    const jobs = b.txs.filter((t) => t.type === "job");
    if (jobs.length < 1 || jobs.length > MAX_JOBS) return "job count";
    if (b.results.length !== jobs.length) return "results count";
    const s = new Map(parent.state);
    credit(s, b.miner, BLOCK_REWARD);
    for (const tx of b.txs) {
      const e = checkTx(tx) ?? applyTx(s, tx, b.miner);
      if (e) return `tx ${tx.id.slice(0, 8)} ${e}`;
    }
    let proofOk = false;
    for (let i = 0; i < jobs.length; i++) {
      const job = jobs[i], r = b.results[i];
      if (r.jobId !== job.id) return "result order";
      const run = runJob(job.prompt, job.maxTokens, jobSeed(b.prevHash, b.miner, job.id, b.attempt), target);
      if (run.output !== r.output) return "wrong output";
      if (job.id === b.proof.jobId) proofOk = run.win === b.proof.step;
    }
    return proofOk ? s : "proof";
  }
  mainChain() {
    const out = [];
    for (let e = this.tipEntry; ; e = this.entries.get(e.block.prevHash)) {
      out.push(e.block);
      if (e.block.height === 0) break;
    }
    return out.reverse();
  }
  findJob(id) {
    for (let e = this.tipEntry; e.block.height > 0; e = this.entries.get(e.block.prevHash)) {
      const r = e.block.results.find((x) => x.jobId === id);
      if (r) return { output: r.output, height: e.block.height, block: e.block.hash };
    }
    return null;
  }
};

// src/node.ts
var arg = (k, d = "") => {
  const i = process.argv.indexOf("--" + k);
  return i > 0 ? process.argv[i + 1] : d;
};
var port = Number(arg("port", "3001"));
var peers = arg("peers").split(",").filter(Boolean);
var me = walletFromSeed(arg("seed", `miner-${port}`));
var mining = arg("mine", "true") !== "false";
var chain = new Chain();
var mempool = /* @__PURE__ */ new Map();
var log = (...a) => console.log(`[${port}]`, ...a);
var sleep = (ms) => new Promise((r) => setTimeout(r, ms));
var tick = () => new Promise((r) => setImmediate(r));
function gossip(path, body) {
  for (const p of peers)
    fetch(p + path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) }).catch(() => {
    });
}
var syncing = false;
async function syncFrom(peer) {
  try {
    const blocks = await (await fetch(peer + "/chain")).json();
    const before = chain.tip;
    for (const b of blocks) chain.addBlock(b);
    if (chain.tip !== before) {
      prune();
      log(`synced to #${chain.tipEntry.block.height} from ${peer}`);
    }
  } catch {
  }
}
async function syncAll() {
  if (syncing) return;
  syncing = true;
  for (const p of peers) await syncFrom(p);
  syncing = false;
}
async function pollPeers() {
  for (const p of peers) {
    try {
      const s = await (await fetch(p + "/status")).json();
      if (BigInt(s.work) > chain.tipEntry.work) await syncFrom(p);
    } catch {
    }
  }
}
function prune() {
  const s = chain.tipEntry.state;
  for (const [id, tx] of mempool) if (tx.nonce < (s.get(tx.from)?.nonce ?? 0)) mempool.delete(id);
}
async function receiveBlock(b) {
  const r = chain.addBlock(b);
  if (r === "orphan") await syncAll();
  else if (r.startsWith("added")) {
    gossip("/block", b);
    if (r === "added-tip") {
      prune();
      log(`tip #${b.height} ${b.hash.slice(0, 8)} miner=${b.miner.slice(0, 6)} jobs=${b.results.length} attempt=${b.attempt}`);
    }
  } else if (r.startsWith("invalid")) log("rejected block:", r);
  return r;
}
function selectTxs(miner = me.address) {
  const s = new Map(chain.tipEntry.state);
  const pending = [...mempool.values()].sort((a, b) => a.nonce - b.nonce || b.fee - a.fee);
  const out = [];
  let jobs = 0, progress = true;
  while (progress) {
    progress = false;
    for (const tx of pending) {
      if (out.includes(tx) || tx.type === "job" && jobs >= MAX_JOBS) continue;
      if (applyTx(s, tx, miner) === null) {
        out.push(tx);
        if (tx.type === "job") jobs++;
        progress = true;
      }
    }
  }
  return out;
}
var steps = 0;
async function mineLoop() {
  let lastKey = "", attempt = 0;
  for (; ; ) {
    await tick();
    const tipE = chain.tipEntry;
    const sel = selectTxs();
    if (!sel.some((t) => t.type === "job")) {
      await sleep(250);
      continue;
    }
    const key = tipE.block.hash + sel.map((t) => t.id).join();
    attempt = key === lastKey ? attempt + 1 : 0;
    lastKey = key;
    const target = chain.nextTarget(tipE);
    const results = [];
    let won = -1, proof = { jobId: "", step: 0 };
    for (let i = 0; i < sel.length && won < 0; i++) {
      const tx = sel[i];
      if (tx.type !== "job") continue;
      const r = runJob(tx.prompt, tx.maxTokens, jobSeed(tipE.block.hash, me.address, tx.id, attempt), target);
      steps += r.steps;
      results.push({ jobId: tx.id, output: r.output });
      if (r.win >= 0) {
        won = i;
        proof = { jobId: tx.id, step: r.win };
      }
    }
    if (won < 0 || chain.tip !== tipE.block.hash) continue;
    const b = {
      height: tipE.block.height + 1,
      prevHash: tipE.block.hash,
      timestamp: Math.max(Date.now(), tipE.block.timestamp + 1),
      miner: me.address,
      target: target.toString(16),
      attempt,
      proof,
      txs: sel.slice(0, won + 1),
      results,
      hash: ""
    };
    b.hash = blockHash(b);
    log(`MINED #${b.height} on attempt ${attempt}`);
    await receiveBlock(b);
  }
}
var readBody = (req) => new Promise((res, rej) => {
  let d = "";
  req.on("data", (c) => d += c);
  req.on("end", () => res(d));
  req.on("error", rej);
});
http.createServer(async (req, res) => {
  const send = (code, o) => {
    res.writeHead(code, { "content-type": "application/json" });
    res.end(JSON.stringify(o));
  };
  try {
    const url = new URL(req.url, "http://x");
    const [, route, param] = url.pathname.split("/");
    if (req.method === "POST") {
      const body = JSON.parse(await readBody(req));
      if (route === "tx") {
        const tx = body;
        if (mempool.has(tx.id)) return send(200, { ok: true, id: tx.id });
        const e = checkTx(tx);
        if (e) return send(400, { error: e });
        mempool.set(tx.id, tx);
        gossip("/tx", tx);
        return send(200, { ok: true, id: tx.id });
      }
      if (route === "block") return send(200, { result: await receiveBlock(body) });
    } else {
      const s = chain.tipEntry.state;
      if (route === "status") {
        const t = chain.tipEntry;
        return send(200, {
          port,
          model: MODEL_ID,
          miner: me.address,
          height: t.block.height,
          tip: t.block.hash,
          target: chain.nextTarget(t).toString(16),
          work: t.work.toString(),
          mempool: mempool.size,
          balance: s.get(me.address)?.balance ?? 0,
          peers
        });
      }
      if (route === "chain") return send(200, chain.mainChain());
      if (route === "template") {
        const t = chain.tipEntry;
        return send(200, {
          height: t.block.height + 1,
          prevHash: t.block.hash,
          prevTimestamp: t.block.timestamp,
          target: chain.nextTarget(t).toString(16),
          txs: selectTxs(url.searchParams.get("miner") ?? me.address)
        });
      }
      if (route === "confirm") {
        const e = chain.entries.get(param), tipH = chain.tipEntry.block.height;
        const onMain = e && chain.ancestor(chain.tip, e.block.height).hash === param;
        return send(200, { confirmations: onMain ? tipH - e.block.height + 1 : -1, tipHeight: tipH });
      }
      if (route === "job") {
        const f = chain.findJob(param);
        return send(200, f ? { status: "done", ...f } : { status: mempool.has(param) ? "pending" : "unknown" });
      }
      if (route === "account") {
        const a = s.get(param) ?? { balance: 0, nonce: 0 };
        const pending = [...mempool.values()].filter((t) => t.from === param).length;
        return send(200, { ...a, pendingNonce: a.nonce + pending });
      }
    }
    send(404, { error: "not found" });
  } catch (e) {
    send(500, { error: String(e) });
  }
}).listen(port, () => log(`node up, miner=${me.address.slice(0, 12)} model=${MODEL_ID} mining=${mining}`));
setTimeout(syncAll, 500);
setInterval(pollPeers, 5e3);
setInterval(() => {
  if (steps) log(`${Math.round(steps / 15)} inference steps/s, height ${chain.tipEntry.block.height}`);
  steps = 0;
}, 15e3);
if (mining) mineLoop();
