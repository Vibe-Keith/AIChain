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
var signMsg = (w2, msg) => sign(null, Buffer.from(msg), w2.key).toString("hex");

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
var TWO256 = 1n << 256n;
var INITIAL_TARGET = TWO256 / 40000n;
var FAUCET = walletFromSeed("devnet-faucet");
var jobSeed = (prev, miner, jobId, attempt) => sha256(`${prev}|${miner}|${jobId}|${attempt}`);

// src/shared/sha256.ts
var K = new Uint32Array([
  1116352408,
  1899447441,
  3049323471,
  3921009573,
  961987163,
  1508970993,
  2453635748,
  2870763221,
  3624381080,
  310598401,
  607225278,
  1426881987,
  1925078388,
  2162078206,
  2614888103,
  3248222580,
  3835390401,
  4022224774,
  264347078,
  604807628,
  770255983,
  1249150122,
  1555081692,
  1996064986,
  2554220882,
  2821834349,
  2952996808,
  3210313671,
  3336571891,
  3584528711,
  113926993,
  338241895,
  666307205,
  773529912,
  1294757372,
  1396182291,
  1695183700,
  1986661051,
  2177026350,
  2456956037,
  2730485921,
  2820302411,
  3259730800,
  3345764771,
  3516065817,
  3600352804,
  4094571909,
  275423344,
  430227734,
  506948616,
  659060556,
  883997877,
  958139571,
  1322822218,
  1537002063,
  1747873779,
  1955562222,
  2024104815,
  2227730452,
  2361852424,
  2428436474,
  2756734187,
  3204031479,
  3329325298
]);
var W = new Uint32Array(64);
var rotr = (x, n) => x >>> n | x << 32 - n;
function sha2562(data) {
  const len = data.length, padLen = len + 9 + 63 >> 6 << 6;
  const buf = new Uint8Array(padLen);
  buf.set(data);
  buf[len] = 128;
  const dv = new DataView(buf.buffer);
  dv.setUint32(padLen - 4, len * 8 >>> 0);
  dv.setUint32(padLen - 8, Math.floor(len * 8 / 2 ** 32));
  let h0 = 1779033703, h1 = 3144134277, h2 = 1013904242, h3 = 2773480762, h4 = 1359893119, h5 = 2600822924, h6 = 528734635, h7 = 1541459225;
  for (let off = 0; off < padLen; off += 64) {
    for (let t = 0; t < 16; t++) W[t] = dv.getUint32(off + t * 4);
    for (let t = 16; t < 64; t++) {
      const a2 = W[t - 15], b2 = W[t - 2];
      W[t] = W[t - 16] + (rotr(a2, 7) ^ rotr(a2, 18) ^ a2 >>> 3) + W[t - 7] + (rotr(b2, 17) ^ rotr(b2, 19) ^ b2 >>> 10) | 0;
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
    for (let t = 0; t < 64; t++) {
      const t1 = h + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + (e & f ^ ~e & g) + K[t] + W[t] | 0;
      const t2 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + (a & b ^ a & c ^ b & c) | 0;
      h = g;
      g = f;
      f = e;
      e = d + t1 | 0;
      d = c;
      c = b;
      b = a;
      a = t1 + t2 | 0;
    }
    h0 = h0 + a | 0;
    h1 = h1 + b | 0;
    h2 = h2 + c | 0;
    h3 = h3 + d | 0;
    h4 = h4 + e | 0;
    h5 = h5 + f | 0;
    h6 = h6 + g | 0;
    h7 = h7 + h | 0;
  }
  const out = new Uint8Array(32), ov = new DataView(out.buffer);
  [h0, h1, h2, h3, h4, h5, h6, h7].forEach((x, i) => ov.setUint32(i * 4, x >>> 0));
  return out;
}
var enc = new TextEncoder();
var utf8 = (s) => enc.encode(s);
var bytesToHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
var hexToBytes = (h) => {
  const out = new Uint8Array(h.length >> 1);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
};

// src/shared/engine.ts
var MAX = (1n << 256n) - 1n;
var targetBytes = (t) => t > MAX ? null : hexToBytes(t.toString(16).padStart(64, "0"));
var below = (d, t) => {
  if (!t) return true;
  for (let i = 0; i < 32; i++) if (d[i] !== t[i]) return d[i] < t[i];
  return false;
};
function runJobWith(k, hash, prompt, maxTokens, seedHex, target, shareTarget) {
  const seed = hexToBytes(seedHex);
  const tb = targetBytes(target), sb = shareTarget === void 0 ? void 0 : targetBytes(shareTarget);
  const buf = new Uint8Array(32 + 16 + 128);
  buf.set(seed, 0);
  k.init(seed);
  let s = 0, win = -1;
  const shares = [];
  const step = (tok) => {
    const hb = k.step(tok);
    if (win < 0 || sb !== void 0) {
      const digits = utf8(String(s));
      buf.set(digits, 32);
      buf.set(hb, 32 + digits.length);
      const d = hash(buf.subarray(0, 32 + digits.length + hb.length));
      if (win < 0 && below(d, tb)) win = s;
      if (sb !== void 0 && below(d, sb)) shares.push(s);
    }
    s++;
  };
  for (const b of utf8(prompt)) step(b);
  let out = "";
  for (let i = 0; i < maxTokens; i++) {
    const tok = k.sample();
    out += String.fromCharCode(tok);
    step(tok);
  }
  return { output: out, win, steps: s, shares };
}
async function loadWasmKernel(bytes) {
  const { instance } = await WebAssembly.instantiate(bytes, {});
  const ex = instance.exports;
  const mem = new Uint8Array(ex.memory.buffer);
  const seedPtr = ex.seed_ptr.value, hbPtr = ex.hb_ptr.value;
  const hb = mem.subarray(hbPtr, hbPtr + 128);
  const kernel = {
    init(seed) {
      mem.set(seed, seedPtr);
      ex.init();
    },
    step(tok) {
      ex.step(tok);
      return hb;
    },
    sample() {
      return ex.sample();
    }
  };
  const modelId = bytesToHex(sha2562(mem.subarray(0, ex.weights_len.value))).slice(0, 16);
  return { kernel, modelId };
}

// src/wasm-node.ts
import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createHash as createHash3 } from "node:crypto";
var nodeHash = (d) => createHash3("sha256").update(d).digest();
async function loadNodeKernel(explicit) {
  const candidates = [explicit, fileURLToPath(new URL("./tinylm.wasm", import.meta.url)), "dist/wasm/tinylm.wasm"].filter(Boolean);
  const path = candidates.find((p) => existsSync(p));
  if (!path) return null;
  return { path, ...await loadWasmKernel(readFileSync(path)) };
}

// src/worker.ts
var arg = (k, d) => {
  const i = process.argv.indexOf("--" + k);
  return i > 0 ? process.argv[i + 1] : d;
};
var poolUrl = arg("pool", "http://localhost:4000");
var name = arg("seed", "worker-1");
var w = walletFromSeed(name);
var sleep = (ms) => new Promise((r) => setTimeout(r, ms));
var log = (...a) => console.log(`[${name}]`, ...a);
var run = runJob;
var engine = "ts";
if (arg("engine", "wasm") === "wasm") {
  const k = await loadNodeKernel(arg("wasm", ""));
  if (!k) log("tinylm.wasm not found (run `npm run build:wasm`), using TS engine");
  else if (k.modelId !== MODEL_ID) throw new Error(`wasm model ${k.modelId} != ${MODEL_ID}`);
  else {
    run = (p, m, s, t, st) => runJobWith(k.kernel, nodeHash, p, m, s, t, st);
    engine = "wasm";
  }
}
async function submit(body) {
  const sig = signMsg(w, sha256(canon(body)));
  return (await fetch(poolUrl + "/submit", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ ...body, sig }) })).json();
}
log(`worker ${w.address.slice(0, 12)} -> ${poolUrl} engine=${engine}`);
for (; ; ) {
  let work;
  try {
    work = await (await fetch(`${poolUrl}/work?worker=${w.address}`)).json();
  } catch {
    await sleep(1e3);
    continue;
  }
  if (work.idle || work.error) {
    await sleep(500);
    continue;
  }
  if (work.modelId && work.modelId !== MODEL_ID) {
    log(`pool model ${work.modelId} != ours, stopping`);
    process.exit(1);
  }
  const target = BigInt("0x" + work.target), shareTarget = BigInt("0x" + work.shareTarget);
  for (let attempt = work.attemptFrom; attempt < work.attemptTo; attempt++) {
    const shares = [], results = [];
    let win;
    for (const job of work.jobs) {
      const r = run(job.prompt, job.maxTokens, jobSeed(work.prevHash, work.miner, job.id, attempt), target, shareTarget);
      results.push({ jobId: job.id, output: r.output });
      for (const step of r.shares) shares.push({ jobId: job.id, step });
      if (r.win >= 0) {
        win = { jobId: job.id, step: r.win, results: [...results] };
        break;
      }
    }
    if (!shares.length && !win) continue;
    const resp = await submit({ worker: w.address, workId: work.workId, attempt, shares, ...win ? { win } : {} });
    if (resp.block) log(`found block ${resp.block.slice(0, 8)}`);
    if (resp.error === "banned") {
      log("banned by pool");
      process.exit(1);
    }
    if (resp.stale || resp.block) break;
  }
}
