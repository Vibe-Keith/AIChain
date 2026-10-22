/**
 * Mining pool (PPLNS). Pool address is the block's `miner`, so every ticket a
 * worker finds is only valid for the pool: workers cannot steal wins.
 * Workers prove work with "shares": tickets below an easier share target.
 */
import http from 'node:http';
import { readFileSync, existsSync } from 'node:fs';
import { join, basename, extname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { blockHash, jobSeed, BLOCK_REWARD } from './chain.js';
import { walletFromSeed, sha256, canon, verifySig, makeTx } from './crypto.js';
import { runJob, MODEL_ID } from './model.js';
import type { Block, Tx, JobTx, JobResult } from './types.js';

const arg = (k: string, d: string) => { const i = process.argv.indexOf('--' + k); return i > 0 ? process.argv[i + 1] : d; };
const port = Number(arg('port', '4000'));
const nodeUrl = arg('node', 'http://localhost:3001');
const pool = walletFromSeed(arg('seed', 'pool-1'));

// Static web miner: --web dir, else ./web next to bundle, else dist/web
const webDir = [arg('web', ''), fileURLToPath(new URL('./web/', import.meta.url)), 'dist/web'].find((d) => d && existsSync(join(d, 'index.html')));
const MIME: Record<string, string> = { '.html': 'text/html', '.js': 'text/javascript', '.wasm': 'application/wasm', '.json': 'application/json' };

const FEE_PCT = 2;            // pool's cut
const SHARE_MULT = 64n;       // share target = 64x easier than block target
const CHECK_RATE = 0.1;       // fraction of share submissions re-executed by pool
const PPLNS_N = 2000;         // reward split over last N shares
const PAYOUT_MIN = 10;        // min owed before sending a transfer
const CONFIRMS = 3;           // credit only after N confirmations (reorg safety)
const ATTEMPTS_PER_WORK = 8;  // attempt range per /work request

type Template = { workId: string; height: number; prevHash: string; prevTimestamp: number; target: bigint; shareTarget: bigint; txs: Tx[]; jobs: JobTx[]; next: number };
type Worker = { shares: number; owed: number; paid: number; banned: boolean; blocks: number };

let current: Template | null = null;
const templates = new Map<string, Template>();
const ranges = new Map<string, [number, number][]>(); // `${workId}|${worker}` -> attempt ranges
const seen = new Set<string>();
const workers = new Map<string, Worker>();
let window: string[] = []; // PPLNS: one entry (worker addr) per share
const pending: { hash: string; height: number; split: Map<string, number> }[] = [];
const found: { height: number; hash: string; reward: number }[] = [];

const log = (...a: unknown[]) => console.log('[pool]', ...a);
const w8 = (addr: string) => { let x = workers.get(addr); if (!x) workers.set(addr, (x = { shares: 0, owed: 0, paid: 0, banned: false, blocks: 0 })); return x; };
const nodeGet = async (p: string) => (await fetch(nodeUrl + p)).json();

function ban(addr: string, why: string) {
  w8(addr).banned = true;
  window = window.filter((a) => a !== addr);
  log(`BANNED ${addr.slice(0, 8)}: ${why}`);
}

async function refreshTemplate() {
  try {
    const t = await nodeGet(`/template?miner=${pool.address}`);
    const jobs = (t.txs as Tx[]).filter((x): x is JobTx => x.type === 'job');
    if (!jobs.length) { current = null; return; }
    const workId = sha256(t.prevHash + (t.txs as Tx[]).map((x) => x.id).join()).slice(0, 16);
    if (current?.workId === workId) return;
    const target = BigInt('0x' + t.target);
    current = { workId, height: t.height, prevHash: t.prevHash, prevTimestamp: t.prevTimestamp, target, shareTarget: target * SHARE_MULT, txs: t.txs, jobs, next: 0 };
    for (const [id, tp] of templates) if (tp.prevHash !== t.prevHash) templates.delete(id);
    templates.set(workId, current);
  } catch { /* node down */ }
}

// Reward the pool gets for a block built from txs
const blockReward = (txs: Tx[]) =>
  BLOCK_REWARD + txs.reduce((s, t) => s + (t.type === 'job' ? t.fee - Math.floor(t.fee / 2) : t.fee), 0);

function pplnsSplit(reward: number) {
  const dist = reward - Math.floor((reward * FEE_PCT) / 100);
  const counts = new Map<string, number>();
  for (const a of window) counts.set(a, (counts.get(a) ?? 0) + 1);
  const split = new Map<string, number>();
  for (const [a, c] of counts) split.set(a, Math.floor((dist * c) / window.length));
  return split;
}

type Submit = { worker: string; workId: string; attempt: number; shares: { jobId: string; step: number }[]; win?: { jobId: string; step: number; results: JobResult[] }; sig: string };

async function handleSubmit(sub: Submit) {
  const { sig, ...body } = sub;
  if (!verifySig(sub.worker, sha256(canon(body)), sig)) return { error: 'bad sig' };
  const wk = w8(sub.worker);
  if (wk.banned) return { error: 'banned' };
  const tp = templates.get(sub.workId);
  if (!tp || tp.prevHash !== current?.prevHash) return { stale: true };
  if (!(ranges.get(`${sub.workId}|${sub.worker}`) ?? []).some(([a, b]) => sub.attempt >= a && sub.attempt < b))
    return { error: 'attempt not assigned to you' };

  // Spot-check: re-run one job of this attempt and confirm claimed share steps
  if (sub.shares.length && Math.random() < CHECK_RATE) {
    const jobId = sub.shares[0].jobId, job = tp.jobs.find((j) => j.id === jobId);
    if (!job) { ban(sub.worker, 'unknown job'); return { error: 'banned' }; }
    const run = runJob(job.prompt, job.maxTokens, jobSeed(tp.prevHash, pool.address, job.id, sub.attempt), tp.target, tp.shareTarget);
    const claimed = sub.shares.filter((s) => s.jobId === jobId);
    if (!claimed.every((s) => run.shares.includes(s.step))) { ban(sub.worker, 'fake share'); return { error: 'banned' }; }
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

  // Build and submit the block; the node does full verification
  const idx = tp.txs.findIndex((t) => t.id === sub.win!.jobId);
  if (idx < 0) { ban(sub.worker, 'bad win job'); return { error: 'banned' }; }
  const txs = tp.txs.slice(0, idx + 1);
  const b: Block = {
    height: tp.height, prevHash: tp.prevHash, timestamp: Math.max(Date.now(), tp.prevTimestamp + 1),
    miner: pool.address, target: tp.target.toString(16), attempt: sub.attempt,
    proof: { jobId: sub.win.jobId, step: sub.win.step }, txs, results: sub.win.results, hash: '',
  };
  b.hash = blockHash(b);
  const r = await (await fetch(nodeUrl + '/block', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(b) })).json();
  if (!String(r.result).startsWith('added')) { ban(sub.worker, `invalid block (${r.result})`); return { error: 'banned' }; }
  const reward = blockReward(txs);
  pending.push({ hash: b.hash, height: b.height, split: pplnsSplit(reward) });
  found.push({ height: b.height, hash: b.hash, reward });
  wk.blocks++;
  log(`BLOCK #${b.height} found by ${sub.worker.slice(0, 8)}, reward ${reward}, pending ${CONFIRMS} confirmations`);
  await refreshTemplate();
  return { ok: true, credited, block: b.hash };
}

// Move matured block rewards into owed balances; drop orphans
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
    } catch { /* node down */ }
  }
}

async function payout() {
  try {
    const acct = await nodeGet(`/account/${pool.address}`);
    let nonce = acct.pendingNonce, bal = acct.balance;
    for (const [addr, wk] of workers) {
      if (wk.banned || wk.owed < PAYOUT_MIN || bal < wk.owed + 1) continue;
      const tx = makeTx(pool, { type: 'transfer', from: pool.address, to: addr, amount: wk.owed, fee: 1, nonce });
      const r = await (await fetch(nodeUrl + '/tx', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(tx) })).json();
      if (!r.ok) continue;
      log(`paid ${wk.owed} to ${addr.slice(0, 8)}`);
      bal -= wk.owed + 1; wk.paid += wk.owed; wk.owed = 0; nonce++;
    }
  } catch { /* node down */ }
}

http.createServer(async (req, res) => {
  res.setHeader('access-control-allow-origin', '*'); // web miners hosted elsewhere
  res.setHeader('access-control-allow-headers', 'content-type');
  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }
  const send = (o: unknown, code = 200) => { res.writeHead(code, { 'content-type': 'application/json' }); res.end(JSON.stringify(o)); };
  try {
    const url = new URL(req.url!, 'http://x');
    if (req.method === 'GET' && webDir && !['/work', '/stats'].includes(url.pathname)) {
      const file = join(webDir, url.pathname === '/' ? 'index.html' : basename(url.pathname));
      if (existsSync(file)) { res.writeHead(200, { 'content-type': MIME[extname(file)] ?? 'application/octet-stream' }); return res.end(readFileSync(file)); }
    }
    if (url.pathname === '/work') {
      const worker = url.searchParams.get('worker') ?? '';
      if (!/^[0-9a-f]{64}$/.test(worker)) return send({ error: 'worker address required' }, 400);
      if (!current) return send({ idle: true });
      const from = current.next; current.next += ATTEMPTS_PER_WORK;
      const k = `${current.workId}|${worker}`;
      ranges.set(k, [...(ranges.get(k) ?? []), [from, from + ATTEMPTS_PER_WORK]]);
      return send({
        modelId: MODEL_ID, workId: current.workId, prevHash: current.prevHash, miner: pool.address, target: current.target.toString(16),
        shareTarget: current.shareTarget.toString(16), jobs: current.jobs, attemptFrom: from, attemptTo: from + ATTEMPTS_PER_WORK,
      });
    }
    if (url.pathname === '/submit' && req.method === 'POST') {
      let d = ''; for await (const c of req) d += c;
      return send(await handleSubmit(JSON.parse(d)));
    }
    if (url.pathname === '/stats') {
      return send({
        pool: pool.address, feePct: FEE_PCT, window: window.length, blocksFound: found.length, pendingBlocks: pending.length,
        workers: Object.fromEntries([...workers].map(([a, w]) => [a.slice(0, 12), w])),
      });
    }
    send({ error: 'not found' }, 404);
  } catch (e) { send({ error: String(e) }, 500); }
}).listen(port, () => log(`pool up on :${port}, node ${nodeUrl}, address ${pool.address.slice(0, 12)}${webDir ? `, web miner at http://localhost:${port}/` : ''}`));

setInterval(refreshTemplate, 1000);
setInterval(settle, 5000);
setInterval(payout, 10_000);
