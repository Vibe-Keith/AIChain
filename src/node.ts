import http from 'node:http';
import { Chain, jobSeed, checkTx, applyTx, blockHash, MAX_JOBS } from './chain.js';
import { walletFromSeed } from './crypto.js';
import { runJob, MODEL_ID } from './model.js';
import type { Block, Tx, JobResult } from './types.js';

const arg = (k: string, d = '') => { const i = process.argv.indexOf('--' + k); return i > 0 ? process.argv[i + 1] : d; };
const port = Number(arg('port', '3001'));
const peers = arg('peers').split(',').filter(Boolean);
const me = walletFromSeed(arg('seed', `miner-${port}`));
const mining = arg('mine', 'true') !== 'false';

const chain = new Chain();
const mempool = new Map<string, Tx>();
const log = (...a: unknown[]) => console.log(`[${port}]`, ...a);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const tick = () => new Promise((r) => setImmediate(r));

// ---------- networking ----------
function gossip(path: string, body: unknown) {
  for (const p of peers)
    fetch(p + path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }).catch(() => {});
}

let syncing = false;
async function syncFrom(peer: string) {
  try {
    const blocks: Block[] = await (await fetch(peer + '/chain')).json();
    const before = chain.tip;
    for (const b of blocks) chain.addBlock(b);
    if (chain.tip !== before) { prune(); log(`synced to #${chain.tipEntry.block.height} from ${peer}`); }
  } catch { /* peer down */ }
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
      const s = await (await fetch(p + '/status')).json();
      if (BigInt(s.work) > chain.tipEntry.work) await syncFrom(p);
    } catch { /* peer down */ }
  }
}

function prune() {
  const s = chain.tipEntry.state;
  for (const [id, tx] of mempool) if (tx.nonce < (s.get(tx.from)?.nonce ?? 0)) mempool.delete(id);
}

async function receiveBlock(b: Block) {
  const r = chain.addBlock(b);
  if (r === 'orphan') await syncAll();
  else if (r.startsWith('added')) {
    gossip('/block', b);
    if (r === 'added-tip') {
      prune();
      log(`tip #${b.height} ${b.hash.slice(0, 8)} miner=${b.miner.slice(0, 6)} jobs=${b.results.length} attempt=${b.attempt}`);
    }
  } else if (r.startsWith('invalid')) log('rejected block:', r);
  return r;
}

// ---------- mining: the PoW IS the inference ----------
function selectTxs(miner = me.address): Tx[] {
  const s = new Map(chain.tipEntry.state);
  const pending = [...mempool.values()].sort((a, b) => a.nonce - b.nonce || b.fee - a.fee);
  const out: Tx[] = [];
  let jobs = 0, progress = true;
  while (progress) {
    progress = false;
    for (const tx of pending) {
      if (out.includes(tx) || (tx.type === 'job' && jobs >= MAX_JOBS)) continue;
      if (applyTx(s, tx, miner) === null) { out.push(tx); if (tx.type === 'job') jobs++; progress = true; }
    }
  }
  return out;
}

let steps = 0;
async function mineLoop() {
  let lastKey = '', attempt = 0;
  for (;;) {
    await tick();
    const tipE = chain.tipEntry;
    const sel = selectTxs();
    if (!sel.some((t) => t.type === 'job')) { await sleep(250); continue; } // no demand, no mining
    const key = tipE.block.hash + sel.map((t) => t.id).join();
    attempt = key === lastKey ? attempt + 1 : 0;
    lastKey = key;
    const target = chain.nextTarget(tipE);

    const results: JobResult[] = [];
    let won = -1, proof = { jobId: '', step: 0 };
    for (let i = 0; i < sel.length && won < 0; i++) {
      const tx = sel[i];
      if (tx.type !== 'job') continue;
      const r = runJob(tx.prompt, tx.maxTokens, jobSeed(tipE.block.hash, me.address, tx.id, attempt), target);
      steps += r.steps;
      results.push({ jobId: tx.id, output: r.output });
      if (r.win >= 0) { won = i; proof = { jobId: tx.id, step: r.win }; }
    }
    if (won < 0 || chain.tip !== tipE.block.hash) continue;

    const b: Block = {
      height: tipE.block.height + 1, prevHash: tipE.block.hash,
      timestamp: Math.max(Date.now(), tipE.block.timestamp + 1),
      miner: me.address, target: target.toString(16), attempt, proof,
      txs: sel.slice(0, won + 1), results, hash: '',
    };
    b.hash = blockHash(b);
    log(`MINED #${b.height} on attempt ${attempt}`);
    await receiveBlock(b);
  }
}

// ---------- HTTP API ----------
const readBody = (req: http.IncomingMessage) =>
  new Promise<string>((res, rej) => { let d = ''; req.on('data', (c) => (d += c)); req.on('end', () => res(d)); req.on('error', rej); });

http.createServer(async (req, res) => {
  const send = (code: number, o: unknown) => { res.writeHead(code, { 'content-type': 'application/json' }); res.end(JSON.stringify(o)); };
  try {
    const url = new URL(req.url!, 'http://x');
    const [, route, param] = url.pathname.split('/');
    if (req.method === 'POST') {
      const body = JSON.parse(await readBody(req));
      if (route === 'tx') {
        const tx = body as Tx;
        if (mempool.has(tx.id)) return send(200, { ok: true, id: tx.id });
        const e = checkTx(tx);
        if (e) return send(400, { error: e });
        mempool.set(tx.id, tx);
        gossip('/tx', tx);
        return send(200, { ok: true, id: tx.id });
      }
      if (route === 'block') return send(200, { result: await receiveBlock(body as Block) });
    } else {
      const s = chain.tipEntry.state;
      if (route === 'status') {
        const t = chain.tipEntry;
        return send(200, {
          port, model: MODEL_ID, miner: me.address, height: t.block.height, tip: t.block.hash,
          target: chain.nextTarget(t).toString(16), work: t.work.toString(), mempool: mempool.size,
          balance: s.get(me.address)?.balance ?? 0, peers,
        });
      }
      if (route === 'chain') return send(200, chain.mainChain());
      if (route === 'template') { // block template for pools
        const t = chain.tipEntry;
        return send(200, {
          height: t.block.height + 1, prevHash: t.block.hash, prevTimestamp: t.block.timestamp,
          target: chain.nextTarget(t).toString(16), txs: selectTxs(url.searchParams.get('miner') ?? me.address),
        });
      }
      if (route === 'confirm') { // confirmations on main chain, -1 if not on it
        const e = chain.entries.get(param), tipH = chain.tipEntry.block.height;
        const onMain = e && chain.ancestor(chain.tip, e.block.height).hash === param;
        return send(200, { confirmations: onMain ? tipH - e!.block.height + 1 : -1, tipHeight: tipH });
      }
      if (route === 'job') {
        const f = chain.findJob(param);
        return send(200, f ? { status: 'done', ...f } : { status: mempool.has(param) ? 'pending' : 'unknown' });
      }
      if (route === 'account') {
        const a = s.get(param) ?? { balance: 0, nonce: 0 };
        const pending = [...mempool.values()].filter((t) => t.from === param).length;
        return send(200, { ...a, pendingNonce: a.nonce + pending });
      }
    }
    send(404, { error: 'not found' });
  } catch (e) {
    send(500, { error: String(e) });
  }
}).listen(port, () => log(`node up, miner=${me.address.slice(0, 12)} model=${MODEL_ID} mining=${mining}`));

setTimeout(syncAll, 500);
setInterval(pollPeers, 5000);
setInterval(() => { if (steps) log(`${Math.round(steps / 15)} inference steps/s, height ${chain.tipEntry.block.height}`); steps = 0; }, 15_000);
if (mining) mineLoop();
