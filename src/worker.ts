/** Pool worker (Node/Linux). Uses the WASM kernel by default, TS reference as fallback. */
import { jobSeed } from './chain.js';
import { walletFromSeed, sha256, canon, signMsg } from './crypto.js';
import { runJob, MODEL_ID } from './model.js';
import { runJobWith } from './shared/engine.js';
import { loadNodeKernel, nodeHash } from './wasm-node.js';
import type { JobTx, JobResult } from './types.js';

const arg = (k: string, d: string) => { const i = process.argv.indexOf('--' + k); return i > 0 ? process.argv[i + 1] : d; };
const poolUrl = arg('pool', 'http://localhost:4000');
const name = arg('seed', 'worker-1');
const w = walletFromSeed(name);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const log = (...a: unknown[]) => console.log(`[${name}]`, ...a);

let run = runJob, engine = 'ts';
if (arg('engine', 'wasm') === 'wasm') {
  const k = await loadNodeKernel(arg('wasm', ''));
  if (!k) log('tinylm.wasm not found (run `npm run build:wasm`), using TS engine');
  else if (k.modelId !== MODEL_ID) throw new Error(`wasm model ${k.modelId} != ${MODEL_ID}`);
  else { run = (p, m, s, t, st) => runJobWith(k.kernel, nodeHash, p, m, s, t, st); engine = 'wasm'; }
}

async function submit(body: object) {
  const sig = signMsg(w, sha256(canon(body)));
  return (await fetch(poolUrl + '/submit', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ ...body, sig }) })).json();
}

log(`worker ${w.address.slice(0, 12)} -> ${poolUrl} engine=${engine}`);
for (;;) {
  let work;
  try { work = await (await fetch(`${poolUrl}/work?worker=${w.address}`)).json(); } catch { await sleep(1000); continue; }
  if (work.idle || work.error) { await sleep(500); continue; }
  if (work.modelId && work.modelId !== MODEL_ID) { log(`pool model ${work.modelId} != ours, stopping`); process.exit(1); }
  const target = BigInt('0x' + work.target), shareTarget = BigInt('0x' + work.shareTarget);

  for (let attempt = work.attemptFrom; attempt < work.attemptTo; attempt++) {
    const shares: { jobId: string; step: number }[] = [], results: JobResult[] = [];
    let win: { jobId: string; step: number; results: JobResult[] } | undefined;
    for (const job of work.jobs as JobTx[]) {
      const r = run(job.prompt, job.maxTokens, jobSeed(work.prevHash, work.miner, job.id, attempt), target, shareTarget);
      results.push({ jobId: job.id, output: r.output });
      for (const step of r.shares) shares.push({ jobId: job.id, step });
      if (r.win >= 0) { win = { jobId: job.id, step: r.win, results: [...results] }; break; }
    }
    if (!shares.length && !win) continue;
    const resp = await submit({ worker: w.address, workId: work.workId, attempt, shares, ...(win ? { win } : {}) });
    if (resp.block) log(`found block ${resp.block.slice(0, 8)}`);
    if (resp.error === 'banned') { log('banned by pool'); process.exit(1); }
    if (resp.stale || resp.block) break;
  }
}
