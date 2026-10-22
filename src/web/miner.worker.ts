/** Browser mining thread: WASM kernel + JS SHA-256 + WebCrypto signing. */
import { loadWasmKernel, runJobWith, jobSeedHex, type Kernel } from '../shared/engine.js';
import { sha256, sha256Hex } from '../shared/sha256.js';
import { canon } from '../shared/canon.js';
import { webWallet } from './wallet.js';

type JobTx = { id: string; prompt: string; maxTokens: number };
const post = (m: object) => (self as unknown as Worker).postMessage(m);
let running = false;
let stats = { steps: 0, shares: 0, accepted: 0, blocks: 0 };
const tick = () => new Promise((r) => setTimeout(r, 0));
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

self.onmessage = (e: MessageEvent) => {
  if (e.data.type === 'start' && !running) { running = true; mine(e.data.poolUrl, e.data.seed).catch((err) => { running = false; post({ type: 'status', status: `stopped: ${err.message}` }); }); }
  if (e.data.type === 'stop') running = false;
};
setInterval(() => { post({ type: 'stats', ...stats }); stats = { steps: 0, shares: 0, accepted: 0, blocks: 0 }; }, 1000);

async function mine(poolUrl: string, seed: string) {
  const { kernel, modelId } = await loadWasmKernel(await (await fetch('tinylm.wasm')).arrayBuffer());
  const w = await webWallet(seed);
  post({ type: 'ready', modelId, address: w.address });
  const submit = async (body: object) => {
    const sig = await w.sign(sha256Hex(canon(body)));
    return (await fetch(poolUrl + '/submit', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ ...body, sig }) })).json();
  };

  while (running) {
    let work;
    try { work = await (await fetch(`${poolUrl}/work?worker=${w.address}`)).json(); }
    catch { post({ type: 'status', status: 'pool unreachable, retrying' }); await sleep(2000); continue; }
    if (work.idle) { post({ type: 'status', status: 'waiting for user queries' }); await sleep(1000); continue; }
    if (work.error) throw new Error(work.error);
    if (work.modelId !== modelId) throw new Error(`model mismatch: pool ${work.modelId}, browser ${modelId}`);
    post({ type: 'status', status: 'mining' });
    const target = BigInt('0x' + work.target), shareTarget = BigInt('0x' + work.shareTarget);

    for (let attempt = work.attemptFrom; attempt < work.attemptTo && running; attempt++) {
      const r = runAttempt(kernel, work, attempt, target, shareTarget);
      await tick(); // let stop messages through
      if (!r.shares.length && !r.win) continue;
      stats.shares += r.shares.length;
      const resp = await submit({ worker: w.address, workId: work.workId, attempt, shares: r.shares, ...(r.win ? { win: r.win } : {}) });
      if (resp.error) throw new Error(resp.error);
      stats.accepted += resp.credited ?? 0;
      if (resp.block) { stats.blocks++; post({ type: 'block', hash: resp.block }); }
      if (resp.stale || resp.block) break;
    }
  }
  post({ type: 'status', status: 'stopped' });
}

function runAttempt(kernel: Kernel, work: any, attempt: number, target: bigint, shareTarget: bigint) {
  const shares: { jobId: string; step: number }[] = [], results: { jobId: string; output: string }[] = [];
  let win: { jobId: string; step: number; results: typeof results } | undefined;
  for (const job of work.jobs as JobTx[]) {
    const r = runJobWith(kernel, sha256, job.prompt, job.maxTokens, jobSeedHex(work.prevHash, work.miner, job.id, attempt), target, shareTarget);
    stats.steps += r.steps;
    results.push({ jobId: job.id, output: r.output });
    for (const step of r.shares) shares.push({ jobId: job.id, step });
    if (r.win >= 0) { win = { jobId: job.id, step: r.win, results: [...results] }; break; }
  }
  return { shares, win };
}
