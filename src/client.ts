import { walletFromSeed, makeTx } from './crypto.js';
import type { Tx } from './types.js';

const args = process.argv.slice(2);
const flag = (k: string, d: string) => { const i = args.indexOf('--' + k); return i >= 0 ? args[i + 1] : d; };
const node = flag('node', 'http://localhost:3001');
const w = walletFromSeed(flag('seed', 'devnet-faucet'));
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const get = async (p: string) => (await fetch(node + p)).json();
const post = async (tx: Tx) =>
  (await fetch(node + '/tx', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(tx) })).json();
const addr = (x: string) => (/^[0-9a-f]{64}$/.test(x) ? x : walletFromSeed(x).address);

const job = (prompt: string, nonce: number) => makeTx(w, {
  type: 'job', from: w.address, prompt, maxTokens: Number(flag('tokens', '64')), fee: Number(flag('fee', '2')), nonce,
});

const [cmd, a1, a2] = args;
if (cmd === 'ask') {
  const tx = job(a1 ?? 'hello', (await get(`/account/${w.address}`)).pendingNonce);
  console.log('submitted', tx.id.slice(0, 12), await post(tx));
  for (;;) {
    const j = await get(`/job/${tx.id}`);
    if (j.status === 'done') { console.log(`answered in block #${j.height}:\n${j.output}`); break; }
    await sleep(1000);
  }
} else if (cmd === 'load') {
  const n = Number(a1 ?? 50), every = Number(flag('every', '1000'));
  let nonce = (await get(`/account/${w.address}`)).pendingNonce;
  for (let i = 0; i < n; i++) {
    const r = await post(job(`query ${i} ${Math.random().toString(36).slice(2)}`, nonce++));
    console.log(`job ${i}`, r.ok ? 'ok' : r.error);
    await sleep(every);
  }
} else if (cmd === 'send') {
  const nonce = (await get(`/account/${w.address}`)).pendingNonce;
  console.log(await post(makeTx(w, { type: 'transfer', from: w.address, to: addr(a1), amount: Number(a2), fee: 1, nonce })));
} else if (cmd === 'account') {
  const x = addr(a1 ?? w.address);
  console.log(x, await get(`/account/${x}`));
} else if (cmd === 'status') {
  console.log(await get('/status'));
} else {
  console.log(`usage:
  client ask "<prompt>" [--tokens 64] [--fee 2]   submit query, wait for answer
  client load [n] [--every ms]                    generate demand (miners need jobs)
  client send <seed|addr> <amount>                transfer coin
  client account [seed|addr]                      balance + nonce
  client status
  flags: --node http://localhost:3001  --seed devnet-faucet`);
}
