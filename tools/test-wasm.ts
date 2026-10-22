// Bit-exactness test: WASM kernel (+ both hashers) vs TS consensus reference
import { readFileSync } from 'node:fs';
import { runJob, MODEL_ID } from '../src/model.js';
import { loadWasmKernel, runJobWith, jobSeedHex } from '../src/shared/engine.js';
import { sha256 } from '../src/shared/sha256.js';
import { jobSeed } from '../src/chain.js';
import { nodeHash } from '../src/wasm-node.js';
import { walletFromSeed, verifySig } from '../src/crypto.js';

const { kernel, modelId } = await loadWasmKernel(readFileSync('dist/wasm/tinylm.wasm'));
if (modelId !== MODEL_ID) throw new Error(`model id mismatch ${modelId} != ${MODEL_ID}`);

const target = (1n << 256n) / 300n, share = target * 64n;
let n = 0;
for (let i = 0; i < 40; i++) {
  const seed = jobSeed('ab'.repeat(32), 'cd'.repeat(32), String(i), i);
  if (seed !== jobSeedHex('ab'.repeat(32), 'cd'.repeat(32), String(i), i)) throw new Error('jobSeed mismatch');
  const prompt = `test ${i} ${'é✓'.repeat(i % 3)}`;
  const ref = JSON.stringify(runJob(prompt, 40, seed, target, share));
  for (const h of [nodeHash, sha256]) {
    const got = JSON.stringify(runJobWith(kernel, h, prompt, 40, seed, target, share));
    if (got !== ref) throw new Error(`mismatch on case ${i}\nref ${ref}\ngot ${got}`);
    n++;
  }
}
console.log(`OK: ${n} runs bit-exact, model ${modelId}`);

// Browser-style Ed25519 wallet (WebCrypto) must match Node wallet
const { webWallet } = await import('../src/web/wallet.js');
const ww = await webWallet('alice');
if (ww.address !== walletFromSeed('alice').address) throw new Error('wallet address mismatch');
if (!verifySig(ww.address, 'hello', await ww.sign('hello'))) throw new Error('web signature rejected');
console.log('OK: WebCrypto wallet matches node wallet');

const bench = (label: string, f: () => { steps: number }) => {
  const t = performance.now(); let s = 0;
  while (performance.now() - t < 1500) s += f().steps;
  console.log(`${label}: ${Math.round(s / ((performance.now() - t) / 1000))} steps/s`);
};
const seed = 'ef'.repeat(32);
bench('TS reference      ', () => runJob('bench', 64, seed, target, share));
bench('WASM + node hash  ', () => runJobWith(kernel, nodeHash, 'bench', 64, seed, target, share));
bench('WASM + JS sha256  ', () => runJobWith(kernel, sha256, 'bench', 64, seed, target, share));
