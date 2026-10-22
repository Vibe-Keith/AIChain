/**
 * TinyLM: integer-only recurrent "language model" stand-in.
 * Pure int math => bit-exact on every machine, which is what makes
 * re-execution verification possible. Output is gibberish by design;
 * swap in a deterministic int8 LLM later (see README).
 */
import { createHash } from 'node:crypto';
import { sha256 } from './crypto.js';

const D = 128, V = 256, LO = 32, HI = 126; // hidden size, vocab (bytes), printable range

function xorshift(seed: number) {
  let s = seed >>> 0 || 1;
  return () => { s ^= s << 13; s >>>= 0; s ^= s >>> 17; s ^= s << 5; s >>>= 0; return s; };
}

// Weights generated from a fixed seed: every node has the identical model
const wr = xorshift(0xc0ffee);
const fill = (n: number) => { const a = new Int8Array(n); for (let i = 0; i < n; i++) a[i] = (wr() % 16) - 8; return a; };
const E = fill(V * D), Wh = fill(D * D), Wo = fill(D * V);
export const MODEL_ID = sha256(new Uint8Array(E.buffer), new Uint8Array(Wh.buffer), new Uint8Array(Wo.buffer)).slice(0, 16);

export type RunResult = { output: string; win: number; steps: number; shares: number[] };

/**
 * Runs inference. Every forward step (prefill + generation) yields a lottery
 * ticket = H(seed | step | hiddenState). First ticket below target = win.
 * seed binds the run to (prevHash, miner, job, attempt) so tickets can't be
 * precomputed or recomputed without redoing inference.
 */
/** shareTarget (optional, pools): also collect every step whose ticket is below
 *  an easier target. Consensus never uses it. */
export function runJob(prompt: string, maxTokens: number, seedHex: string, target: bigint, shareTarget?: bigint): RunResult {
  const seed = Buffer.from(seedHex, 'hex');
  const h = new Int32Array(D), nx = new Int32Array(D), hb = new Uint8Array(D);
  for (let i = 0; i < D; i++) h[i] = seed[i % 32] - 128;

  let s = 0, win = -1;
  const shares: number[] = [];
  const step = (tok: number) => {
    const eo = tok * D;
    for (let i = 0; i < D; i++) {
      let acc = E[eo + i] * 64;
      const ro = i * D;
      for (let j = 0; j < D; j++) acc += Wh[ro + j] * h[j];
      acc >>= 6;
      nx[i] = acc > 127 ? 127 : acc < -127 ? -127 : acc;
    }
    h.set(nx);
    if (win < 0 || shareTarget !== undefined) {
      for (let i = 0; i < D; i++) hb[i] = h[i] & 255;
      const t = BigInt('0x' + createHash('sha256').update(seed).update(String(s)).update(hb).digest('hex'));
      if (win < 0 && t < target) win = s;
      if (shareTarget !== undefined && t < shareTarget) shares.push(s);
    }
    s++;
  };

  for (const b of Buffer.from(prompt, 'utf8')) step(b);

  const rng = xorshift(seed.readUInt32LE(0)); // seeded sampling noise
  let out = '';
  for (let k = 0; k < maxTokens; k++) {
    let best = -Infinity, tok = LO;
    for (let v = LO; v <= HI; v++) {
      let l = rng() % 4096;
      for (let i = 0; i < D; i++) l += Wo[i * V + v] * h[i];
      if (l > best) { best = l; tok = v; }
    }
    out += String.fromCharCode(tok);
    step(tok);
  }
  return { output: out, win, steps: s, shares };
}
