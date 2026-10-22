/**
 * Runtime-agnostic job runner over a pluggable kernel (WASM) and hash function.
 * Same semantics as src/model.ts runJob (the consensus reference).
 */
import { utf8, hexToBytes, bytesToHex, sha256 } from './sha256.js';

export type RunResult = { output: string; win: number; steps: number; shares: number[] };
export type Hash = (data: Uint8Array) => Uint8Array; // 32-byte digest
export interface Kernel { init(seed: Uint8Array): void; step(tok: number): Uint8Array; sample(): number }

const MAX = (1n << 256n) - 1n;
const targetBytes = (t: bigint) => (t > MAX ? null : hexToBytes(t.toString(16).padStart(64, '0')));
const below = (d: Uint8Array, t: Uint8Array | null) => {
  if (!t) return true;
  for (let i = 0; i < 32; i++) if (d[i] !== t[i]) return d[i] < t[i];
  return false;
};

export function runJobWith(k: Kernel, hash: Hash, prompt: string, maxTokens: number, seedHex: string, target: bigint, shareTarget?: bigint): RunResult {
  const seed = hexToBytes(seedHex);
  const tb = targetBytes(target), sb = shareTarget === undefined ? undefined : targetBytes(shareTarget);
  const buf = new Uint8Array(32 + 16 + 128);
  buf.set(seed, 0);
  k.init(seed);
  let s = 0, win = -1;
  const shares: number[] = [];
  const step = (tok: number) => {
    const hb = k.step(tok);
    if (win < 0 || sb !== undefined) {
      const digits = utf8(String(s));
      buf.set(digits, 32);
      buf.set(hb, 32 + digits.length);
      const d = hash(buf.subarray(0, 32 + digits.length + hb.length));
      if (win < 0 && below(d, tb)) win = s;
      if (sb !== undefined && below(d, sb)) shares.push(s);
    }
    s++;
  };
  for (const b of utf8(prompt)) step(b);
  let out = '';
  for (let i = 0; i < maxTokens; i++) { const tok = k.sample(); out += String.fromCharCode(tok); step(tok); }
  return { output: out, win, steps: s, shares };
}

export async function loadWasmKernel(bytes: BufferSource): Promise<{ kernel: Kernel; modelId: string }> {
  const { instance } = await WebAssembly.instantiate(bytes, {});
  const ex = instance.exports as any;
  const mem = new Uint8Array(ex.memory.buffer);
  const seedPtr: number = ex.seed_ptr.value, hbPtr: number = ex.hb_ptr.value;
  const hb = mem.subarray(hbPtr, hbPtr + 128);
  const kernel: Kernel = {
    init(seed) { mem.set(seed, seedPtr); ex.init(); },
    step(tok) { ex.step(tok); return hb; },
    sample() { return ex.sample(); },
  };
  const modelId = bytesToHex(sha256(mem.subarray(0, ex.weights_len.value))).slice(0, 16);
  return { kernel, modelId };
}

export const jobSeedHex = (prev: string, miner: string, jobId: string, attempt: number) =>
  bytesToHex(sha256(utf8(`${prev}|${miner}|${jobId}|${attempt}`)));
