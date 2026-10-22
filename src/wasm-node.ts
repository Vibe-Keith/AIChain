// Load the WASM kernel in Node (worker / Linux bundle)
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { loadWasmKernel } from './shared/engine.js';

export const nodeHash = (d: Uint8Array) => createHash('sha256').update(d).digest();

export async function loadNodeKernel(explicit?: string) {
  const candidates = [explicit, fileURLToPath(new URL('./tinylm.wasm', import.meta.url)), 'dist/wasm/tinylm.wasm'].filter(Boolean) as string[];
  const path = candidates.find((p) => existsSync(p));
  if (!path) return null;
  return { path, ...(await loadWasmKernel(readFileSync(path))) };
}
