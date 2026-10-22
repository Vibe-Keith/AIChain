import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

// npm run devnet            -> 3 solo-mining nodes
// npm run devnet -- --pool  -> 3 nodes (only :3003 solo mines), pool on :4000, workers
const withPool = process.argv.includes('--pool');
const nWorkers = Number(process.argv[process.argv.indexOf('--workers') + 1]) || 3;
const ports = [3001, 3002, 3003];
const here = dirname(fileURLToPath(import.meta.url));
const bundled = import.meta.url.endsWith('.mjs'); // Linux bundle vs dev (tsx)
const run = (name: string, args: string[]) =>
  spawn(process.execPath, bundled ? [join(here, `${name}.mjs`), ...args] : ['--import', 'tsx', `src/${name}.ts`, ...args], { stdio: 'inherit' });

for (const p of ports) {
  const peers = ports.filter((q) => q !== p).map((q) => `http://localhost:${q}`).join(',');
  run('node', ['--port', String(p), '--peers', peers, '--mine', String(!withPool || p === 3003)]);
}
if (withPool) {
  setTimeout(() => {
    run('pool', ['--port', '4000', '--node', 'http://localhost:3001']);
    for (let i = 1; i <= nWorkers; i++) run('worker', ['--pool', 'http://localhost:4000', '--seed', `worker-${i}`]);
  }, 1500);
}
