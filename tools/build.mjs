// Bundles the web miner and the Linux distribution (JS only; WASM comes from tools/build_wasm.py)
import { build } from 'esbuild';
import { cpSync, existsSync, rmSync, writeFileSync, chmodSync } from 'node:fs';
import { execSync } from 'node:child_process';

if (!existsSync('dist/wasm/tinylm.wasm')) throw new Error('dist/wasm/tinylm.wasm missing: run `npm run build:wasm`');
for (const d of ['dist/web', 'dist/linux']) rmSync(d, { recursive: true, force: true });

await build({
  entryPoints: { app: 'src/web/app.ts', 'miner.worker': 'src/web/miner.worker.ts' },
  bundle: true, format: 'esm', target: 'es2022', minify: true, outdir: 'dist/web', logLevel: 'warning',
});
cpSync('web/index.html', 'dist/web/index.html');
cpSync('dist/wasm/tinylm.wasm', 'dist/web/tinylm.wasm');

await build({
  entryPoints: ['node', 'pool', 'worker', 'client', 'devnet'].map((n) => `src/${n}.ts`),
  bundle: true, platform: 'node', format: 'esm', target: 'node20', outdir: 'dist/linux',
  outExtension: { '.js': '.mjs' }, logLevel: 'warning',
});
cpSync('dist/wasm/tinylm.wasm', 'dist/linux/tinylm.wasm');
cpSync('dist/web', 'dist/linux/web', { recursive: true });
writeFileSync('dist/linux/aichain', `#!/usr/bin/env bash
# aichain launcher (needs Node.js 20+)
set -e
DIR="$(cd "$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
cmd="\${1:-}"; shift || true
case "$cmd" in
  node|pool|worker|client|devnet) exec node "$DIR/$cmd.mjs" "$@" ;;
  *) echo "usage: aichain {node|pool|worker|client|devnet} [args]"; exit 1 ;;
esac
`);
chmodSync('dist/linux/aichain', 0o755);
execSync('tar -czf dist/aichain-linux.tar.gz -C dist --transform s/^linux/aichain/ linux');
console.log('built dist/web (browser miner), dist/linux + dist/aichain-linux.tar.gz');
