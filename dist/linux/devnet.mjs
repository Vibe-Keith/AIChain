// src/devnet.ts
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
var withPool = process.argv.includes("--pool");
var nWorkers = Number(process.argv[process.argv.indexOf("--workers") + 1]) || 3;
var ports = [3001, 3002, 3003];
var here = dirname(fileURLToPath(import.meta.url));
var bundled = import.meta.url.endsWith(".mjs");
var run = (name, args) => spawn(process.execPath, bundled ? [join(here, `${name}.mjs`), ...args] : ["--import", "tsx", `src/${name}.ts`, ...args], { stdio: "inherit" });
for (const p of ports) {
  const peers = ports.filter((q) => q !== p).map((q) => `http://localhost:${q}`).join(",");
  run("node", ["--port", String(p), "--peers", peers, "--mine", String(!withPool || p === 3003)]);
}
if (withPool) {
  setTimeout(() => {
    run("pool", ["--port", "4000", "--node", "http://localhost:3001"]);
    for (let i = 1; i <= nWorkers; i++) run("worker", ["--pool", "http://localhost:4000", "--seed", `worker-${i}`]);
  }, 1500);
}
