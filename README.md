# aichain: Proof of Inference prototype

The PoW is the AI job. No hash grinding, no memory hardness.

## How it works
1. Users submit `job` txs (prompt + fee) to the mempool.
2. Miners run inference on mempool jobs. Every forward step emits a ticket:
   `H(seed | step | hiddenState)`, where `seed = H(prevHash | miner | jobId | attempt)`.
3. Ticket below target = block found. Miner publishes block with the answers.
4. No ticket? Increment `attempt` (new sampling seed) and re-run. Each retry is real inference.
5. Validators re-run only the winning attempt once. Mining cost ~ 1/p steps, verify cost ~ 1 run.
6. Reward: 50 coin + 50% of job fees. Other 50% of fees burned. Difficulty retargets every 6 blocks toward 10s.
7. No jobs = no mining. Block production follows demand.

## Pools (PPLNS)
- Pool sets itself as block `miner`. Tickets are bound to that address, so workers can't steal a win by submitting it solo.
- Workers get disjoint `attempt` ranges (no duplicate work) and submit signed **shares**: tickets below a target 64x easier than the block target.
- Pool re-runs 10% of submissions; any fake share = ban + shares wiped. Invalid winning block = ban.
- Reward split over the last 2,000 shares, minus 2% pool fee, credited after 3 confirmations, paid as on-chain transfers once owed >= 10.

```
npm run devnet -- --pool [--workers 3]   # nodes :3001-3003 (only :3003 solo mines), pool :4000, workers
npm run client -- load 400 --every 300
curl localhost:4000/stats
npm run worker -- --pool http://localhost:4000 --seed my-rig   # add a worker
```

## Run
```
npm install
npm run devnet                          # 3 nodes on :3001-3003
npm run client -- load 50 --every 500   # generate demand
npm run client -- send alice 100
npm run client -- ask "hello" --seed alice
npm run client -- status --node http://localhost:3002
```

## Python pool and browser inquiry chat

The repository includes `pool.py`, a Python implementation of the pool HTTP API plus a browser chat page. The chat accepts questions, submits each as a signed AIChain `job` transaction, and polls the node until an answer is mined. The existing browser miner and Node workers use the same `/work`, `/submit`, and `/stats` routes.

Requirements: Python 3.10+, NumPy, and `cryptography` (`python3 -m pip install -r requirements.txt`). For a simple local setup, start one node with solo mining disabled, then run the Python pool and at least one worker:

```sh
npm install
# Terminal 1: blockchain node; Python-pool workers will mine.
npm run node -- --port 3001 --mine false
# Terminal 2: Python pool with web chat.
python3 -m pip install -r requirements.txt
python3 pool.py --node http://127.0.0.1:3001 --port 4000
# Terminal 3: an inference worker.
npm run worker -- --pool http://127.0.0.1:4000 --seed my-rig
# Open http://127.0.0.1:4000 to submit inquiries in the browser.
```

The chat sender defaults to the devnet faucet wallet and charges `--chat-fee` (default 2 coins) per question; use a dedicated, funded wallet with `--chat-seed` outside local testing. Inquiry history is stored in `data/inquiries.sqlite3` by default; customize with `--db`. The Python server binds to `127.0.0.1` by default. Do not expose it directly to the public internet without adding authentication, abuse controls, and a dedicated funded wallet.

**Model limitation:** this is still the original deterministic TinyLM placeholder, not a production conversational LLM. The chat wires inquiries into the chain and returns the resulting output, but answer quality remains placeholder/gibberish until the model is replaced.

## WebAssembly build
`tools/build_wasm.py` compiles the TinyLM kernel (matvec, clamp, sampling, weights) straight to a `.wasm` binary. The Python pool is a separate runtime service; the default node, CLI, and worker remain TypeScript/Node.js.

```
npm run build        # python3 tools/build_wasm.py + esbuild bundles
npm run test:wasm    # WASM vs TS reference: bit-exact check + benchmark
```
Outputs:
- `dist/wasm/tinylm.wasm` + `tinylm.json` (model id, memory layout)
- `dist/web/` browser miner (pool serves it at `http://localhost:4000/`)
- `dist/linux/` + `dist/aichain-linux.tar.gz`: standalone bundles, no npm install needed

## Browser miner
Open the pool URL, pick a wallet name and thread count, press Start. Each thread is a Web Worker running WASM inference, pure-JS SHA-256 tickets, and WebCrypto Ed25519 signing. Requires a browser with Ed25519 in WebCrypto (current Chrome, Firefox, Safari).

## Linux
```
tar -xzf aichain-linux.tar.gz && cd aichain      # needs Node.js 20+
./aichain devnet --pool
./aichain client load 300 --every 300
./aichain worker --pool http://<pool-host>:4000 --seed my-rig
```

## Files
- `src/model.ts`  TinyLM: integer-only stand-in model (deterministic, gibberish output)
- `src/chain.ts`  consensus rules, validation, state, retarget, fork choice (most work)
- `src/node.ts`   HTTP node, gossip, sync, mining loop
- `src/pool.ts`   pool server: work assignment, share checks, PPLNS, payouts
- `src/worker.ts` pool worker
- `src/client.ts` wallet CLI
- `src/shared/`   browser-safe engine, SHA-256, canonical JSON
- `src/web/`      browser miner (UI + Web Worker + WebCrypto wallet)
- `tools/build_wasm.py` WASM compiler (only Python in the repo)
- `tools/build.mjs`, `tools/test-wasm.ts` bundling and verification
- `src/devnet.ts` spawns local network

## Known limits
- Model is a placeholder. Real LLM needs bit-exact int8 inference.
- Losing miners' inference is wasted, same as Bitcoin. Only the winner's answers ship.
- Users get sampled (temperature) answers, chosen by the winning seed.
- Sync re-downloads the full chain; orphaned-block txs are not returned to mempool.
- One wallet, one client at a time (nonce collisions otherwise).
- Consensus validation still uses the TS reference model; WASM is used by miners only.
- Pool: block withholding (worker hides wins, keeps share credit) is undetectable, same as Bitcoin pools.
- Pool: spot-check costs ~10% of worker compute; pool state is in memory only.
- No persistence, no P2P discovery, devnet keys derived from strings.
