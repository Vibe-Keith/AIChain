import { sha256, canon, walletFromSeed, verifySig } from './crypto.js';
import { runJob } from './model.js';
import type { Block, Tx, JobTx } from './types.js';

export const BLOCK_REWARD = 50;
export const MAX_JOBS = 8;
export const MAX_TOKENS = 128;
export const MAX_PROMPT = 512;
export const TARGET_BLOCK_MS = 10_000;
export const RETARGET = 6; // retarget every N blocks
const TWO256 = 1n << 256n;
const INITIAL_TARGET = TWO256 / 40_000n; // ~1 win per 40k inference steps
export const FAUCET = walletFromSeed('devnet-faucet');

export type Acct = { balance: number; nonce: number };
export type State = Map<string, Acct>;
type Entry = { block: Block; state: State; work: bigint };

export const txId = (tx: Tx) => { const { id, sig, ...body } = tx; return sha256(canon(body)); };
export const blockHash = (b: Block) => {
  const { hash, txs, results, ...hdr } = b;
  return sha256(canon({ ...hdr, txRoot: sha256(canon(txs)), resRoot: sha256(canon(results)) }));
};
export const jobSeed = (prev: string, miner: string, jobId: string, attempt: number) =>
  sha256(`${prev}|${miner}|${jobId}|${attempt}`);

const credit = (s: State, addr: string, n: number) => {
  const a = s.get(addr) ?? { balance: 0, nonce: 0 };
  s.set(addr, { balance: a.balance + n, nonce: a.nonce });
};

export function checkTx(tx: Tx): string | null {
  if (txId(tx) !== tx.id) return 'bad id';
  if (!verifySig(tx.from, tx.id, tx.sig)) return 'bad sig';
  if (!Number.isInteger(tx.fee) || tx.fee < 1) return 'bad fee';
  if (!Number.isInteger(tx.nonce) || tx.nonce < 0) return 'bad nonce';
  if (tx.type === 'job') {
    if (!Number.isInteger(tx.maxTokens) || tx.maxTokens < 1 || tx.maxTokens > MAX_TOKENS) return 'bad maxTokens';
    if (typeof tx.prompt !== 'string' || tx.prompt.length > MAX_PROMPT) return 'bad prompt';
  } else if (tx.type === 'transfer') {
    if (!Number.isInteger(tx.amount) || tx.amount < 1 || !/^[0-9a-f]{64}$/.test(tx.to)) return 'bad transfer';
  } else return 'bad type';
  return null;
}

// Job fees: 50% burned (makes self-submitted jobs cost real coin), 50% to miner
export function applyTx(s: State, tx: Tx, miner: string): string | null {
  const a = s.get(tx.from) ?? { balance: 0, nonce: 0 };
  if (tx.nonce !== a.nonce) return 'nonce';
  const cost = tx.fee + (tx.type === 'transfer' ? tx.amount : 0);
  if (a.balance < cost) return 'funds';
  s.set(tx.from, { balance: a.balance - cost, nonce: a.nonce + 1 });
  if (tx.type === 'transfer') credit(s, tx.to, tx.amount);
  credit(s, miner, tx.type === 'job' ? tx.fee - Math.floor(tx.fee / 2) : tx.fee);
  return null;
}

export class Chain {
  entries = new Map<string, Entry>();
  tip: string;

  constructor() {
    const g: Block = {
      height: 0, prevHash: '0'.repeat(64), timestamp: 0, miner: '', target: INITIAL_TARGET.toString(16),
      attempt: 0, proof: { jobId: '', step: 0 }, txs: [], results: [], hash: '',
    };
    g.hash = blockHash(g);
    this.entries.set(g.hash, { block: g, state: new Map([[FAUCET.address, { balance: 1_000_000, nonce: 0 }]]), work: 0n });
    this.tip = g.hash;
  }

  get tipEntry() { return this.entries.get(this.tip)!; }

  ancestor(hash: string, height: number): Block {
    let e = this.entries.get(hash)!;
    while (e.block.height > height) e = this.entries.get(e.block.prevHash)!;
    return e.block;
  }

  nextTarget(parent: Entry): bigint {
    const p = parent.block, t = BigInt('0x' + p.target);
    if ((p.height + 1) % RETARGET !== 0 || p.height < RETARGET) return t;
    const first = this.ancestor(p.hash, p.height - RETARGET + 1);
    const expected = (RETARGET - 1) * TARGET_BLOCK_MS;
    const actual = Math.min(Math.max(p.timestamp - first.timestamp, expected / 4), expected * 4);
    const nt = (t * BigInt(Math.round(actual))) / BigInt(expected);
    return nt >= TWO256 ? TWO256 - 1n : nt < 1n ? 1n : nt;
  }

  addBlock(b: Block): string {
    if (this.entries.has(b.hash)) return 'known';
    if (blockHash(b) !== b.hash) return 'invalid: hash';
    const parent = this.entries.get(b.prevHash);
    if (!parent) return 'orphan';
    const res = this.validate(b, parent);
    if (typeof res === 'string') return 'invalid: ' + res;
    const work = parent.work + TWO256 / (BigInt('0x' + b.target) + 1n);
    this.entries.set(b.hash, { block: b, state: res, work });
    if (work > this.tipEntry.work) { this.tip = b.hash; return 'added-tip'; }
    return 'added';
  }

  private validate(b: Block, parent: Entry): State | string {
    const p = parent.block;
    if (b.height !== p.height + 1) return 'height';
    const target = this.nextTarget(parent);
    if (b.target !== target.toString(16)) return 'target';
    if (b.timestamp <= p.timestamp || b.timestamp > Date.now() + 15_000) return 'timestamp';
    if (!/^[0-9a-f]{64}$/.test(b.miner)) return 'miner';
    if (!Number.isInteger(b.attempt) || b.attempt < 0) return 'attempt';
    const jobs = b.txs.filter((t): t is JobTx => t.type === 'job');
    if (jobs.length < 1 || jobs.length > MAX_JOBS) return 'job count';
    if (b.results.length !== jobs.length) return 'results count';

    const s: State = new Map(parent.state);
    credit(s, b.miner, BLOCK_REWARD);
    for (const tx of b.txs) {
      const e = checkTx(tx) ?? applyTx(s, tx, b.miner);
      if (e) return `tx ${tx.id.slice(0, 8)} ${e}`;
    }

    // Verification = one re-run of the winning attempt (miner did many attempts)
    let proofOk = false;
    for (let i = 0; i < jobs.length; i++) {
      const job = jobs[i], r = b.results[i];
      if (r.jobId !== job.id) return 'result order';
      const run = runJob(job.prompt, job.maxTokens, jobSeed(b.prevHash, b.miner, job.id, b.attempt), target);
      if (run.output !== r.output) return 'wrong output';
      if (job.id === b.proof.jobId) proofOk = run.win === b.proof.step;
    }
    return proofOk ? s : 'proof';
  }

  mainChain(): Block[] {
    const out: Block[] = [];
    for (let e = this.tipEntry; ; e = this.entries.get(e.block.prevHash)!) {
      out.push(e.block);
      if (e.block.height === 0) break;
    }
    return out.reverse();
  }

  findJob(id: string) {
    for (let e = this.tipEntry; e.block.height > 0; e = this.entries.get(e.block.prevHash)!) {
      const r = e.block.results.find((x) => x.jobId === id);
      if (r) return { output: r.output, height: e.block.height, block: e.block.hash };
    }
    return null;
  }
}
