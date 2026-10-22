export type TransferBody = { type: 'transfer'; from: string; to: string; amount: number; fee: number; nonce: number };
export type JobBody = { type: 'job'; from: string; prompt: string; maxTokens: number; fee: number; nonce: number };
export type Signed = { id: string; sig: string };
export type JobTx = JobBody & Signed;
export type Tx = (TransferBody | JobBody) & Signed;
export type JobResult = { jobId: string; output: string };

export type Block = {
  height: number;
  prevHash: string;
  timestamp: number;
  miner: string;
  target: string; // hex
  attempt: number; // sampling-seed counter; each retry = full re-inference
  proof: { jobId: string; step: number }; // which job + inference step hit the target
  txs: Tx[];
  results: JobResult[]; // results[i] answers the i-th job tx in txs
  hash: string;
};
