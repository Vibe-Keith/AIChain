import { createHash, createPrivateKey, createPublicKey, sign, verify, KeyObject } from 'node:crypto';
import type { Tx, TransferBody, JobBody } from './types.js';

export const sha256 = (...parts: (string | Uint8Array)[]): string => {
  const h = createHash('sha256');
  for (const p of parts) h.update(p);
  return h.digest('hex');
};

import { canon } from './shared/canon.js';
export { canon };

const PKCS8 = Buffer.from('302e020100300506032b657004220420', 'hex');
const SPKI = Buffer.from('302a300506032b6570032100', 'hex');

export type Wallet = { address: string; key: KeyObject };

// Ed25519 wallet from a string seed (devnet convenience, not secure key mgmt)
export function walletFromSeed(seed: string): Wallet {
  const raw = createHash('sha256').update(seed).digest();
  const key = createPrivateKey({ key: Buffer.concat([PKCS8, raw]), format: 'der', type: 'pkcs8' });
  const pub = createPublicKey(key).export({ format: 'der', type: 'spki' }) as Buffer;
  return { address: pub.subarray(-32).toString('hex'), key };
}

export function verifySig(address: string, msg: string, sig: string): boolean {
  try {
    const pub = createPublicKey({ key: Buffer.concat([SPKI, Buffer.from(address, 'hex')]), format: 'der', type: 'spki' });
    return verify(null, Buffer.from(msg), pub, Buffer.from(sig, 'hex'));
  } catch {
    return false;
  }
}

export function makeTx(w: Wallet, body: TransferBody | JobBody): Tx {
  const id = sha256(canon(body));
  return { ...body, id, sig: sign(null, Buffer.from(id), w.key).toString('hex') };
}

export const signMsg = (w: Wallet, msg: string) => sign(null, Buffer.from(msg), w.key).toString('hex');
