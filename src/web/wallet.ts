// Ed25519 wallet via WebCrypto; same derivation as src/crypto.ts walletFromSeed
import { sha256, utf8, bytesToHex, hexToBytes } from '../shared/sha256.js';

const PKCS8 = hexToBytes('302e020100300506032b657004220420');
const b64url = (s: string) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4)), (c) => c.charCodeAt(0));

export async function webWallet(seed: string) {
  const der = new Uint8Array(48);
  der.set(PKCS8); der.set(sha256(utf8(seed)), 16);
  const key = await crypto.subtle.importKey('pkcs8', der, { name: 'Ed25519' }, true, ['sign']);
  const jwk = await crypto.subtle.exportKey('jwk', key);
  return {
    address: bytesToHex(b64url(jwk.x!)),
    sign: async (msg: string) => bytesToHex(new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, key, utf8(msg)))),
  };
}
