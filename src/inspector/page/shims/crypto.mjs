// Browser stand-in for the parts of node:crypto the verifier uses: SHA-256 and random bytes.
import { sha256 } from '@noble/hashes/sha256';
import { Buffer } from 'buffer';

/** createHash('sha256') with update(string | bytes, encoding?) and digest(encoding?). */
export function createHash(algorithm) {
  if (algorithm !== 'sha256') throw new Error(`unsupported hash ${algorithm}`);
  const h = sha256.create();
  const api = {
    update(data, encoding) {
      h.update(typeof data === 'string' ? Buffer.from(data, encoding ?? 'utf8') : data);
      return api;
    },
    digest(encoding) {
      const out = Buffer.from(h.digest());
      return encoding ? out.toString(encoding) : out;
    },
  };
  return api;
}

/** Random bytes from the browser CSPRNG. */
export function randomBytes(n) {
  return Buffer.from(globalThis.crypto.getRandomValues(new Uint8Array(n)));
}

/** UUID from the browser. */
export const randomUUID = () => globalThis.crypto.randomUUID();
