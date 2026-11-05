import { generateKeyPair, exportJWK, importJWK } from 'jose';
import { fromBase64url, toBase64url, toBase58, fromBase58 } from './encoding.mjs';

/** Multicodec prefix for an Ed25519 public key. */
const ED25519_PUB = Uint8Array.from([0xed, 0x01]);

/**
 * @typedef {{ kty: 'OKP', crv: 'Ed25519', x: string, d?: string }} Ed25519Jwk
 */

/**
 * New Ed25519 key pair as JWKs.
 * @returns {Promise<{ privateJwk: Ed25519Jwk, publicJwk: Ed25519Jwk }>}
 */
export async function generateEd25519() {
  const { privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
  const privateJwk = /** @type {Ed25519Jwk} */ (await exportJWK(privateKey));
  return { privateJwk, publicJwk: publicOf(privateJwk) };
}

/**
 * @param {Ed25519Jwk} jwk
 * @returns {Ed25519Jwk}
 */
export function publicOf(jwk) {
  return { kty: 'OKP', crv: 'Ed25519', x: jwk.x };
}

/**
 * Signer in the shape the SD-JWT library expects: data string in, base64url signature out.
 * @param {Ed25519Jwk} privateJwk
 * @returns {(data: string) => Promise<string>}
 */
export function signerFor(privateJwk) {
  const keyP = importJWK({ ...privateJwk, alg: 'EdDSA' }, 'EdDSA');
  return async (data) => {
    const key = /** @type {CryptoKey} */ (await keyP);
    const sig = await crypto.subtle.sign('Ed25519', key, new TextEncoder().encode(data));
    return toBase64url(new Uint8Array(sig));
  };
}

/**
 * Verifier in the shape the SD-JWT library expects.
 * @param {Ed25519Jwk} publicJwk
 * @returns {(data: string, signature: string) => Promise<boolean>}
 */
export function verifierFor(publicJwk) {
  const keyP = importJWK({ ...publicOf(publicJwk), alg: 'EdDSA' }, 'EdDSA');
  return async (data, signature) => {
    const key = /** @type {CryptoKey} */ (await keyP);
    return crypto.subtle.verify('Ed25519', key, fromBase64url(signature), new TextEncoder().encode(data));
  };
}

/**
 * did:key for an Ed25519 public key.
 * @param {Ed25519Jwk} jwk
 * @returns {string}
 */
export function didKeyFromJwk(jwk) {
  const x = fromBase64url(jwk.x);
  if (x.length !== 32) throw new TypeError('didKeyFromJwk: Ed25519 public key must be 32 bytes');
  const bytes = new Uint8Array(34);
  bytes.set(ED25519_PUB, 0);
  bytes.set(x, 2);
  return `did:key:z${toBase58(bytes)}`;
}

/**
 * Ed25519 public JWK from a did:key. Throws for any other key type.
 * @param {string} did
 * @returns {Ed25519Jwk}
 */
export function jwkFromDidKey(did) {
  const m = /^did:key:z([1-9A-HJ-NP-Za-km-z]+)$/.exec(did);
  if (!m) throw new TypeError('jwkFromDidKey: not a base58 did:key');
  const bytes = fromBase58(m[1]);
  if (bytes.length !== 34 || bytes[0] !== ED25519_PUB[0] || bytes[1] !== ED25519_PUB[1]) {
    throw new TypeError('jwkFromDidKey: not an Ed25519 did:key');
  }
  return { kty: 'OKP', crv: 'Ed25519', x: toBase64url(bytes.slice(2)) };
}
