import { toBase64url, fromBase64url } from './encoding.mjs';
import { signerFor, verifierFor } from './keys.mjs';

const enc = (o) => toBase64url(new TextEncoder().encode(JSON.stringify(o)));
const dec = (s) => JSON.parse(new TextDecoder().decode(fromBase64url(s)));

/**
 * Compact JWS (EdDSA) over a JSON payload.
 * @param {Record<string, unknown>} payload
 * @param {{ typ: string, kid: string }} header
 * @param {import('./keys.mjs').Ed25519Jwk} privateJwk
 * @returns {Promise<string>}
 */
export async function signJws(payload, header, privateJwk) {
  const input = `${enc({ alg: 'EdDSA', typ: header.typ, kid: header.kid })}.${enc(payload)}`;
  return `${input}.${await signerFor(privateJwk)(input)}`;
}

/**
 * Header and payload of a compact JWS, without checking the signature.
 * @param {string} jws
 * @returns {{ header: Record<string, any>, payload: Record<string, any> }}
 */
export function decodeJws(jws) {
  const parts = jws.split('.');
  if (parts.length !== 3 || parts.some((p) => !p)) throw new Error('not a compact JWS');
  return { header: dec(parts[0]), payload: dec(parts[1]) };
}

/**
 * Verifies a compact JWS against a public key and an expected `typ`. Returns header and payload.
 * @param {string} jws
 * @param {import('./keys.mjs').Ed25519Jwk} publicJwk
 * @param {string} typ
 */
export async function verifyJws(jws, publicJwk, typ) {
  const { header, payload } = decodeJws(jws);
  if (header.alg !== 'EdDSA') throw new Error(`unexpected alg ${header.alg}`);
  if (header.typ !== typ) throw new Error(`unexpected typ ${header.typ}`);
  const [h, p, s] = jws.split('.');
  if (!(await verifierFor(publicJwk)(`${h}.${p}`, s))) throw new Error('signature invalid');
  return { header, payload };
}
