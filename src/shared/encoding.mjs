import { createHash } from 'node:crypto';

/**
 * SHA-256 of a string (UTF-8) or bytes.
 * @param {string | Uint8Array} data
 * @returns {Uint8Array}
 */
export function sha256(data) {
  return new Uint8Array(createHash('sha256').update(data).digest());
}

/**
 * SHA-256 as lowercase hex.
 * @param {string | Uint8Array} data
 * @returns {string}
 */
export function sha256Hex(data) {
  return createHash('sha256').update(data).digest('hex');
}

/**
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function toBase64url(bytes) {
  return Buffer.from(bytes).toString('base64url');
}

/**
 * @param {string} text
 * @returns {Uint8Array}
 */
export function fromBase64url(text) {
  return new Uint8Array(Buffer.from(text, 'base64url'));
}

/**
 * JSON with object keys sorted at every level and no whitespace.
 * Throws on values JSON cannot represent exactly.
 * @param {unknown} value
 * @returns {string}
 */
export function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('canonicalJson: non-finite number');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (typeof value === 'object') {
    const keys = Object.keys(value).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(/** @type {Record<string, unknown>} */ (value)[k])}`).join(',')}}`;
  }
  throw new TypeError(`canonicalJson: unsupported type ${typeof value}`);
}

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

/**
 * Base58 (Bitcoin alphabet).
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function toBase58(bytes) {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  let out = '';
  while (n > 0n) { out = B58[Number(n % 58n)] + out; n /= 58n; }
  for (const b of bytes) { if (b !== 0) break; out = '1' + out; }
  return out;
}

/**
 * @param {string} text
 * @returns {Uint8Array}
 */
export function fromBase58(text) {
  let n = 0n;
  for (const c of text) {
    const i = B58.indexOf(c);
    if (i < 0) throw new TypeError(`fromBase58: invalid character ${c}`);
    n = n * 58n + BigInt(i);
  }
  const bytes = [];
  while (n > 0n) { bytes.unshift(Number(n & 0xffn)); n >>= 8n; }
  for (const c of text) { if (c !== '1') break; bytes.unshift(0); }
  return new Uint8Array(bytes);
}
