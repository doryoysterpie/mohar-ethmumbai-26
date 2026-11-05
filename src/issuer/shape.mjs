import { VISIBLE_CLAIMS, DISCLOSABLE, ISSUING_BODY } from './profile.mjs';

const B64URL_SHA256 = /^[A-Za-z0-9_-]{43}$/;
const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

function exactKeys(value, keys, where) {
  if (!isObject(value)) throw new Error(`${where} must be an object`);
  const got = Object.keys(value).sort();
  const want = [...keys].sort();
  if (got.length !== want.length || got.some((k, i) => k !== want[i])) {
    throw new Error(`${where} must have exactly ${want.join(', ')}; has ${got.join(', ') || 'nothing'}`);
  }
}

/**
 * Throws unless the always-visible payload of an eligibility credential has exactly the expected shape,
 * down to every nested member: iss, sub, vct, iat, status.status_list { idx, uri }, cnf.jwk { kty, crv, x },
 * _sd (digests) and _sd_alg. Nothing else may be visible.
 * @param {Record<string, any>} p issuer-signed payload before disclosures are applied
 * @param {{ issuer: string, vct: string, statusUri: string, holderDid: string, holderX: string }} expected
 */
export function assertCredentialShape(p, expected) {
  exactKeys(p, VISIBLE_CLAIMS, 'credential');
  if (p.iss !== expected.issuer) throw new Error('credential issuer is not the expected issuer');
  if (p.vct !== expected.vct) throw new Error('credential is not an eligibility credential');
  if (p.sub !== expected.holderDid) throw new Error('credential subject is not this holder');
  if (!Number.isInteger(p.iat) || p.iat <= 0) throw new Error('credential iat must be a positive integer');
  if (p._sd_alg !== 'sha-256') throw new Error('credential _sd_alg must be sha-256');
  if (!Array.isArray(p._sd) || p._sd.length === 0 || !p._sd.every((d) => typeof d === 'string' && B64URL_SHA256.test(d))) {
    throw new Error('credential _sd must be a list of SHA-256 digests');
  }
  exactKeys(p.status, ['status_list'], 'credential status');
  exactKeys(p.status.status_list, ['idx', 'uri'], 'credential status_list');
  if (!Number.isInteger(p.status.status_list.idx) || p.status.status_list.idx < 0) throw new Error('credential status index must be a non-negative integer');
  if (p.status.status_list.uri !== expected.statusUri) throw new Error('credential status list is not the expected list');
  exactKeys(p.cnf, ['jwk'], 'credential cnf');
  exactKeys(p.cnf.jwk, ['kty', 'crv', 'x'], 'credential cnf.jwk');
  if (p.cnf.jwk.kty !== 'OKP' || p.cnf.jwk.crv !== 'Ed25519' || p.cnf.jwk.x !== expected.holderX) {
    throw new Error('credential is not bound to this holder key');
  }
}

/** Allowed value for each claim that may be disclosed in an eligibility presentation. */
const VALUE_RULES = {
  qualified: (v) => typeof v === 'boolean',
  paper: (v) => ['I', 'II', 'both'].includes(v),
  stage: (v) => ['primary', 'elementary', 'both'].includes(v),
  exam_session: (v) => typeof v === 'string' && /^[A-Z]{3,9} \d{4}$/.test(v),
  issuing_body: (v) => v === ISSUING_BODY,
  certificate_commitment: (v) => typeof v === 'string' && /^[0-9a-f]{64}$/.test(v),
  name: (v) => typeof v === 'string' && v.length >= 1 && v.length <= 120 && !/[\u0000-\u001f\u007f]/.test(v),
};

/**
 * Throws unless every disclosure is an object-property disclosure of a known claim, and every disclosure in
 * `presented` has a value of the allowed type. Disclosed values carry no nested structure.
 * @param {Array<{ key?: string, value: unknown }>} disclosures
 * @param {string[]} presented claim names that will be disclosed
 */
export function assertDisclosures(disclosures, presented) {
  const seen = new Set();
  for (const d of disclosures) {
    if (typeof d.key !== 'string') throw new Error('credential carries an array-element disclosure');
    if (!DISCLOSABLE.includes(d.key)) throw new Error(`credential discloses unknown claim ${d.key}`);
    if (seen.has(d.key)) throw new Error(`credential discloses ${d.key} twice`);
    seen.add(d.key);
  }
  for (const claim of presented) {
    const rule = VALUE_RULES[claim];
    const d = disclosures.find((x) => x.key === claim);
    if (!rule) throw new Error(`${claim} cannot be presented`);
    if (!d) throw new Error(`credential cannot disclose ${claim}`);
    if (!rule(d.value)) throw new Error(`credential value for ${claim} is not allowed`);
  }
}
