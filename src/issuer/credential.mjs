import { randomBytes } from 'node:crypto';
import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import { decodeSdJwt } from '@sd-jwt/core';
import { sha256, sha256Hex, canonicalJson, toBase64url } from '../shared/encoding.mjs';
import { signerFor, verifierFor, didKeyFromJwk, publicOf } from '../shared/keys.mjs';
import { resolveIssuerKey } from './did-web.mjs';
import {
  ISSUER_DID, VCT, STATUS_LIST_URI, ISSUING_BODY, DISCLOSABLE, CERTIFICATE_FIELDS,
} from './profile.mjs';

/** SD-JWT hasher: SHA-256 only. */
export async function hasher(data, alg) {
  if (alg.toLowerCase() !== 'sha-256') throw new Error(`unsupported hash ${alg}`);
  return sha256(typeof data === 'string' ? data : new Uint8Array(data));
}

/** @param {number} length */
const saltGenerator = (length) => toBase64url(randomBytes(length));

/**
 * SHA-256 (hex) of the canonical JSON of a certificate.
 * @param {Record<string, unknown>} certificate
 */
export function certificateCommitment(certificate) {
  return sha256Hex(canonicalJson(certificate));
}

/**
 * Throws unless the certificate carries every field and is marked SIMULATED.
 * @param {Record<string, unknown>} certificate
 */
export function assertCertificate(certificate) {
  const missing = CERTIFICATE_FIELDS.filter((f) => !(f in certificate));
  if (missing.length) throw new Error(`certificate is missing ${missing.join(', ')}`);
  if (typeof certificate.notice !== 'string' || !certificate.notice.includes('SIMULATED')) {
    throw new Error('certificate is not marked SIMULATED');
  }
}

/**
 * Issues an eligibility credential (SD-JWT VC) for a certificate, bound to the holder's key.
 * @param {{
 *   certificate: Record<string, any>,
 *   holderPublicJwk: import('../shared/keys.mjs').Ed25519Jwk,
 *   statusIndex: number,
 *   issuerPrivateJwk: import('../shared/keys.mjs').Ed25519Jwk,
 *   kid: string,
 *   issuerDid?: string, vct?: string, statusUri?: string, iat?: number,
 * }} p
 * @returns {Promise<string>} compact SD-JWT with all disclosures
 */
export async function issueCredential(p) {
  assertCertificate(p.certificate);
  const c = p.certificate;
  const holder = publicOf(p.holderPublicJwk);
  const sdjwt = new SDJwtVcInstance({
    signer: signerFor(p.issuerPrivateJwk), signAlg: 'EdDSA', hasher, hashAlg: 'sha-256', saltGenerator,
  });
  const payload = {
    iss: p.issuerDid ?? ISSUER_DID,
    sub: didKeyFromJwk(holder),
    vct: p.vct ?? VCT,
    iat: p.iat ?? Math.floor(Date.now() / 1000),
    status: { status_list: { idx: p.statusIndex, uri: p.statusUri ?? STATUS_LIST_URI } },
    cnf: { jwk: holder },
    qualified: c.qualified,
    paper: c.paper,
    stage: c.stage,
    exam_session: c.exam_session,
    issuing_body: ISSUING_BODY,
    certificate_commitment: certificateCommitment(c),
    name: c.name,
    roll_no: c.roll_no,
    dob: c.dob,
    category: c.category,
    mother_name: c.mother_name,
    father_or_husband_name: c.father_or_husband_name,
    marks: c.marks,
  };
  return sdjwt.issue(payload, { _sd: DISCLOSABLE }, { header: { kid: p.kid } });
}

/**
 * Verifies the issuer signature of an SD-JWT VC (or a presentation of one) against the issuer's did:web document,
 * and returns the issuer-signed claims with the disclosed claims applied. Status is checked separately.
 * @param {string} encoded
 * @param {{ didFetch?: import('web-did-resolver').WebDidFetch, expectedIssuer?: string }} [options]
 * @returns {Promise<{ payload: Record<string, any>, header: Record<string, any> }>}
 */
export async function verifyCredential(encoded, options = {}) {
  const decoded = await decodeSdJwt(encoded, hasher);
  const header = decoded.jwt.header ?? {};
  const iss = decoded.jwt.payload?.iss;
  if (typeof iss !== 'string') throw new Error('credential has no issuer');
  if (options.expectedIssuer && iss !== options.expectedIssuer) throw new Error('credential issuer is not the expected issuer');
  if (typeof header.kid !== 'string') throw new Error('credential header has no kid');
  const issuerKey = await resolveIssuerKey(iss, header.kid, { fetch: options.didFetch });
  const sdjwt = new SDJwtVcInstance({ verifier: verifierFor(issuerKey), hasher, hashAlg: 'sha-256' });
  const result = await sdjwt.verify(encoded, { disableStatusVerification: true, allowedIssuerAlgorithms: ['EdDSA'] });
  return { payload: result.payload, header: result.header ?? {} };
}
