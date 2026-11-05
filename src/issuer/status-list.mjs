import {
  StatusList, createHeaderAndPayload, getListFromStatusListJWT, verifyStatusListJwtHeader, verifyStatusListJwtClaims,
} from '@owf/token-status-list';
import { toBase64url, fromBase64url } from '../shared/encoding.mjs';
import { verifierFor } from '../shared/keys.mjs';
import { resolveIssuerKey } from './did-web.mjs';

/** @typedef {'not_revoked' | 'revoked' | 'unknown'} StatusResult */

/**
 * Signed status list token (IETF Token Status List, JWT form, one bit per credential).
 * @param {{ uri: string, statuses: number[], issuerDid: string, kid: string, signer: (data: string) => Promise<string>, iat?: number }} p
 * @returns {Promise<string>}
 */
export async function buildStatusList({ uri, statuses, issuerDid, kid, signer, iat }) {
  const list = new StatusList(statuses, 1);
  const { header, payload } = createHeaderAndPayload(
    list,
    { iss: issuerDid, sub: uri, iat: iat ?? Math.floor(Date.now() / 1000) },
    { alg: 'EdDSA', typ: 'statuslist+jwt', kid },
  );
  const enc = (o) => toBase64url(new TextEncoder().encode(JSON.stringify(o)));
  const signingInput = `${enc(header)}.${enc(payload)}`;
  return `${signingInput}.${await signer(signingInput)}`;
}

/**
 * Fetches a URL as text with a timeout. Rejects on network failure or a non-2xx response.
 * @param {string} uri
 * @returns {Promise<string>}
 */
export async function fetchText(uri) {
  const res = await fetch(uri, { signal: AbortSignal.timeout(10_000) });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.text();
}

/**
 * Status of a credential from its issuer's status list.
 * `unknown` when there is no status reference, the list cannot be fetched, or the list is not validly signed
 * by the credential's issuer; `revoked` when the index is set; `not_revoked` when it is clear.
 * @param {{ iss: string, status?: { status_list?: { idx: number, uri: string } } }} credential issuer-signed payload
 * @param {{ fetchText?: (uri: string) => Promise<string>, didFetch?: import('web-did-resolver').WebDidFetch }} [options]
 * @returns {Promise<{ result: StatusResult, reason?: string }>}
 */
export async function checkStatus(credential, options = {}) {
  const ref = credential.status?.status_list;
  if (!ref || typeof ref.uri !== 'string' || !Number.isInteger(ref.idx) || ref.idx < 0) {
    return { result: 'unknown', reason: 'no status reference' };
  }
  let token;
  try {
    token = await (options.fetchText ?? fetchText)(ref.uri);
  } catch (e) {
    return { result: 'unknown', reason: `status list unreachable: ${e.message}` };
  }
  try {
    const [h, p, s] = token.trim().split('.');
    if (!h || !p || !s) throw new Error('not a compact JWT');
    const header = verifyStatusListJwtHeader(JSON.parse(new TextDecoder().decode(fromBase64url(h))));
    if (header.alg !== 'EdDSA') throw new Error(`unexpected alg ${header.alg}`);
    const kid = /** @type {unknown} */ (header.kid);
    if (typeof kid !== 'string') throw new Error('no kid');
    const payload = JSON.parse(new TextDecoder().decode(fromBase64url(p)));
    if (payload.iss !== credential.iss) throw new Error('status list issuer differs from credential issuer');
    const key = await resolveIssuerKey(credential.iss, kid, { fetch: options.didFetch });
    if (!(await verifierFor(key)(`${h}.${p}`, s))) throw new Error('signature invalid');
    verifyStatusListJwtClaims(payload, { uri: ref.uri, checkFreshness: false });
    const status = getListFromStatusListJWT(token.trim()).getStatus(ref.idx);
    if (status === 0) return { result: 'not_revoked' };
    if (status === 1) return { result: 'revoked' };
    return { result: 'unknown', reason: `unrecognised status value ${status}` };
  } catch (e) {
    return { result: 'unknown', reason: `status list not usable: ${e.message}` };
  }
}
