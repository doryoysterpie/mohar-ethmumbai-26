import { randomUUID } from 'node:crypto';
import { sha256Hex } from '../shared/encoding.mjs';
import { jwkFromDidKey } from '../shared/keys.mjs';
import { signJws, decodeJws, verifyJws } from '../shared/jws.mjs';
import { NEVER_PRESENTED, DISCLOSABLE } from '../issuer/profile.mjs';

export const CONSENT_TYP = 'consent+jwt';
export const PURPOSE = 'teacher_eligibility_verification';
export const RECORD_SHAPE = 'DPDP-Rules-2025/Rule-4-shaped';

/** Claims a teacher discloses to a school for eligibility verification. */
export const CONSENT_SCOPE = ['qualified', 'paper', 'stage', 'exam_session', 'issuing_body', 'certificate_commitment', 'name'];

/** Month and day (UTC) on which the academic year ends; configurable with MOHAR_ACADEMIC_YEAR_END=MM-DD. */
const YEAR_END = (process.env.MOHAR_ACADEMIC_YEAR_END ?? '03-31').split('-').map(Number);

/**
 * End of the academic year containing `now`, as 23:59:59 UTC on the configured month and day.
 * @param {Date} now
 * @returns {Date}
 */
export function academicYearEnd(now) {
  const [m, d] = YEAR_END;
  const thisYear = new Date(Date.UTC(now.getUTCFullYear(), m - 1, d, 23, 59, 59));
  return now <= thisYear ? thisYear : new Date(Date.UTC(now.getUTCFullYear() + 1, m - 1, d, 23, 59, 59));
}

/** did:key verification method id. */
export const didKeyKid = (did) => `${did}#${did.slice('did:key:'.length)}`;

/**
 * Throws unless `scope` is a non-empty list of disclosable claims that excludes every never-presented claim.
 * @param {unknown} scope
 */
export function assertScope(scope) {
  if (!Array.isArray(scope) || scope.length === 0) throw new Error('consent scope is empty');
  for (const c of scope) {
    if (NEVER_PRESENTED.includes(c)) throw new Error(`consent scope includes ${c}, which is never presented`);
    if (!DISCLOSABLE.includes(c)) throw new Error(`consent scope includes unknown claim ${c}`);
  }
  if (new Set(scope).size !== scope.length) throw new Error('consent scope repeats a claim');
}

/**
 * Signed consent record (compact JWS by the teacher).
 * @param {{ holderDid: string, holderPrivateJwk: import('../shared/keys.mjs').Ed25519Jwk, schoolDid: string,
 *   now?: Date, validUntil?: Date, scope?: string[], withdrawalEndpoint?: string | null }} p
 * @returns {Promise<string>}
 */
export async function signConsent(p) {
  const now = p.now ?? new Date();
  const scope = p.scope ?? CONSENT_SCOPE;
  assertScope(scope);
  if (!p.schoolDid.startsWith('did:key:')) throw new Error('school must be a did:key');
  const record = {
    consent_id: randomUUID(),
    data_principal: p.holderDid,
    data_fiduciary: p.schoolDid,
    purpose: PURPOSE,
    scope,
    recheck_scope: 'status_only',
    granted_at: now.toISOString(),
    valid_until: (p.validUntil ?? academicYearEnd(now)).toISOString(),
    withdrawable: true,
    withdrawal_endpoint: p.withdrawalEndpoint ?? null,
    record_shape: RECORD_SHAPE,
  };
  return signJws(record, { typ: CONSENT_TYP, kid: didKeyKid(p.holderDid) }, p.holderPrivateJwk);
}

/**
 * True for the exact form Date.prototype.toISOString produces (YYYY-MM-DDTHH:MM:SS.sssZ) and only for a real instant,
 * so these strings compare in time order as text.
 */
export function isCanonicalTime(v) {
  if (typeof v !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(v)) return false;
  const t = Date.parse(v);
  return Number.isFinite(t) && new Date(t).toISOString() === v;
}

/** SHA-256 (hex) of the consent record as transmitted. */
export const consentHash = (consentJws) => sha256Hex(consentJws);

/**
 * Verifies a consent record's signature against its data principal and its shape. Returns the record.
 * @param {string} consentJws
 * @param {{ at?: Date }} [options] time at which the consent must be valid
 */
export async function verifyConsent(consentJws, options = {}) {
  const { header, payload: c } = decodeJws(consentJws);
  if (typeof c.data_principal !== 'string') throw new Error('consent has no data principal');
  if (header.kid !== didKeyKid(c.data_principal)) throw new Error('consent is not signed with the data principal key id');
  await verifyJws(consentJws, jwkFromDidKey(c.data_principal), CONSENT_TYP);
  if (c.purpose !== PURPOSE) throw new Error('consent purpose is not eligibility verification');
  if (c.recheck_scope !== 'status_only') throw new Error('consent recheck scope is not status_only');
  if (c.record_shape !== RECORD_SHAPE) throw new Error('consent record shape is not recognised');
  assertScope(c.scope);
  for (const f of ['granted_at', 'valid_until']) {
    if (!isCanonicalTime(c[f])) throw new Error(`consent ${f} must be an ISO 8601 UTC time with milliseconds`);
  }
  if (Date.parse(c.valid_until) < Date.parse(c.granted_at)) throw new Error('consent ends before it is granted');
  const at = options.at ?? new Date();
  if (!(Date.parse(c.granted_at) <= at.getTime())) throw new Error('consent is not yet granted');
  if (!(at.getTime() <= Date.parse(c.valid_until))) throw new Error('consent has expired');
  return c;
}
