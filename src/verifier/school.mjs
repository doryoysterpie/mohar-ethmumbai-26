import { randomUUID } from 'node:crypto';
import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import { decodeSdJwt } from '@sd-jwt/core';
import { sha256Hex } from '../shared/encoding.mjs';
import { didKeyFromJwk, publicOf, verifierFor } from '../shared/keys.mjs';
import { signJws } from '../shared/jws.mjs';
import { hasher, verifyCredential } from '../issuer/credential.mjs';
import { checkStatus } from '../issuer/status-list.mjs';
import { ISSUER_DID } from '../issuer/profile.mjs';
import { resolveIssuerKey } from '../issuer/did-web.mjs';
import { verifyConsent, didKeyKid } from '../holder/consent.mjs';
import { commitRecord } from '../log/client.mjs';
import { nextTermBoundary } from './calendar.mjs';

export const RECEIPT_TYP = 'receipt+jwt';
export const RECHECK_TYP = 'recheck+jwt';

export const REFUSALS = [
  'issuer_signature_invalid', 'key_binding_invalid', 'nonce_stale', 'consent_mismatch', 'status_revoked', 'scope_insufficient',
];

/** Claims the school needs disclosed to sign a receipt. */
export const REQUIRED_CLAIMS = ['qualified', 'paper', 'stage', 'exam_session', 'issuing_body', 'certificate_commitment'];

/** Disclosed claims copied onto the receipt. The receipt carries no name and no identity. */
export const RECEIPT_CLAIMS = ['qualified', 'paper', 'stage', 'exam_session', 'issuing_body'];

class Refusal extends Error {
  constructor(reason, detail) { super(detail); this.reason = reason; }
}

/**
 * The school verifier.
 * @param {{
 *   store: ReturnType<typeof import('./store.mjs').openStore>,
 *   schoolPrivateJwk: import('../shared/keys.mjs').Ed25519Jwk,
 *   trustedIssuers?: string[],
 *   didFetch?: import('web-did-resolver').WebDidFetch,
 *   fetchText?: (uri: string) => Promise<string>,
 *   logUrl?: string,
 *   logFetch?: typeof fetch,
 *   clock?: () => Date,
 *   keyBindingMaxAgeSeconds?: number,
 * }} config
 */
export function createSchool(config) {
  const { store } = config;
  const did = didKeyFromJwk(publicOf(config.schoolPrivateJwk));
  const kid = didKeyKid(did);
  const trusted = config.trustedIssuers ?? [ISSUER_DID];
  const clock = config.clock ?? (() => new Date());
  const kbMaxAge = config.keyBindingMaxAgeSeconds ?? 300;
  const seconds = (d) => Math.floor(d.getTime() / 1000);

  async function log(entryType, record) {
    if (!config.logUrl) return { commitment: sha256Hex(record), posted: false };
    try {
      const { commitment } = await commitRecord({ logUrl: config.logUrl, entryType, record, fetch: config.logFetch });
      return { commitment, posted: true };
    } catch (e) {
      return { commitment: sha256Hex(record), posted: false, error: e.message };
    }
  }

  /**
   * Runs every check on a presentation and its consent. Throws a Refusal on the first failure.
   * The nonce is consumed only after the key binding has verified.
   */
  async function check(presentation, consent, now) {
    if (typeof presentation !== 'string' || !presentation.includes('~')) throw new Refusal('issuer_signature_invalid', 'not an SD-JWT presentation');
    if (typeof consent !== 'string') throw new Refusal('consent_mismatch', 'no consent record');

    // Issuer signature and disclosure digests, on the SD-JWT without its key binding.
    const sdOnly = presentation.slice(0, presentation.lastIndexOf('~') + 1);
    let credential;
    try {
      credential = await verifyCredential(sdOnly, { didFetch: config.didFetch });
    } catch (e) {
      throw new Refusal('issuer_signature_invalid', e.message);
    }
    if (!trusted.includes(credential.payload.iss)) throw new Refusal('issuer_signature_invalid', 'issuer is not trusted by this school');

    // Key binding: signed by the credential's cnf key, for this school, fresh, over this SD-JWT.
    const decoded = await decodeSdJwt(presentation, hasher);
    const kbPayload = decoded.kbJwt?.payload;
    if (!kbPayload) throw new Refusal('key_binding_invalid', 'presentation has no key binding');
    const cnf = credential.payload.cnf?.jwk;
    if (!cnf) throw new Refusal('key_binding_invalid', 'credential has no holder key');
    let issuerKey;
    try {
      issuerKey = await resolveIssuerKey(credential.payload.iss, String(credential.header.kid), { fetch: config.didFetch });
    } catch (e) {
      throw new Refusal('issuer_signature_invalid', e.message);
    }
    const kbCheck = new SDJwtVcInstance({ hasher, hashAlg: 'sha-256', verifier: verifierFor(issuerKey), kbVerifier: verifierFor(cnf) });
    try {
      await kbCheck.verify(presentation, {
        disableStatusVerification: true,
        keyBindingNonce: String(kbPayload.nonce),
        expectedKeyBindingAudience: did,
        keyBindingMaxAgeSeconds: kbMaxAge,
        allowedKeyBindingAlgorithms: ['EdDSA'],
        currentDate: seconds(now),
      });
    } catch (e) {
      throw new Refusal('key_binding_invalid', e.message);
    }
    if (kbPayload.aud !== did) throw new Refusal('key_binding_invalid', 'key binding is for another audience');

    // Consent: valid now, given by the credential's holder to this school, and the one the key binding names.
    let c;
    try {
      c = await verifyConsent(consent, { at: now });
    } catch (e) {
      throw new Refusal('consent_mismatch', e.message);
    }
    if (kbPayload.consent_hash !== sha256Hex(consent)) throw new Refusal('consent_mismatch', 'key binding names another consent');
    if (c.data_fiduciary !== did) throw new Refusal('consent_mismatch', 'consent is for another school');
    if (c.data_principal !== credential.payload.sub) throw new Refusal('consent_mismatch', 'consent is not from the credential holder');

    // Disclosures: exactly the consented claims, including what the receipt needs.
    const disclosed = decoded.disclosures.map((d) => d.key).filter((k) => typeof k === 'string');
    const extra = disclosed.filter((k) => !c.scope.includes(k));
    if (extra.length) throw new Refusal('consent_mismatch', `disclosed outside consent: ${extra.join(', ')}`);
    const missing = REQUIRED_CLAIMS.filter((k) => !disclosed.includes(k));
    if (missing.length) throw new Refusal('scope_insufficient', `not disclosed: ${missing.join(', ')}`);

    // Nonce: issued by this school, unused and unexpired. Consumed here, once.
    const n = store.consumeNonce(kbPayload.nonce, seconds(now));
    if (n !== 'ok') throw new Refusal('nonce_stale', `nonce ${n}`);

    return { credential, consent: c };
  }

  return {
    did,

    nonce() {
      return store.issueNonce(seconds(clock()));
    },

    /**
     * Verifies a presentation. Returns a signed receipt, or a typed refusal (stored, with no receipt).
     * @param {{ presentation: string, consent: string }} body
     */
    async present({ presentation, consent }) {
      const now = clock();
      const presentationHash = sha256Hex(typeof presentation === 'string' ? presentation : '');
      let verified;
      try {
        verified = await check(presentation, consent, now);
      } catch (e) {
        if (!(e instanceof Refusal)) throw e;
        store.saveRefusal(presentationHash, e.reason, now.toISOString());
        return { ok: false, refusal: e.reason, detail: e.message };
      }
      const { credential, consent: c } = verified;
      const status = await checkStatus(credential.payload, { fetchText: config.fetchText, didFetch: config.didFetch });
      if (status.result === 'revoked') {
        store.saveRefusal(presentationHash, 'status_revoked', now.toISOString());
        return { ok: false, refusal: 'status_revoked', detail: 'credential is revoked' };
      }
      const receiptId = randomUUID();
      const recheckDue = nextTermBoundary(now);
      const receipt = {
        receipt_id: receiptId,
        verifier: did,
        presentation_hash: presentationHash,
        certificate_commitment: credential.payload.certificate_commitment,
        consent_hash: sha256Hex(consent),
        issuer: credential.payload.iss,
        issuer_sig_valid: true,
        key_binding_valid: true,
        status_result: status.result,
        status_checked_at: now.toISOString(),
        disclosed_claims: Object.fromEntries(RECEIPT_CLAIMS.map((k) => [k, credential.payload[k]])),
        purpose: c.purpose,
        verified_at: now.toISOString(),
        recheck_due: recheckDue.toISOString(),
      };
      const receiptJws = await signJws(receipt, { typ: RECEIPT_TYP, kid }, config.schoolPrivateJwk);
      store.saveReceipt({
        receipt_id: receiptId,
        holder_did: credential.payload.sub,
        presentation,
        consent,
        receipt: receiptJws,
        status_ref: JSON.stringify({ iss: credential.payload.iss, status: credential.payload.status }),
        issuer: credential.payload.iss,
        status_result: status.result,
        verified_at: receipt.verified_at,
        recheck_due: receipt.recheck_due,
        valid_until: c.valid_until,
      });
      return { ok: true, receipt_id: receiptId, receipt: receiptJws, status_reason: status.reason, log: await log('receipt', receiptJws) };
    },

    /** Latest receipt and re-check for a holder, or null. */
    status(holderDid) {
      const r = store.latestReceipt(holderDid);
      if (!r) return null;
      const last = store.latestRecheck(r.receipt_id);
      return {
        receipt_id: r.receipt_id,
        receipt: r.receipt,
        verified_at: r.verified_at,
        status_result: last ? last.status_result : r.status_result,
        status_checked_at: last ? last.checked_at : r.verified_at,
        recheck_due: last ? last.next_recheck_due : r.recheck_due,
        alert: last ? Boolean(last.alert) : false,
        recheck: last ? last.recheck : null,
      };
    },

    /**
     * Term check: re-reads the status of every receipt whose consent is still valid, without a new presentation,
     * and signs a re-check receipt for each. `alert` is true when the result is revoked or differs from the last one.
     */
    async recheck() {
      const now = clock();
      const out = [];
      for (const r of store.activeReceipts(now.toISOString())) {
        const ref = JSON.parse(r.status_ref);
        const status = await checkStatus(ref, { fetchText: config.fetchText, didFetch: config.didFetch });
        const previous = store.latestRecheck(r.receipt_id)?.status_result ?? r.status_result;
        const alert = status.result === 'revoked' || status.result !== previous;
        const next = nextTermBoundary(now);
        const recheck = {
          recheck_id: randomUUID(),
          receipt_id: r.receipt_id,
          verifier: did,
          status_result: status.result,
          status_checked_at: now.toISOString(),
          next_recheck_due: next.toISOString(),
          alert,
        };
        const jws = await signJws(recheck, { typ: RECHECK_TYP, kid }, config.schoolPrivateJwk);
        store.saveRecheck({
          recheck_id: recheck.recheck_id, receipt_id: r.receipt_id, recheck: jws, status_result: status.result,
          checked_at: recheck.status_checked_at, next_recheck_due: recheck.next_recheck_due, alert: alert ? 1 : 0,
        });
        out.push({ ...recheck, recheck: jws, status_reason: status.reason, log: await log('recheck', jws) });
      }
      return out;
    },
  };
}
