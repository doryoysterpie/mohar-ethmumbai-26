import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import { decodeSdJwt } from '@sd-jwt/core';
import { signerFor, publicOf, didKeyFromJwk } from '../shared/keys.mjs';
import { hasher } from '../issuer/credential.mjs';
import { verifyConsent, consentHash } from './consent.mjs';

/**
 * Builds a presentation of `credential` that discloses exactly the claims in the consent's scope,
 * with a key-binding JWT carrying `aud` (the school), `nonce` (from the school), `iat` and `consent_hash`.
 * Refuses when the consent is not the holder's, is not for this school, or is not valid now,
 * or when the credential is not bound to the holder's key.
 * @param {{ credential: string, consent: string, holderPrivateJwk: import('../shared/keys.mjs').Ed25519Jwk,
 *   nonce: string, aud: string, now?: Date }} p
 * @returns {Promise<string>}
 */
export async function buildPresentation(p) {
  if (typeof p.nonce !== 'string' || p.nonce.length < 16) throw new Error('nonce must be a string of at least 16 characters');
  const now = p.now ?? new Date();
  const holderPublic = publicOf(p.holderPrivateJwk);
  const holderDid = didKeyFromJwk(holderPublic);
  const consent = await verifyConsent(p.consent, { at: now });
  if (consent.data_principal !== holderDid) throw new Error('consent was not given by this holder');
  if (consent.data_fiduciary !== p.aud) throw new Error('consent is not for this school');

  const decoded = await decodeSdJwt(p.credential, hasher);
  const cnf = /** @type {any} */ (decoded.jwt.payload)?.cnf?.jwk;
  if (!cnf || cnf.x !== holderPublic.x) throw new Error('credential is not bound to this holder key');
  if (decoded.kbJwt) throw new Error('credential already carries a key binding');

  const available = new Set(decoded.disclosures.map((d) => d.key));
  const missing = consent.scope.filter((c) => !available.has(c));
  if (missing.length) throw new Error(`credential cannot disclose ${missing.join(', ')}`);

  const frame = Object.fromEntries(consent.scope.map((c) => [c, true]));
  const sdjwt = new SDJwtVcInstance({ hasher, hashAlg: 'sha-256', kbSigner: signerFor(p.holderPrivateJwk), kbSignAlg: 'EdDSA' });
  return sdjwt.present(p.credential, frame, {
    kb: {
      payload: /** @type {any} */ ({
        aud: p.aud, nonce: p.nonce, iat: Math.floor(now.getTime() / 1000), consent_hash: consentHash(p.consent),
      }),
    },
  });
}

/**
 * Claim names disclosed by a presentation (or credential), without verifying it.
 * @param {string} encoded
 * @returns {Promise<string[]>}
 */
export async function disclosedClaims(encoded) {
  const decoded = await decodeSdJwt(encoded, hasher);
  return decoded.disclosures.map((d) => d.key).filter((k) => typeof k === 'string');
}
