import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import { decodeSdJwt } from '@sd-jwt/core';
import { signerFor, publicOf, didKeyFromJwk } from '../shared/keys.mjs';
import { hasher, verifyCredential } from '../issuer/credential.mjs';
import { ISSUER_DID, VCT, STATUS_LIST_URI } from '../issuer/profile.mjs';
import { assertCredentialShape, assertDisclosures } from '../issuer/shape.mjs';
import { verifyConsent, consentHash } from './consent.mjs';

/**
 * Builds a presentation of `credential` that discloses exactly the claims in the consent's scope,
 * with a key-binding JWT carrying `aud` (the school), `nonce` (from the school), `iat` and `consent_hash`.
 * Refuses when the consent is not the holder's, is not for this school, or is not valid now; when the credential's
 * always-visible payload is not exactly the eligibility-credential shape (nested members included), a disclosed value
 * is not of its allowed type, or the credential does not verify against the expected issuer.
 * @param {{ credential: string, consent: string, holderPrivateJwk: import('../shared/keys.mjs').Ed25519Jwk,
 *   nonce: string, aud: string, now?: Date, expectedIssuer?: string, expectedVct?: string, expectedStatusUri?: string,
 *   didFetch?: import('web-did-resolver').WebDidFetch }} p
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
  if (decoded.kbJwt) throw new Error('credential already carries a key binding');
  // Everything that stays visible in the presentation, and every value it discloses, must match the profile exactly.
  assertCredentialShape(decoded.jwt.payload ?? {}, {
    issuer: p.expectedIssuer ?? ISSUER_DID,
    vct: p.expectedVct ?? VCT,
    statusUri: p.expectedStatusUri ?? STATUS_LIST_URI,
    holderDid,
    holderX: holderPublic.x,
  });
  assertDisclosures(decoded.disclosures, consent.scope);
  try {
    await verifyCredential(p.credential, { didFetch: p.didFetch, expectedIssuer: p.expectedIssuer ?? ISSUER_DID });
  } catch (e) {
    throw new Error(`credential does not verify against the expected issuer: ${e.message}`);
  }

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
