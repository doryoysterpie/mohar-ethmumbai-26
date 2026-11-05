import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { randomBytes } from 'node:crypto';
import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import { generateEd25519, didKeyFromJwk, verifierFor, signerFor } from '../src/shared/keys.mjs';
import { signJws, decodeJws } from '../src/shared/jws.mjs';
import { didDocument } from '../src/issuer/did-web.mjs';
import { issueCredential, hasher } from '../src/issuer/credential.mjs';
import { ISSUER_DID, VCT, STATUS_LIST_URI } from '../src/issuer/profile.mjs';
import { signConsent, consentHash, verifyConsent, didKeyKid, CONSENT_TYP, academicYearEnd } from '../src/holder/consent.mjs';
import { buildPresentation } from '../src/holder/presentation.mjs';

const cert = JSON.parse(fs.readFileSync(new URL('../fixtures/certificates/teacher-a.json', import.meta.url), 'utf8'));
const NONCE = 'nonce-0123456789abcdef';
const NOW = new Date('2026-11-06T10:00:00Z');

async function setup() {
  const issuer = await generateEd25519();
  const holder = await generateEd25519();
  const school = await generateEd25519();
  const { kid, document } = didDocument(ISSUER_DID, issuer.publicJwk);
  const didFetch = async () => ({ status: 200, json: async () => document });
  const credential = await issueCredential({
    certificate: cert, holderPublicJwk: holder.publicJwk, statusIndex: 0, issuerPrivateJwk: issuer.privateJwk, kid,
  });
  const holderDid = didKeyFromJwk(holder.publicJwk);
  const aud = didKeyFromJwk(school.publicJwk);
  const consent = await signConsent({ holderDid, holderPrivateJwk: holder.privateJwk, schoolDid: aud, now: NOW });
  const present = (over = {}) => buildPresentation({
    credential, consent, holderPrivateJwk: holder.privateJwk, nonce: NONCE, aud, now: NOW, didFetch, ...over,
  });
  return { issuer, holder, school, credential, holderDid, aud, consent, present, kid };
}

test('key binding carries aud, nonce, iat, consent_hash and verifies with the holder key', async () => {
  const { issuer, holder, aud, consent, present } = await setup();
  const presentation = await present();
  const v = new SDJwtVcInstance({ hasher, hashAlg: 'sha-256', verifier: verifierFor(issuer.publicJwk), kbVerifier: verifierFor(holder.publicJwk) });
  const r = await v.verify(presentation, {
    disableStatusVerification: true, keyBindingNonce: NONCE, expectedKeyBindingAudience: aud, currentDate: Math.floor(NOW.getTime() / 1000),
  });
  assert.equal(r.kb.payload.aud, aud);
  assert.equal(r.kb.payload.nonce, NONCE);
  assert.equal(r.kb.payload.iat, Math.floor(NOW.getTime() / 1000));
  assert.equal(r.kb.payload.consent_hash, consentHash(consent));
  assert.equal(typeof r.kb.payload.sd_hash, 'string');
  assert.equal(r.kb.header.typ, 'kb+jwt');
});

test('the key binding does not verify under another holder key', async () => {
  const { issuer, aud, present } = await setup();
  const other = await generateEd25519();
  const v = new SDJwtVcInstance({ hasher, hashAlg: 'sha-256', verifier: verifierFor(issuer.publicJwk), kbVerifier: verifierFor(other.publicJwk) });
  await assert.rejects(v.verify(await present(), { disableStatusVerification: true, keyBindingNonce: NONCE, expectedKeyBindingAudience: aud }));
});

test('no presentation without a consent signed by the holder', async () => {
  const { present, consent, school, holderDid } = await setup();
  await assert.rejects(present({ consent: 'not.a.consent' }));
  await assert.rejects(present({ consent: '' }));
  const { payload } = decodeJws(consent);
  const forged = await signJws(payload, { typ: CONSENT_TYP, kid: didKeyKid(holderDid) }, school.privateJwk);
  await assert.rejects(present({ consent: forged }), /signature invalid/);
});

test('a consent widened after signing is refused', async () => {
  const { present, consent, holder, holderDid } = await setup();
  const { payload } = decodeJws(consent);
  const widened = await signJws({ ...payload, purpose: 'marketing' }, { typ: CONSENT_TYP, kid: didKeyKid(holderDid) }, holder.privateJwk);
  await assert.rejects(present({ consent: widened }), /purpose/);
});

test('a consent for another school is refused', async () => {
  const { present } = await setup();
  const other = await generateEd25519();
  await assert.rejects(present({ aud: didKeyFromJwk(other.publicJwk) }), /not for this school/);
});

test('a consent from another holder is refused', async () => {
  const { present, aud } = await setup();
  const other = await generateEd25519();
  const consent = await signConsent({ holderDid: didKeyFromJwk(other.publicJwk), holderPrivateJwk: other.privateJwk, schoolDid: aud, now: NOW });
  await assert.rejects(present({ consent }), /not given by this holder/);
});

test('an expired consent is refused', async () => {
  const { present } = await setup();
  await assert.rejects(present({ now: new Date('2027-04-01T00:00:01Z') }), /expired/);
});

test('a credential issued to another holder is refused', async () => {
  const { present, issuer } = await setup();
  const other = await generateEd25519();
  const { kid } = didDocument(ISSUER_DID, issuer.publicJwk);
  const credential = await issueCredential({
    certificate: cert, holderPublicJwk: other.publicJwk, statusIndex: 0, issuerPrivateJwk: issuer.privateJwk, kid,
  });
  await assert.rejects(present({ credential }), /subject is not this holder/);
});

test('a credential naming this holder but bound to another key is refused', async () => {
  const { present, issuer, kid, holderDid } = await setup();
  const other = await generateEd25519();
  const sdjwt = new SDJwtVcInstance({ signer: signerFor(issuer.privateJwk), signAlg: 'EdDSA', hasher, hashAlg: 'sha-256', saltGenerator: (n) => randomBytes(n).toString('base64url') });
  const credential = await sdjwt.issue({
    iss: ISSUER_DID, sub: holderDid, vct: VCT, iat: 1, status: { status_list: { idx: 0, uri: STATUS_LIST_URI } },
    cnf: { jwk: { kty: 'OKP', crv: 'Ed25519', x: other.publicJwk.x } },
    qualified: true, paper: 'I', stage: 'primary', exam_session: 'JULY 2024', issuing_body: 'CBSE (simulated)', certificate_commitment: 'x', name: 'n',
  }, { _sd: ['qualified', 'paper', 'stage', 'exam_session', 'issuing_body', 'certificate_commitment', 'name'] }, { header: { kid } });
  await assert.rejects(present({ credential }), /not bound to this holder/);
});

test('a credential of another type is refused', async () => {
  const s = await setup();
  const other = await issueCredential({
    certificate: cert, holderPublicJwk: s.holder.publicJwk, statusIndex: 0, issuerPrivateJwk: s.issuer.privateJwk, kid: s.kid, vct: 'https://example.test/other/v1',
  });
  await assert.rejects(s.present({ credential: other }), /not an eligibility credential/);
});

test('a short nonce is refused', async () => {
  const { present } = await setup();
  await assert.rejects(present({ nonce: '123' }), /nonce/);
});

test('a consent whose times are not canonical ISO 8601 UTC is refused', async () => {
  const { consent, holder, holderDid } = await setup();
  const { payload } = decodeJws(consent);
  for (const [field, value] of [['valid_until', 'April 1, 2027 00:00:00 UTC'], ['valid_until', '2027-03-31T23:59:59Z'], ['granted_at', 'Nov 6, 2026'], ['valid_until', '2027-02-30T00:00:00.000Z']]) {
    const odd = await signJws({ ...payload, [field]: value }, { typ: CONSENT_TYP, kid: didKeyKid(holderDid) }, holder.privateJwk);
    await assert.rejects(verifyConsent(odd, { at: NOW }), new RegExp(`${field} must be an ISO 8601`), `${field}=${value}`);
  }
  const backwards = await signJws({ ...payload, valid_until: '2026-01-01T00:00:00.000Z' }, { typ: CONSENT_TYP, kid: didKeyKid(holderDid) }, holder.privateJwk);
  await assert.rejects(verifyConsent(backwards, { at: NOW }), /ends before it is granted/);
});

test('consent runs to the end of the academic year', async () => {
  const { consent } = await setup();
  const c = await verifyConsent(consent, { at: NOW });
  assert.equal(c.valid_until, academicYearEnd(NOW).toISOString());
  assert.equal(c.valid_until, '2027-03-31T23:59:59.000Z');
  assert.equal(c.recheck_scope, 'status_only');
  assert.equal(c.withdrawable, true);
});
