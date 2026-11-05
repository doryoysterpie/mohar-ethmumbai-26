import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import { generateEd25519, didKeyFromJwk, jwkFromDidKey, signerFor } from '../src/shared/keys.mjs';
import { randomBytes } from 'node:crypto';
import { hasher, issueCredential } from '../src/issuer/credential.mjs';
import { ISSUER_DID, VCT, STATUS_LIST_URI } from '../src/issuer/profile.mjs';
import { CONSENT_SCOPE, didKeyKid } from '../src/holder/consent.mjs';
import { decodeJws, verifyJws, signJws } from '../src/shared/jws.mjs';
import { sha256Hex } from '../src/shared/encoding.mjs';
import { saltedCommitment } from '../src/shared/commitment.mjs';
import { signConsent } from '../src/holder/consent.mjs';
import { RECEIPT_TYP, RECHECK_TYP } from '../src/verifier/school.mjs';
import { world, logServer, cert } from './helpers/world.mjs';

const receiptOf = (r) => decodeJws(r.receipt).payload;

test('issuer-signature failure yields a refusal and no receipt', async () => {
  const w = await world();
  const forger = await generateEd25519();
  const presentation = await w.rawPresent({ credential: await w.credential(0, forger.privateJwk) });
  const r = await w.school.present({ presentation, consent: w.consent });
  assert.equal(r.ok, false);
  assert.equal(r.refusal, 'issuer_signature_invalid');
  assert.equal(r.receipt, undefined);
  assert.equal(w.receiptCount(), 0);
  assert.equal(w.store.refusals()[0].presentation_hash, sha256Hex(presentation));
});

test('a replayed nonce is refused', async () => {
  const w = await world();
  const presentation = await w.present();
  assert.equal((await w.school.present({ presentation, consent: w.consent })).ok, true);
  const again = await w.school.present({ presentation, consent: w.consent });
  assert.deepEqual([again.ok, again.refusal], [false, 'nonce_stale']);
  assert.equal(w.receiptCount(), 1);
});

test('a nonce the school never issued, or one that expired, is refused', async () => {
  const w = await world();
  const made = await w.school.present({ presentation: await w.present({ nonce: 'never-issued-0123456789' }), consent: w.consent });
  assert.equal(made.refusal, 'nonce_stale');
  const nonce = w.school.nonce().nonce;
  w.now = new Date(w.now.getTime() + 601_000);
  const late = await w.school.present({ presentation: await w.present({ nonce }), consent: w.consent });
  assert.equal(late.refusal, 'nonce_stale');
  assert.match(late.detail, /expired/);
});

test('receipt presentation_hash is the SHA-256 of the presentation exactly as received', async () => {
  const w = await world();
  const presentation = await w.present();
  const r = await w.school.present({ presentation, consent: w.consent });
  assert.equal(receiptOf(r).presentation_hash, sha256Hex(presentation));
  assert.equal(receiptOf(r).consent_hash, sha256Hex(w.consent));
});

test('the receipt verifies against the school did:key', async () => {
  const w = await world();
  const r = await w.school.present({ presentation: await w.present(), consent: w.consent });
  const { header, payload } = await verifyJws(r.receipt, jwkFromDidKey(w.school.did), RECEIPT_TYP);
  assert.equal(header.kid.split('#')[0], w.school.did);
  assert.equal(payload.verifier, w.school.did);
  assert.equal(payload.issuer_sig_valid, true);
  assert.equal(payload.key_binding_valid, true);
  assert.equal(payload.recheck_due, '2027-01-01T00:00:00.000Z');
});

test('status on the receipt is not_revoked or unknown; revoked is refused', async () => {
  const w = await world();
  const clear = await w.school.present({ presentation: await w.present({ statusIndex: 0 }), consent: w.consent });
  assert.equal(receiptOf(clear).status_result, 'not_revoked');
  w.listDown = true;
  const down = await w.school.present({ presentation: await w.present({ statusIndex: 0 }), consent: w.consent });
  assert.equal(receiptOf(down).status_result, 'unknown');
  w.listDown = false;
  const revoked = await w.school.present({ presentation: await w.present({ statusIndex: 1 }), consent: w.consent });
  assert.deepEqual([revoked.ok, revoked.refusal], [false, 'status_revoked']);
  assert.equal(w.receiptCount(), 2);
});

test('a revoked index flips to revoked with alert true at the term check, and the re-check is logged', async () => {
  const log = await logServer();
  try {
    const w = await world({ logUrl: log.url });
    const r = await w.school.present({ presentation: await w.present({ statusIndex: 0 }), consent: w.consent });
    w.now = new Date('2027-01-01T00:00:00Z');
    w.statuses = [1, 1, 0];
    const [rc] = await w.school.recheck();
    const { payload } = await verifyJws(rc.recheck, jwkFromDidKey(w.school.did), RECHECK_TYP);
    assert.equal(payload.receipt_id, r.receipt_id);
    assert.equal(payload.status_result, 'revoked');
    assert.equal(payload.alert, true);
    assert.equal(payload.next_recheck_due, '2027-10-01T00:00:00.000Z');
    const logged = log.bodies.find((b) => b.entry_type === 'recheck');
    const { recheck_salt: salt } = w.store.db.prepare('SELECT recheck_salt FROM rechecks WHERE recheck_id = ?').get(rc.recheck_id);
    assert.equal(logged.commitment, saltedCommitment(rc.recheck, salt));
    assert.notEqual(logged.commitment, sha256Hex(rc.recheck));
    const s = w.school.status(w.holderDid);
    assert.deepEqual([s.status_result, s.alert], ['revoked', true]);
  } finally {
    log.close();
  }
});

test('an unchanged clear status re-checks with alert false; a change from unknown raises alert', async () => {
  const w = await world();
  await w.school.present({ presentation: await w.present({ statusIndex: 0 }), consent: w.consent });
  w.now = new Date('2027-01-01T00:00:00Z');
  assert.equal((await w.school.recheck())[0].alert, false);
  w.listDown = true;
  w.now = new Date('2027-01-02T00:00:00Z');
  const [down] = await w.school.recheck();
  assert.deepEqual([down.status_result, down.alert], ['unknown', true]);
});

test('the term check skips receipts whose consent has ended', async () => {
  const w = await world();
  await w.school.present({ presentation: await w.present(), consent: w.consent });
  w.now = new Date('2027-04-01T00:00:00Z');
  assert.deepEqual(await w.school.recheck(), []);
});

test('a key binding for another school is refused', async () => {
  const w = await world();
  const other = await generateEd25519();
  const otherDid = didKeyFromJwk(other.publicJwk);
  const consent = await signConsent({ holderDid: w.holderDid, holderPrivateJwk: w.holder.privateJwk, schoolDid: otherDid, now: w.now });
  const presentation = await w.present({ consent, aud: otherDid });
  const r = await w.school.present({ presentation, consent });
  assert.equal(r.refusal, 'key_binding_invalid');
});

test('a consent other than the one the key binding names is refused', async () => {
  const w = await world();
  const presentation = await w.present();
  const other = await signConsent({ holderDid: w.holderDid, holderPrivateJwk: w.holder.privateJwk, schoolDid: w.school.did, now: w.now });
  const r = await w.school.present({ presentation, consent: other });
  assert.equal(r.refusal, 'consent_mismatch');
});

test('a consent that does not cover what the receipt needs is refused as scope_insufficient', async () => {
  const w = await world();
  const narrow = await signConsent({ holderDid: w.holderDid, holderPrivateJwk: w.holder.privateJwk, schoolDid: w.school.did, now: w.now, scope: ['qualified', 'paper'] });
  const r = await w.school.present({ presentation: await w.present({ consent: narrow }), consent: narrow });
  assert.equal(r.refusal, 'scope_insufficient');
});

test('a disclosure appended after key binding breaks the key binding', async () => {
  const w = await world();
  const credential = await w.credential(0);
  const presentation = await w.present({ credential });
  const roll = credential.split('~').slice(1, -1).find((d) => JSON.parse(Buffer.from(d, 'base64url'))[1] === 'roll_no');
  const parts = presentation.split('~');
  const widened = [...parts.slice(0, -1), roll, parts.at(-1)].join('~');
  const r = await w.school.present({ presentation: widened, consent: w.consent });
  assert.equal(r.refusal, 'key_binding_invalid');
});

test('a disclosure from another credential fails the digest check', async () => {
  const w = await world();
  const presentation = await w.present({ credential: await w.credential(0) });
  const roll = (await w.credential(0)).split('~').slice(1, -1).find((d) => JSON.parse(Buffer.from(d, 'base64url'))[1] === 'roll_no');
  const parts = presentation.split('~');
  const r = await w.school.present({ presentation: [...parts.slice(0, -1), roll, parts.at(-1)].join('~'), consent: w.consent });
  assert.equal(r.refusal, 'issuer_signature_invalid');
});

test('a key binding signed by a key other than the credential holder key is refused', async () => {
  const w = await world();
  const thief = await generateEd25519();
  const sdjwt = new SDJwtVcInstance({ hasher, hashAlg: 'sha-256', kbSigner: signerFor(thief.privateJwk), kbSignAlg: 'EdDSA' });
  const presentation = await sdjwt.present(await w.credential(0), Object.fromEntries(CONSENT_SCOPE.map((c) => [c, true])), {
    kb: { payload: { aud: w.school.did, nonce: w.school.nonce().nonce, iat: Math.floor(w.now.getTime() / 1000), consent_hash: sha256Hex(w.consent) } },
  });
  const r = await w.school.present({ presentation, consent: w.consent });
  assert.equal(r.refusal, 'key_binding_invalid');
  assert.equal(w.receiptCount(), 0);
});

test('a key-bound presentation disclosing beyond the consent is refused', async () => {
  const w = await world();
  const sdjwt = new SDJwtVcInstance({ hasher, hashAlg: 'sha-256', kbSigner: signerFor(w.holder.privateJwk), kbSignAlg: 'EdDSA' });
  const frame = Object.fromEntries([...CONSENT_SCOPE, 'roll_no'].map((c) => [c, true]));
  const presentation = await sdjwt.present(await w.credential(0), frame, {
    kb: { payload: { aud: w.school.did, nonce: w.school.nonce().nonce, iat: Math.floor(w.now.getTime() / 1000), consent_hash: sha256Hex(w.consent) } },
  });
  const r = await w.school.present({ presentation, consent: w.consent });
  assert.equal(r.refusal, 'consent_mismatch');
  assert.match(r.detail, /roll_no/);
  assert.equal(w.receiptCount(), 0);
});

test('every refusal is one of the typed reasons and leaves no receipt', async () => {
  const w = await world();
  for (const body of [{}, { presentation: 'x~', consent: w.consent }, { presentation: await w.present(), consent: 'nope' }]) {
    const r = await w.school.present(body);
    assert.equal(r.ok, false);
    assert.ok(['issuer_signature_invalid', 'key_binding_invalid', 'nonce_stale', 'consent_mismatch', 'status_revoked', 'scope_insufficient'].includes(r.refusal), r.refusal);
  }
  assert.equal(w.receiptCount(), 0);
});

test('a malformed key binding is a typed refusal, stored, with no receipt', async () => {
  const w = await world();
  const parts = (await w.present()).split('~');
  const presentation = [...parts.slice(0, -1), 'not-a-compact-jwt'].join('~');
  const r = await w.school.present({ presentation, consent: w.consent });
  assert.deepEqual([r.ok, r.refusal], [false, 'key_binding_invalid']);
  assert.equal(w.receiptCount(), 0);
  const rows = w.store.refusals();
  assert.equal(rows.length, 1);
  assert.equal(rows[0].presentation_hash, sha256Hex(presentation));
  assert.equal(rows[0].reason, 'key_binding_invalid');
});

test('a presentation that omits a consented claim is refused', async () => {
  const w = await world();
  const presentation = await w.rawPresent({ claims: CONSENT_SCOPE.filter((c) => c !== 'name') });
  const r = await w.school.present({ presentation, consent: w.consent });
  assert.equal(r.refusal, 'consent_mismatch');
  assert.match(r.detail, /consented but not disclosed: name/);
  assert.equal(w.receiptCount(), 0);
});

test('a consent with a non-canonical end date is refused, so no re-check can run past it', async () => {
  const w = await world();
  const { payload } = decodeJws(w.consent);
  const odd = await signJws({ ...payload, valid_until: 'April 1, 2027 00:00:00 UTC' }, { typ: 'consent+jwt', kid: didKeyKid(w.holderDid) }, w.holder.privateJwk);
  const r = await w.school.present({ presentation: await w.rawPresent({ consent: odd }), consent: odd });
  assert.equal(r.refusal, 'consent_mismatch');
  assert.match(r.detail, /valid_until must be an ISO 8601/);
  w.now = new Date('2028-01-01T00:00:00.000Z');
  assert.deepEqual(await w.school.recheck(), []);
});

test('an issuer clock up to 60 s ahead of the school is tolerated; further ahead is refused', async () => {
  const w = await world();
  const at = (ahead) => issueCredential({
    certificate: cert, holderPublicJwk: w.holder.publicJwk, statusIndex: 0, issuerPrivateJwk: w.issuer.privateJwk, kid: w.kid,
    iat: Math.floor(w.now.getTime() / 1000) + ahead,
  });
  assert.equal((await w.school.present({ presentation: await w.rawPresent({ credential: await at(59) }), consent: w.consent })).ok, true);
  const late = await w.school.present({ presentation: await w.rawPresent({ credential: await at(120) }), consent: w.consent });
  assert.equal(late.refusal, 'issuer_signature_invalid');
});

test('a validly signed credential with data nested in a visible container is refused by the school', async () => {
  const w = await world();
  const sdjwt = new SDJwtVcInstance({ signer: signerFor(w.issuer.privateJwk), signAlg: 'EdDSA', hasher, hashAlg: 'sha-256', saltGenerator: (n) => randomBytes(n).toString('base64url') });
  const claims = { qualified: true, paper: 'I', stage: 'primary', exam_session: 'JULY 2024', issuing_body: 'CBSE (simulated)', certificate_commitment: 'a'.repeat(64), name: 'A [SIMULATED]' };
  const credential = await sdjwt.issue({
    iss: ISSUER_DID, sub: w.holderDid, vct: VCT, iat: Math.floor(w.now.getTime() / 1000) - 10,
    status: { status_list: { idx: 0, uri: STATUS_LIST_URI, roll_no: 'SIM-2024-100001' } },
    cnf: { jwk: { kty: 'OKP', crv: 'Ed25519', x: w.holder.publicJwk.x } }, ...claims,
  }, { _sd: Object.keys(claims) }, { header: { kid: w.kid } });
  const r = await w.school.present({ presentation: await w.rawPresent({ credential }), consent: w.consent });
  assert.equal(r.refusal, 'consent_mismatch');
  assert.match(r.detail, /outside the credential profile/);
  assert.equal(w.receiptCount(), 0);
});
