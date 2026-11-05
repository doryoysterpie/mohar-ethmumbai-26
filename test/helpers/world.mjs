// A simulated issuer, teacher and school wired together in memory, for tests.
import fs from 'node:fs';
import http from 'node:http';
import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import { generateEd25519, didKeyFromJwk, signerFor } from '../../src/shared/keys.mjs';
import { sha256Hex } from '../../src/shared/encoding.mjs';
import { didDocument } from '../../src/issuer/did-web.mjs';
import { issueCredential, hasher } from '../../src/issuer/credential.mjs';
import { buildStatusList } from '../../src/issuer/status-list.mjs';
import { ISSUER_DID, STATUS_LIST_URI } from '../../src/issuer/profile.mjs';
import { signConsent, CONSENT_SCOPE } from '../../src/holder/consent.mjs';
import { buildPresentation } from '../../src/holder/presentation.mjs';
import { openStore } from '../../src/verifier/store.mjs';
import { createSchool } from '../../src/verifier/school.mjs';

export const cert = JSON.parse(fs.readFileSync(new URL('../../fixtures/certificates/teacher-a.json', import.meta.url), 'utf8'));

/** Local HTTP server that records every JSON body posted to it. */
export async function logServer() {
  const bodies = [];
  const server = http.createServer((req, res) => {
    let b = '';
    req.on('data', (c) => { b += c; });
    req.on('end', () => { bodies.push(JSON.parse(b)); res.setHeader('content-type', 'application/json'); res.end('{}'); });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return { url: `http://127.0.0.1:${server.address().port}`, bodies, close: () => server.close() };
}

export async function world({ logUrl } = {}) {
  const issuer = await generateEd25519();
  const holder = await generateEd25519();
  const schoolKey = await generateEd25519();
  const { document, kid } = didDocument(ISSUER_DID, issuer.publicJwk);
  const didFetch = async () => ({ status: 200, json: async () => document });
  const w = {
    issuer, holder, schoolKey, kid, didFetch,
    statuses: [0, 1, 0],
    listDown: false,
    now: new Date('2026-11-06T10:00:00Z'),
    holderDid: didKeyFromJwk(holder.publicJwk),
  };
  w.fetchText = async () => {
    if (w.listDown) throw new Error('ECONNREFUSED');
    return buildStatusList({ uri: STATUS_LIST_URI, statuses: w.statuses, issuerDid: ISSUER_DID, kid, signer: signerFor(issuer.privateJwk) });
  };
  w.store = openStore(':memory:');
  w.school = createSchool({
    store: w.store, schoolPrivateJwk: schoolKey.privateJwk, didFetch, fetchText: w.fetchText, logUrl, clock: () => w.now,
  });
  w.consent = await signConsent({ holderDid: w.holderDid, holderPrivateJwk: holder.privateJwk, schoolDid: w.school.did, now: w.now });
  w.credential = (statusIndex = 0, issuerPrivateJwk = issuer.privateJwk) => issueCredential({
    certificate: cert, holderPublicJwk: holder.publicJwk, statusIndex, issuerPrivateJwk, kid,
  });
  w.present = async (over = {}) => buildPresentation({
    credential: over.credential ?? await w.credential(over.statusIndex ?? 0),
    consent: over.consent ?? w.consent,
    holderPrivateJwk: holder.privateJwk,
    nonce: over.nonce ?? w.school.nonce().nonce,
    aud: over.aud ?? w.school.did,
    now: w.now,
    didFetch,
  });
  /** A presentation built directly with the library, skipping the teacher's own checks (for hostile inputs). */
  w.rawPresent = async ({ credential, consent = w.consent, claims = CONSENT_SCOPE, nonce, aud = w.school.did, signer = holder.privateJwk } = {}) => {
    const sdjwt = new SDJwtVcInstance({ hasher, hashAlg: 'sha-256', kbSigner: signerFor(signer), kbSignAlg: 'EdDSA' });
    return sdjwt.present(credential ?? await w.credential(0), Object.fromEntries(claims.map((c) => [c, true])), {
      kb: { payload: { aud, nonce: nonce ?? w.school.nonce().nonce, iat: Math.floor(w.now.getTime() / 1000), consent_hash: sha256Hex(consent) } },
    });
  };
  w.receiptCount = () => w.store.db.prepare('SELECT count(*) AS n FROM receipts').get().n;
  return w;
}
