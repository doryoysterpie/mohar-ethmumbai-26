import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { generateEd25519, signerFor, didKeyFromJwk } from '../src/shared/keys.mjs';
import { sha256Hex, canonicalJson } from '../src/shared/encoding.mjs';
import { didDocument, didWebFromBase } from '../src/issuer/did-web.mjs';
import { getListFromStatusListJWT } from '@owf/token-status-list';
import { buildStatusList, checkStatus } from '../src/issuer/status-list.mjs';
import { issueCredential, verifyCredential, certificateCommitment } from '../src/issuer/credential.mjs';
import { ISSUER_DID, SITE_BASE, STATUS_LIST_URI, DISCLOSABLE } from '../src/issuer/profile.mjs';

const cert = JSON.parse(fs.readFileSync(new URL('../fixtures/certificates/teacher-a.json', import.meta.url), 'utf8'));

async function setup() {
  const issuer = await generateEd25519();
  const holder = await generateEd25519();
  const { document, kid } = didDocument(ISSUER_DID, issuer.publicJwk);
  const didFetch = async () => ({ status: 200, json: async () => document });
  const list = await buildStatusList({
    uri: STATUS_LIST_URI, statuses: [0, 1, 0], issuerDid: ISSUER_DID, kid, signer: signerFor(issuer.privateJwk),
  });
  const issue = (statusIndex) => issueCredential({
    certificate: cert, holderPublicJwk: holder.publicJwk, statusIndex, issuerPrivateJwk: issuer.privateJwk, kid,
  });
  return { issuer, holder, document, kid, didFetch, list, issue };
}

test('a credential verifies against the DID document', async () => {
  const { didFetch, issue, holder } = await setup();
  const { payload, header } = await verifyCredential(await issue(0), { didFetch });
  assert.equal(payload.iss, ISSUER_DID);
  assert.equal(payload.sub, didKeyFromJwk(holder.publicJwk));
  assert.equal(header.typ, 'dc+sd-jwt');
  assert.equal(payload.certificate_commitment, certificateCommitment(cert, payload.certificate_salt));
  assert.notEqual(payload.certificate_commitment, sha256Hex(canonicalJson(cert)));
  assert.equal(payload.issuing_body, 'CBSE (simulated)');
  assert.equal(payload.exp, undefined);
});

test('a credential fails against a different issuer key', async () => {
  const { issue } = await setup();
  const other = await generateEd25519();
  const doc = didDocument(ISSUER_DID, other.publicJwk).document;
  await assert.rejects(verifyCredential(await issue(0), { didFetch: async () => ({ status: 200, json: async () => doc }) }));
});

test('a credential fails when its issuer-signed part is altered', async () => {
  const { didFetch, issue } = await setup();
  const cred = await issue(0);
  const [jwt, ...rest] = cred.split('~');
  const [h, p, s] = jwt.split('.');
  const payload = JSON.parse(Buffer.from(p, 'base64url'));
  payload.status.status_list.idx = 2;
  const forged = [[h, Buffer.from(JSON.stringify(payload)).toString('base64url'), s].join('.'), ...rest].join('~');
  await assert.rejects(verifyCredential(forged, { didFetch }));
});

test('every certificate field is a separate disclosure', async () => {
  const { issue } = await setup();
  const cred = await issue(0);
  const names = cred.split('~').slice(1, -1).map((d) => JSON.parse(Buffer.from(d, 'base64url'))[1]);
  assert.deepEqual([...names].sort(), [...DISCLOSABLE].sort());
});

test('a revoked index reports revoked; a clear index reports not_revoked', async () => {
  const { didFetch, issue, list } = await setup();
  const fetchText = async () => list;
  for (const [idx, want] of [[0, 'not_revoked'], [1, 'revoked'], [2, 'not_revoked']]) {
    const { payload } = await verifyCredential(await issue(idx), { didFetch });
    assert.equal((await checkStatus(payload, { fetchText, didFetch })).result, want, `index ${idx}`);
  }
});

test('an unreachable list reports unknown', async () => {
  const { didFetch, issue } = await setup();
  const { payload } = await verifyCredential(await issue(1), { didFetch });
  const r = await checkStatus(payload, { fetchText: async () => { throw new Error('ECONNREFUSED'); }, didFetch });
  assert.equal(r.result, 'unknown');
  assert.match(r.reason, /unreachable/);
});

test('a list signed by another key reports unknown, never not_revoked', async () => {
  const { didFetch, issue, kid } = await setup();
  const other = await generateEd25519();
  const forged = await buildStatusList({
    uri: STATUS_LIST_URI, statuses: [0, 0, 0], issuerDid: ISSUER_DID, kid, signer: signerFor(other.privateJwk),
  });
  const { payload } = await verifyCredential(await issue(1), { didFetch });
  assert.equal((await checkStatus(payload, { fetchText: async () => forged, didFetch })).result, 'unknown');
});

test('a list published for another URI reports unknown', async () => {
  const { didFetch, issue, issuer, kid } = await setup();
  const elsewhere = await buildStatusList({
    uri: `${SITE_BASE}/status/other.jwt`, statuses: [0, 0, 0], issuerDid: ISSUER_DID, kid, signer: signerFor(issuer.privateJwk),
  });
  const { payload } = await verifyCredential(await issue(1), { didFetch });
  assert.equal((await checkStatus(payload, { fetchText: async () => elsewhere, didFetch })).result, 'unknown');
});

test('an index past the signed entry count reports unknown, inside or beyond the padded byte', async () => {
  const { didFetch, kid, issuer } = await setup();
  const one = await buildStatusList({ uri: STATUS_LIST_URI, statuses: [0], issuerDid: ISSUER_DID, kid, signer: signerFor(issuer.privateJwk) });
  const fetchText = async () => one;
  const at = (idx) => checkStatus({ iss: ISSUER_DID, status: { status_list: { idx, uri: STATUS_LIST_URI } } }, { fetchText, didFetch });
  assert.equal((await at(0)).result, 'not_revoked');
  for (const idx of [1, 7, 8, 1000]) {
    const r = await at(idx);
    assert.equal(r.result, 'unknown', `index ${idx}`);
  }
  assert.match((await at(1)).reason, /not allocated/);
});

test('the bits that pad a list to a whole byte are set', async () => {
  const { kid, issuer } = await setup();
  const token = await buildStatusList({ uri: STATUS_LIST_URI, statuses: [0, 0, 0], issuerDid: ISSUER_DID, kid, signer: signerFor(issuer.privateJwk) });
  const list = getListFromStatusListJWT(token);
  assert.deepEqual([0, 1, 2].map((i) => list.getStatus(i)), [0, 0, 0]);
  assert.deepEqual([3, 4, 5, 6, 7].map((i) => list.getStatus(i)), [1, 1, 1, 1, 1]);
  assert.equal(JSON.parse(Buffer.from(token.split('.')[1], 'base64url')).entries, 3);
});

test('a list without a signed entry count reports unknown', async () => {
  const { didFetch, kid, issuer } = await setup();
  const token = await buildStatusList({ uri: STATUS_LIST_URI, statuses: [0, 0], issuerDid: ISSUER_DID, kid, signer: signerFor(issuer.privateJwk) });
  const [h, p] = token.split('.');
  const payload = JSON.parse(Buffer.from(p, 'base64url'));
  delete payload.entries;
  const input = `${h}.${Buffer.from(JSON.stringify(payload)).toString('base64url')}`;
  const resigned = `${input}.${await signerFor(issuer.privateJwk)(input)}`;
  const r = await checkStatus({ iss: ISSUER_DID, status: { status_list: { idx: 0, uri: STATUS_LIST_URI } } }, { fetchText: async () => resigned, didFetch });
  assert.equal(r.result, 'unknown');
  assert.match(r.reason, /entry count/);
});

test('the published DID document and status list agree with each other', async () => {
  const doc = JSON.parse(fs.readFileSync(new URL('../site/did.json', import.meta.url), 'utf8'));
  const list = fs.readFileSync(new URL('../site/status/tet-eligibility.jwt', import.meta.url), 'utf8');
  assert.equal(doc.id, ISSUER_DID);
  assert.equal(didWebFromBase(SITE_BASE), doc.id);
  const didFetch = async () => ({ status: 200, json: async () => doc });
  const fetchText = async () => list;
  const manifest = JSON.parse(fs.readFileSync(new URL('../fixtures/issuance.json', import.meta.url), 'utf8'));
  for (const c of manifest.credentials) {
    const ref = { iss: ISSUER_DID, status: { status_list: { idx: c.status_index, uri: STATUS_LIST_URI } } };
    assert.equal((await checkStatus(ref, { fetchText, didFetch })).result, c.revoked ? 'revoked' : 'not_revoked', c.certificate);
  }
  const firstFree = Math.max(...manifest.credentials.map((c) => c.status_index)) + 1;
  const free = { iss: ISSUER_DID, status: { status_list: { idx: firstFree, uri: STATUS_LIST_URI } } };
  assert.equal((await checkStatus(free, { fetchText, didFetch })).result, 'unknown', `unallocated index ${firstFree}`);
});
