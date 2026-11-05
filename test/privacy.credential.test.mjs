import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { generateEd25519 } from '../src/shared/keys.mjs';
import { didDocument } from '../src/issuer/did-web.mjs';
import { issueCredential, certificateCommitment } from '../src/issuer/credential.mjs';
import { sha256Hex, canonicalJson } from '../src/shared/encoding.mjs';
import { ISSUER_DID, DISCLOSABLE } from '../src/issuer/profile.mjs';

const VISIBLE = ['iss', 'sub', 'vct', 'iat', 'status', 'cnf', '_sd', '_sd_alg'];
const manifest = JSON.parse(fs.readFileSync(new URL('../fixtures/issuance.json', import.meta.url), 'utf8'));

/** Every string or number inside a value, flattened. */
function leaves(v) {
  if (v === null || typeof v !== 'object') return [String(v)];
  return Object.values(v).flatMap(leaves);
}

for (const entry of manifest.credentials) {
  test(`the always-visible part of the credential for ${entry.certificate} carries no certificate field or value`, async () => {
    const cert = JSON.parse(fs.readFileSync(new URL(`../fixtures/${entry.certificate}`, import.meta.url), 'utf8'));
    const issuer = await generateEd25519();
    const holder = await generateEd25519();
    const { kid } = didDocument(ISSUER_DID, issuer.publicJwk);
    const cred = await issueCredential({
      certificate: cert, holderPublicJwk: holder.publicJwk, statusIndex: entry.status_index, issuerPrivateJwk: issuer.privateJwk, kid,
    });
    const jwtText = Buffer.from(cred.split('~')[0].split('.')[1], 'base64url').toString('utf8');
    const payload = JSON.parse(jwtText);
    assert.deepEqual(Object.keys(payload).sort(), [...VISIBLE].sort());
    for (const claim of DISCLOSABLE) assert.ok(!(claim in payload), `${claim} is visible`);
    const personal = ['name', 'roll_no', 'dob', 'category', 'mother_name', 'father_or_husband_name', 'marks']
      .flatMap((f) => leaves(cert[f]))
      .filter((s) => s.length > 3);
    for (const value of personal) assert.ok(!jwtText.includes(value), `certificate value "${value}" is visible`);
  });
}

test('two credentials issued for the same certificate JSON yield different certificate_commitment values', async () => {
  const cert = JSON.parse(fs.readFileSync(new URL('../fixtures/certificates/teacher-a.json', import.meta.url), 'utf8'));
  const issuer = await generateEd25519();
  const holder = await generateEd25519();
  const { kid } = didDocument(ISSUER_DID, issuer.publicJwk);
  const commitmentOf = async () => {
    const cred = await issueCredential({ certificate: cert, holderPublicJwk: holder.publicJwk, statusIndex: 0, issuerPrivateJwk: issuer.privateJwk, kid });
    const d = cred.split('~').slice(1, -1).map((x) => JSON.parse(Buffer.from(x, 'base64url')));
    return { commitment: d.find((x) => x[1] === 'certificate_commitment')[2], salt: d.find((x) => x[1] === 'certificate_salt')[2] };
  };
  const a = await commitmentOf();
  const b = await commitmentOf();
  assert.notEqual(a.commitment, b.commitment);
  assert.notEqual(a.salt, b.salt);
  for (const c of [a.commitment, b.commitment]) assert.notEqual(c, sha256Hex(canonicalJson(cert)));
  assert.equal(certificateCommitment(cert, a.salt), a.commitment);
});
