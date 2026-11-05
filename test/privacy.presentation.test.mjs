import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import { generateEd25519, didKeyFromJwk } from '../src/shared/keys.mjs';
import { fromBase64url } from '../src/shared/encoding.mjs';
import { didDocument } from '../src/issuer/did-web.mjs';
import { issueCredential } from '../src/issuer/credential.mjs';
import { ISSUER_DID, NEVER_PRESENTED } from '../src/issuer/profile.mjs';
import { signConsent, CONSENT_SCOPE } from '../src/holder/consent.mjs';
import { buildPresentation, disclosedClaims } from '../src/holder/presentation.mjs';
import { commitRecord } from '../src/log/client.mjs';

const manifest = JSON.parse(fs.readFileSync(new URL('../fixtures/issuance.json', import.meta.url), 'utf8'));
const NONCE = 'nonce-0123456789abcdef';

/** Every string or number inside a value, flattened. */
const leaves = (v) => (v === null || typeof v !== 'object' ? [String(v)] : Object.values(v).flatMap(leaves));

/** Decoded text of every segment of a presentation (JWT parts and disclosures). */
function decodedText(presentation) {
  return presentation.split(/[~.]/).filter(Boolean).map((s) => {
    try { return new TextDecoder().decode(fromBase64url(s)); } catch { return ''; }
  }).join('\n');
}

async function present(certFile, scope) {
  const cert = JSON.parse(fs.readFileSync(new URL(`../fixtures/${certFile}`, import.meta.url), 'utf8'));
  const issuer = await generateEd25519();
  const holder = await generateEd25519();
  const school = await generateEd25519();
  const { kid } = didDocument(ISSUER_DID, issuer.publicJwk);
  const credential = await issueCredential({
    certificate: cert, holderPublicJwk: holder.publicJwk, statusIndex: 0, issuerPrivateJwk: issuer.privateJwk, kid,
  });
  const aud = didKeyFromJwk(school.publicJwk);
  const consent = await signConsent({
    holderDid: didKeyFromJwk(holder.publicJwk), holderPrivateJwk: holder.privateJwk, schoolDid: aud, scope,
  });
  const presentation = await buildPresentation({ credential, consent, holderPrivateJwk: holder.privateJwk, nonce: NONCE, aud });
  return { cert, presentation, holder, aud, credential };
}

for (const entry of manifest.credentials) {
  test(`a presentation for ${entry.certificate} discloses exactly the consented claims and no certificate detail`, async () => {
    const { cert, presentation } = await present(entry.certificate);
    assert.deepEqual((await disclosedClaims(presentation)).sort(), [...CONSENT_SCOPE].sort());
    const text = decodedText(presentation);
    for (const claim of NEVER_PRESENTED) {
      assert.ok(!text.includes(`"${claim}"`), `${claim} appears in the presentation`);
      for (const value of leaves(cert[claim]).filter((s) => s.length > 3)) {
        assert.ok(!text.includes(value), `${claim} value "${value}" appears in the presentation`);
      }
    }
  });
}

test('a narrower consent discloses only its own claims', async () => {
  const { presentation } = await present(manifest.credentials[0].certificate, ['qualified', 'paper']);
  assert.deepEqual((await disclosedClaims(presentation)).sort(), ['paper', 'qualified']);
});

test('a consent naming a never-presented claim cannot be signed', async () => {
  const holder = await generateEd25519();
  const school = await generateEd25519();
  for (const claim of NEVER_PRESENTED) {
    await assert.rejects(signConsent({
      holderDid: didKeyFromJwk(holder.publicJwk), holderPrivateJwk: holder.privateJwk,
      schoolDid: didKeyFromJwk(school.publicJwk), scope: [...CONSENT_SCOPE, claim],
    }), new RegExp(claim));
  }
});

test('the log client sends only an entry type and a SHA-256 commitment', async () => {
  const bodies = [];
  const server = http.createServer((req, res) => {
    let b = '';
    req.on('data', (c) => { b += c; });
    req.on('end', () => { bodies.push(b); res.setHeader('content-type', 'application/json'); res.end('{}'); });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  try {
    const { presentation } = await present(manifest.credentials[0].certificate);
    await commitRecord({ logUrl: `http://127.0.0.1:${server.address().port}`, entryType: 'presentation', record: presentation });
    assert.equal(bodies.length, 1);
    const body = JSON.parse(bodies[0]);
    assert.deepEqual(Object.keys(body).sort(), ['commitment', 'entry_type']);
    assert.equal(body.entry_type, 'presentation');
    assert.match(body.commitment, /^[0-9a-f]{64}$/);
  } finally {
    server.close();
  }
});
