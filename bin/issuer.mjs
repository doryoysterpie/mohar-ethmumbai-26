#!/usr/bin/env node
// SIMULATED issuer. Commands:
//   keygen [--force]                       new issuer key in .keys/issuer.json; writes site/did.json
//   did                                    rewrites site/did.json from the existing key in .keys/issuer.json
//   publish                                writes site/status/tet-eligibility.jwt from fixtures/issuance.json
//   issue <certificate.json> <holder-did>  prints a credential for the certificate's status index in fixtures/issuance.json
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateEd25519, signerFor, jwkFromDidKey } from '../src/shared/keys.mjs';
import { didDocument } from '../src/issuer/did-web.mjs';
import { buildStatusList } from '../src/issuer/status-list.mjs';
import { issueCredential } from '../src/issuer/credential.mjs';
import { ISSUER_DID, STATUS_LIST_PATH, STATUS_LIST_URI } from '../src/issuer/profile.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const KEY_FILE = path.join(ROOT, '.keys', 'issuer.json');
const SITE = path.join(ROOT, 'site');
const MANIFEST = path.join(ROOT, 'fixtures', 'issuance.json');

function readKey() {
  if (!fs.existsSync(KEY_FILE)) throw new Error(`no issuer key at ${KEY_FILE}; run: issuer keygen`);
  return JSON.parse(fs.readFileSync(KEY_FILE, 'utf8'));
}

function write(file, text, mode) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, text, mode ? { mode } : undefined);
  console.error(`wrote ${path.relative(ROOT, file)}`);
}

const [cmd, ...args] = process.argv.slice(2);

if (cmd === 'keygen') {
  if (fs.existsSync(KEY_FILE) && !args.includes('--force')) throw new Error(`${KEY_FILE} exists; pass --force to replace it`);
  const { privateJwk, publicJwk } = await generateEd25519();
  const { document, kid } = didDocument(ISSUER_DID, publicJwk);
  write(KEY_FILE, `${JSON.stringify({ did: ISSUER_DID, kid, privateJwk }, null, 2)}\n`, 0o600);
  write(path.join(SITE, 'did.json'), `${JSON.stringify(document, null, 2)}\n`);
} else if (cmd === 'did') {
  const key = readKey();
  const { document, kid } = didDocument(key.did, { kty: 'OKP', crv: 'Ed25519', x: key.privateJwk.x });
  if (kid !== key.kid) throw new Error('key id in .keys/issuer.json does not match the DID document');
  write(path.join(SITE, 'did.json'), `${JSON.stringify(document, null, 2)}\n`);
} else if (cmd === 'publish') {
  const key = readKey();
  const { credentials } = JSON.parse(fs.readFileSync(MANIFEST, 'utf8'));
  const size = Math.max(...credentials.map((c) => c.status_index)) + 1;
  const statuses = new Array(size).fill(0);
  for (const c of credentials) statuses[c.status_index] = c.revoked ? 1 : 0;
  const token = await buildStatusList({
    uri: STATUS_LIST_URI, statuses, issuerDid: key.did, kid: key.kid, signer: signerFor(key.privateJwk),
  });
  write(path.join(SITE, STATUS_LIST_PATH), `${token}\n`);
} else if (cmd === 'issue') {
  const [certFile, holderDid] = args;
  if (!certFile || !holderDid) throw new Error('usage: issuer issue <certificate.json> <holder-did:key>');
  const key = readKey();
  const { credentials } = JSON.parse(fs.readFileSync(MANIFEST, 'utf8'));
  const rel = path.relative(path.dirname(MANIFEST), path.resolve(certFile));
  const entry = credentials.find((c) => c.certificate === rel);
  if (!entry) throw new Error(`${rel} is not listed in fixtures/issuance.json`);
  const certificate = JSON.parse(fs.readFileSync(certFile, 'utf8'));
  const credential = await issueCredential({
    certificate, holderPublicJwk: jwkFromDidKey(holderDid), statusIndex: entry.status_index,
    issuerPrivateJwk: key.privateJwk, kid: key.kid,
  });
  process.stdout.write(`${credential}\n`);
} else {
  console.error('usage: issuer keygen [--force] | did | publish | issue <certificate.json> <holder-did:key>');
  process.exit(2);
}
