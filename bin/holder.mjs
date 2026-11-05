#!/usr/bin/env node
// Teacher (holder). Commands:
//   keygen <name>                                                 new key in .keys/holder-<name>.json; prints the did:key
//   consent <name> <school-did>                                   prints a signed consent record
//   present <name> <credential-file> <consent-file> <school-did> <nonce>
//                                                                 prints { presentation, presentation_salt }; keeps the consent
//                                                                 salt in <consent-file>.salt; posts both salted
//                                                                 commitments to the log service at MOHAR_LOG_URL when set;
//                                                                 verifies the credential first (MOHAR_SITE_DIR: local did.json)
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateEd25519, didKeyFromJwk } from '../src/shared/keys.mjs';
import { signConsent } from '../src/holder/consent.mjs';
import { buildPresentation } from '../src/holder/presentation.mjs';
import { commitRecord } from '../src/log/client.mjs';
import { newSalt, isSalt, saltedCommitment } from '../src/shared/commitment.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const keyFile = (name) => {
  if (!/^[a-z0-9-]+$/.test(name ?? '')) throw new Error('name must be lowercase letters, digits and hyphens');
  return path.join(ROOT, '.keys', `holder-${name}.json`);
};
const readKey = (name) => {
  const f = keyFile(name);
  if (!fs.existsSync(f)) throw new Error(`no holder key at ${f}; run: holder keygen ${name}`);
  return JSON.parse(fs.readFileSync(f, 'utf8'));
};
const readText = (f) => fs.readFileSync(f, 'utf8').trim();

const [cmd, ...args] = process.argv.slice(2);

if (cmd === 'keygen') {
  const f = keyFile(args[0]);
  if (fs.existsSync(f)) throw new Error(`${f} exists`);
  const { privateJwk, publicJwk } = await generateEd25519();
  const did = didKeyFromJwk(publicJwk);
  fs.mkdirSync(path.dirname(f), { recursive: true });
  fs.writeFileSync(f, `${JSON.stringify({ did, privateJwk }, null, 2)}\n`, { mode: 0o600 });
  process.stdout.write(`${did}\n`);
} else if (cmd === 'consent') {
  const [name, schoolDid] = args;
  if (!schoolDid) throw new Error('usage: holder consent <name> <school-did>');
  const key = readKey(name);
  process.stdout.write(`${await signConsent({ holderDid: key.did, holderPrivateJwk: key.privateJwk, schoolDid })}\n`);
} else if (cmd === 'present') {
  const [name, credFile, consentFile, schoolDid, nonce] = args;
  if (!nonce) throw new Error('usage: holder present <name> <credential-file> <consent-file> <school-did> <nonce>');
  const key = readKey(name);
  const consent = readText(consentFile);
  // MOHAR_SITE_DIR reads the issuer's did.json from a local copy of the site instead of fetching it.
  const siteDir = process.env.MOHAR_SITE_DIR;
  const didFetch = siteDir
    ? async () => ({ status: 200, json: async () => JSON.parse(fs.readFileSync(path.join(siteDir, 'did.json'), 'utf8')) })
    : undefined;
  const presentation = await buildPresentation({
    credential: readText(credFile), consent, holderPrivateJwk: key.privateJwk, nonce, aud: schoolDid, didFetch,
  });
  // The teacher keeps both salts; the presentation salt also goes to the school with the presentation.
  const consentSaltFile = `${consentFile}.salt`;
  const consentSalt = fs.existsSync(consentSaltFile) ? readText(consentSaltFile) : newSalt();
  if (!isSalt(consentSalt)) throw new Error(`${consentSaltFile} does not hold a 32-byte hex salt`);
  fs.writeFileSync(consentSaltFile, `${consentSalt}\n`, { mode: 0o600 });
  const presentationSalt = newSalt();
  process.stdout.write(`${JSON.stringify({ presentation, presentation_salt: presentationSalt })}\n`);
  const logUrl = process.env.MOHAR_LOG_URL;
  const records = [['consent', consent, consentSalt], ['presentation', presentation, presentationSalt]];
  if (logUrl) {
    for (const [entryType, record, salt] of records) {
      const { commitment } = await commitRecord({ logUrl, entryType, record, salt });
      console.error(`committed ${entryType} ${commitment}`);
    }
  } else {
    console.error('MOHAR_LOG_URL not set; commitments not posted:');
    for (const [entryType, record, salt] of records) console.error(`  ${entryType} ${saltedCommitment(record, salt)}`);
  }
} else {
  console.error('usage: holder keygen <name> | consent <name> <school-did> | present <name> <credential-file> <consent-file> <school-did> <nonce>');
  process.exit(2);
}
