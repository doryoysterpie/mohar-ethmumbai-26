#!/usr/bin/env node
// School (verifier). Commands:
//   keygen      new key in .keys/school.json; prints the school's did:key
//   did         prints the school's did:key
//   serve       runs the verifier service on PORT (default 8080), store at MOHAR_SCHOOL_DB (default school.sqlite);
//               posts receipt and re-check commitments to MOHAR_LOG_URL when set; /status and /recheck need MOHAR_ADMIN_TOKEN
//   recheck     runs the term status check against the local store and prints the re-check receipts
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateEd25519, didKeyFromJwk } from '../src/shared/keys.mjs';
import { openStore } from '../src/verifier/store.mjs';
import { createSchool } from '../src/verifier/school.mjs';
import { createServer } from '../src/verifier/server.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const KEY_FILE = process.env.MOHAR_SCHOOL_KEY ?? path.join(ROOT, '.keys', 'school.json');
const DB_FILE = process.env.MOHAR_SCHOOL_DB ?? path.join(ROOT, 'school.sqlite');

function readKey() {
  if (!fs.existsSync(KEY_FILE)) throw new Error(`no school key at ${KEY_FILE}; run: school keygen`);
  return JSON.parse(fs.readFileSync(KEY_FILE, 'utf8'));
}

function school() {
  const key = readKey();
  return createSchool({ store: openStore(DB_FILE), schoolPrivateJwk: key.privateJwk, logUrl: process.env.MOHAR_LOG_URL });
}

const [cmd] = process.argv.slice(2);

if (cmd === 'keygen') {
  if (fs.existsSync(KEY_FILE)) throw new Error(`${KEY_FILE} exists`);
  const { privateJwk, publicJwk } = await generateEd25519();
  const did = didKeyFromJwk(publicJwk);
  fs.mkdirSync(path.dirname(KEY_FILE), { recursive: true });
  fs.writeFileSync(KEY_FILE, `${JSON.stringify({ did, privateJwk }, null, 2)}\n`, { mode: 0o600 });
  process.stdout.write(`${did}\n`);
} else if (cmd === 'did') {
  process.stdout.write(`${readKey().did}\n`);
} else if (cmd === 'serve') {
  const s = school();
  const port = Number(process.env.PORT ?? 8080);
  createServer(s, { adminToken: process.env.MOHAR_ADMIN_TOKEN }).listen(port, () => {
    console.error(`school ${s.did} listening on ${port}${process.env.MOHAR_ADMIN_TOKEN ? '' : ' (staff routes disabled)'}`);
  });
} else if (cmd === 'recheck') {
  process.stdout.write(`${JSON.stringify(await school().recheck(), null, 2)}\n`);
} else {
  console.error('usage: school keygen | did | serve | recheck');
  process.exit(2);
}
