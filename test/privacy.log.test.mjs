import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { generatePrivateKey } from 'viem/accounts';
import { sha256Hex, canonicalJson } from '../src/shared/encoding.mjs';
import { openLogStore } from '../src/log/store.mjs';
import { createLog } from '../src/log/service.mjs';
import { createLogServer } from '../src/log/server.mjs';
import { readAnchor } from '../src/anchor/sepolia.mjs';
import { commitRecord } from '../src/log/client.mjs';
import { newSalt, saltedCommitment } from '../src/shared/commitment.mjs';
import { fakeRpc } from './helpers/fake-rpc.mjs';
import { otsProof } from './helpers/ots-proof.mjs';
import { world } from './helpers/world.mjs';

const cert = JSON.parse(fs.readFileSync(new URL('../fixtures/certificates/teacher-a.json', import.meta.url), 'utf8'));
const leaves = (v) => (v === null || typeof v !== 'object' ? [String(v)] : Object.values(v).flatMap(leaves));
const PERSONAL = ['name', 'roll_no', 'dob', 'category', 'mother_name', 'father_or_husband_name', 'marks']
  .flatMap((f) => leaves(cert[f])).filter((s) => s.length > 3);

const HEX64 = /^[0-9a-f]{64}$/;

/** Every value in every row of every table, as text. */
function dump(db) {
  const tables = db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'").all().map((r) => r.name);
  return tables.flatMap((t) => db.prepare(`SELECT * FROM ${t}`).all().flatMap((row) => Object.values(row).map((v) => (Buffer.isBuffer(v) ? v.toString('latin1') : String(v)))));
}

test('no field of a log entry, root or anchor transaction is personal data, or recomputable from personal data without a salt held outside the log', async () => {
  const rpc = await fakeRpc();
  const store = openLogStore(':memory:');
  const log = createLog({
    store, sepolia: { privateKey: generatePrivateKey(), rpcUrls: [rpc.url], pollMs: 10 }, stamp: async (root) => otsProof(root),
  });
  const server = createLogServer(log);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const logUrl = `http://127.0.0.1:${server.address().port}`;
  try {
    // The real record flow: the teacher commits consent and presentation, the school commits receipt and re-check.
    const w = await world({ logUrl });
    const consentSalt = newSalt();
    const presentationSalt = newSalt();
    const presentation = await w.present();
    await commitRecord({ logUrl, entryType: 'consent', record: w.consent, salt: consentSalt });
    await commitRecord({ logUrl, entryType: 'presentation', record: presentation, salt: presentationSalt });
    const r = await w.school.present({ presentation, consent: w.consent, presentation_salt: presentationSalt });
    assert.equal(r.ok, true);
    w.now = new Date('2027-01-01T00:00:00.000Z');
    const [rc] = await w.school.recheck();
    const batch = await log.closeBatch();
    const saved = w.store.db.prepare('SELECT receipt_salt FROM receipts').get();
    const savedRc = w.store.db.prepare('SELECT recheck_salt FROM rechecks').get();
    const records = [
      ['consent', w.consent, consentSalt],
      ['presentation', presentation, presentationSalt],
      ['receipt', r.receipt, saved.receipt_salt],
      ['recheck', rc.recheck, savedRc.recheck_salt],
    ];

    const entries = store.entries();
    assert.equal(entries.length, 4);
    for (const e of entries) {
      assert.deepEqual(Object.keys(e).sort(), ['batch_id', 'commitment', 'entry_hash', 'entry_type', 'prev_hash', 'seq', 'ts']);
      for (const f of ['commitment', 'entry_hash', 'prev_hash']) assert.match(e[f], HEX64);
    }
    const tx = await readAnchor({ txHash: batch.sepolia.tx_hash, rpcUrls: [rpc.url] });
    assert.equal(tx.calldata, batch.root);
    const logText = `${dump(store.db).join('\n')}\n${tx.calldata}`;

    // Not personal data: no certificate value appears anywhere in the log store or the anchor.
    for (const v of PERSONAL) assert.ok(!logText.includes(v), `"${v}" is in the log`);
    // Not recomputable without the salt: no field is an unsalted hash of a record or of a personal value,
    // and no salt is held by the log.
    const unsalted = [...records.map(([, rec]) => rec), ...PERSONAL, canonicalJson(cert)].map((x) => sha256Hex(x));
    for (const h of unsalted) assert.ok(!logText.includes(h), 'an unsalted hash is in the log');
    for (const [, , salt] of records) assert.ok(!logText.includes(salt), 'a salt is in the log');
    // Each commitment is bound to its record by its own salt, and to nothing else.
    for (const [type, rec, salt] of records) {
      const e = entries.find((x) => x.entry_type === type);
      assert.equal(e.commitment, saltedCommitment(rec, salt), type);
      assert.notEqual(e.commitment, saltedCommitment(rec, newSalt()), type);
    }
  } finally {
    server.close();
    rpc.close();
  }
});

test('committing the same record twice yields two different commitments, neither equal to SHA-256 of the record', async () => {
  const bodies = [];
  const server = createLogServer({ commit: (b) => { bodies.push(b); return { created: true, entry: {} }; }, acknowledge: async () => null });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const logUrl = `http://127.0.0.1:${server.address().port}`;
  try {
    const record = canonicalJson(cert);
    const first = await commitRecord({ logUrl, entryType: 'consent', record, salt: newSalt() });
    const second = await commitRecord({ logUrl, entryType: 'consent', record, salt: newSalt() });
    assert.notEqual(first.commitment, second.commitment);
    for (const c of [first.commitment, second.commitment]) assert.notEqual(c, sha256Hex(record));
    assert.deepEqual(bodies.map((b) => b.commitment), [first.commitment, second.commitment]);
    await assert.rejects(commitRecord({ logUrl, entryType: 'consent', record }), /salt must be 32 bytes/);
    assert.equal(bodies.length, 2);
  } finally {
    server.close();
  }
});

test('the log refuses anything but an entry type and a SHA-256 commitment', async () => {
  const store = openLogStore(':memory:');
  const log = createLog({ store, ots: false });
  const server = createLogServer(log);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${server.address().port}/commit`;
  const post = (body) => fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  try {
    for (const body of [
      { entry_type: 'consent', commitment: cert.name },
      { entry_type: 'consent', commitment: cert.roll_no },
      { entry_type: 'consent', commitment: sha256Hex('x').toUpperCase() },
      { entry_type: 'consent', commitment: sha256Hex('x'), name: cert.name },
      { entry_type: 'consent', commitment: sha256Hex('x'), record: canonicalJson(cert) },
      { entry_type: cert.name, commitment: sha256Hex('x') },
      { commitment: sha256Hex('x') },
    ]) {
      assert.equal((await post(body)).status, 400, JSON.stringify(body));
    }
    assert.equal(store.entries().length, 0);
    assert.equal((await post({ entry_type: 'consent', commitment: sha256Hex('x') })).status, 201);
    assert.equal(store.entries().length, 1);
  } finally {
    server.close();
  }
});
