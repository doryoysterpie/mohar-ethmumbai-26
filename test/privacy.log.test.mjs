import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { generatePrivateKey } from 'viem/accounts';
import { sha256Hex, canonicalJson } from '../src/shared/encoding.mjs';
import { openLogStore } from '../src/log/store.mjs';
import { createLog } from '../src/log/service.mjs';
import { createLogServer } from '../src/log/server.mjs';
import { readAnchor } from '../src/anchor/sepolia.mjs';
import { fakeRpc } from './helpers/fake-rpc.mjs';
import { otsProof } from './helpers/ots-proof.mjs';

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

test('no personal data in any log entry, batch root or Sepolia transaction', async () => {
  const rpc = await fakeRpc();
  try {
    const store = openLogStore(':memory:');
    const log = createLog({
      store, sepolia: { privateKey: generatePrivateKey(), rpcUrls: [rpc.url], pollMs: 10 }, stamp: async (root) => otsProof(root),
    });
    // The records the platform's clients commit to carry personal data; the log only ever sees their hashes.
    const records = [canonicalJson(cert), `consent for ${cert.name}`, `presentation ${cert.roll_no}`, `receipt ${cert.dob}`];
    for (const [i, r] of records.entries()) log.commit({ entry_type: ['consent', 'presentation', 'receipt', 'recheck'][i], commitment: sha256Hex(r) });
    const batch = await log.closeBatch();

    for (const e of store.entries()) {
      assert.deepEqual(Object.keys(e).sort(), ['batch_id', 'commitment', 'entry_hash', 'entry_type', 'prev_hash', 'seq', 'ts']);
      for (const f of ['commitment', 'entry_hash', 'prev_hash']) assert.match(e[f], HEX64);
    }
    assert.match(batch.root, HEX64);
    const text = dump(store.db).join('\n');
    for (const v of PERSONAL) assert.ok(!text.includes(v), `"${v}" is in the log store`);

    const tx = await readAnchor({ txHash: batch.sepolia.tx_hash, rpcUrls: [rpc.url] });
    assert.equal(tx.calldata, batch.root);
    assert.equal(tx.calldata.length, 64);
  } finally {
    rpc.close();
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
