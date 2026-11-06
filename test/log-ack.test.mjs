import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { generateEd25519 } from '../src/shared/keys.mjs';
import { sha256Hex } from '../src/shared/encoding.mjs';
import { openLogStore } from '../src/log/store.mjs';
import { createLog } from '../src/log/service.mjs';
import { createLogServer } from '../src/log/server.mjs';
import { logProblems } from '../src/log/integrity.mjs';
import { verifyAck, compareAcks, operatorDocument, signAck } from '../src/log/ack.mjs';
import { decodeJws, signJws } from '../src/shared/jws.mjs';
import { saltedCommitment, newSalt } from '../src/shared/commitment.mjs';
import { buildBundle } from '../src/verifier/export.mjs';
import { verifyBundle } from '../src/inspector/verify.mjs';
import { commitRecord } from '../src/log/client.mjs';

const ROOT = new URL('..', import.meta.url).pathname;
const HEAD_KEY = 'ef'.repeat(32);

async function commitAndAck(log, entryType, commitment) {
  const { entry } = log.commit({ entry_type: entryType, commitment });
  return { entry, ack: await log.acknowledge(entry) };
}

test('every accepted commit returns an acknowledgement signed by the operator key', async () => {
  const op = await generateEd25519();
  const doc = operatorDocument(op.publicJwk);
  const store = openLogStore(':memory:');
  const log = createLog({ store, ots: false, operatorKey: op.privateJwk });
  const server = createLogServer(log);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  try {
    const c = sha256Hex('record');
    const res = await fetch(`http://127.0.0.1:${server.address().port}/commit`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ entry_type: 'receipt', commitment: c }),
    });
    const body = await res.json();
    const ack = await verifyAck(body.ack, doc);
    assert.deepEqual(
      { seq: ack.seq, entry_hash: ack.entry_hash, entry_type: ack.entry_type, commitment: ack.commitment, ts: ack.ts },
      { seq: body.seq, entry_hash: body.entry_hash, entry_type: 'receipt', commitment: c, ts: body.ts },
    );
    assert.equal(ack.operator_key_id, doc.id);
    // The log stores nothing extra: no table or column holds acknowledgements.
    const tables = store.db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all().map((t) => t.name);
    const columns = tables.flatMap((t) => store.db.prepare(`PRAGMA table_info(${t})`).all().map((c) => `${t}.${c.name}`));
    assert.ok(!columns.some((c) => /ack/i.test(c)), columns.join());
    assert.ok(!JSON.stringify(store.db.prepare('SELECT * FROM entries').all()).includes(body.ack.split('.')[2]));
  } finally {
    server.close();
  }
});

test('the auditor’s replay: the log alone reports itself intact, and the held acknowledgement proves the rollback', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mohar-replay-'));
  const file = path.join(dir, 'log.sqlite');
  const op = await generateEd25519();
  const doc = operatorDocument(op.publicJwk);
  try {
    let store = openLogStore(file, { headKey: HEAD_KEY });
    let log = createLog({ store, ots: false, operatorKey: op.privateJwk });
    await commitAndAck(log, 'consent', sha256Hex('consent'));
    const savedHead = store.db.prepare('SELECT seq, entry_hash, mac FROM head').get();
    const original = await commitAndAck(log, 'receipt', sha256Hex('original receipt'));
    assert.equal(original.entry.seq, 1);

    // Roll back: delete the unbatched tail and restore the older, genuinely authenticated checkpoint.
    store.db.prepare('DELETE FROM entries WHERE seq = 1').run();
    store.db.prepare('UPDATE head SET seq = ?, entry_hash = ?, mac = ? WHERE id = 1').run(savedHead.seq, savedHead.entry_hash, savedHead.mac);
    store.close();

    store = openLogStore(file, { headKey: HEAD_KEY });
    log = createLog({ store, ots: false, operatorKey: op.privateJwk });
    // (a) The stated limit: the log alone cannot see it.
    assert.deepEqual(logProblems(store), []);
    const replacementRecord = 'replacement receipt';
    const replacementSalt = newSalt();
    const replacement = await commitAndAck(log, 'receipt', saltedCommitment(replacementRecord, replacementSalt));
    assert.equal(replacement.entry.seq, 1);
    assert.notEqual(replacement.entry.entry_hash, original.entry.entry_hash);
    assert.deepEqual(logProblems(store), []);

    // The verifier: a bundle for the entry now at seq 1, carrying the acknowledgement held for seq 1, fails the
    // acknowledgement line; with the operator's acknowledgement of the replacement it passes.
    await log.closeBatch();
    const logProof = log.proof(saltedCommitment(replacementRecord, replacementSalt), 'receipt');
    const bundle = buildBundle({ record: replacementRecord, salt: replacementSalt, recordType: 'receipt', proof: logProof, ack: original.ack });
    const held = (await verifyBundle(bundle, { operator: doc, rpcUrls: [] })).checks.find((c) => c.check === 'acknowledgement');
    assert.equal(held.result, 'fail');
    assert.match(held.detail, /acknowledgement entry_hash [0-9a-f]{64} is not the bundle entry's [0-9a-f]{64}/);
    const own = (await verifyBundle({ ...bundle, ack: replacement.ack }, { operator: doc, rpcUrls: [] })).checks.find((c) => c.check === 'acknowledgement');
    assert.equal(own.result, 'pass');
    store.close();

    // (b) The acknowledgement the client kept, against the new one, proves equivocation.
    const proof = await compareAcks(original.ack, replacement.ack, doc);
    assert.equal(proof.equivocation, true);
    fs.writeFileSync(path.join(dir, 'a.ack'), original.ack);
    fs.writeFileSync(path.join(dir, 'b.ack'), replacement.ack);
    fs.writeFileSync(path.join(dir, 'operator.json'), JSON.stringify(doc));
    const run = spawnSync(process.execPath, [
      '--no-deprecation', path.join(ROOT, 'bin', 'log.mjs'), 'equivocation', path.join(dir, 'a.ack'), path.join(dir, 'b.ack'), '--operator', path.join(dir, 'operator.json'),
    ], { encoding: 'utf8', env: { ...process.env, MOHAR_LOG_DB: path.join(dir, 'cli.sqlite'), MOHAR_OTS: 'off' } });
    assert.equal(run.status, 3, run.stderr);
    const out = JSON.parse(run.stdout);
    assert.equal(out.equivocation, true);
    assert.equal(out.seq, 1);
    assert.equal(out.a.signature, original.ack.split('.')[2]);
    assert.equal(out.b.signature, replacement.ack.split('.')[2]);
    assert.notEqual(out.a.entry_hash, out.b.entry_hash);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('acknowledgements for different entries, or from another key, are not equivocation proofs', async () => {
  const op = await generateEd25519();
  const doc = operatorDocument(op.publicJwk);
  const log = createLog({ store: openLogStore(':memory:'), ots: false, operatorKey: op.privateJwk });
  const a = await commitAndAck(log, 'receipt', sha256Hex('a'));
  const b = await commitAndAck(log, 'receipt', sha256Hex('b'));
  assert.equal((await compareAcks(a.ack, b.ack, doc)).equivocation, false);
  assert.equal((await compareAcks(a.ack, a.ack, doc)).equivocation, false);
  const other = await generateEd25519();
  const foreign = createLog({ store: openLogStore(':memory:'), ots: false, operatorKey: other.privateJwk });
  const f = await commitAndAck(foreign, 'receipt', sha256Hex('x'));
  await assert.rejects(compareAcks(a.ack, f.ack, doc), /another operator key/);
  // A forgery that names the real operator key but is signed by another key.
  const { header, payload } = decodeJws(a.ack);
  const forged = await signJws({ ...payload, entry_hash: sha256Hex('forged') }, { typ: header.typ, kid: header.kid }, other.privateJwk);
  await assert.rejects(verifyAck(forged, doc), /signature invalid/);
});

test('the school keeps the acknowledgements of its receipt and re-check commitments', async () => {
  const { world } = await import('./helpers/world.mjs');
  const op = await generateEd25519();
  const doc = operatorDocument(op.publicJwk);
  const log = createLog({ store: openLogStore(':memory:'), ots: false, operatorKey: op.privateJwk });
  const server = createLogServer(log);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  try {
    const w = await world({ logUrl: `http://127.0.0.1:${server.address().port}`, operator: doc });
    const r = await w.school.present({ presentation: await w.present(), consent: w.consent });
    w.now = new Date('2027-01-01T00:00:00.000Z');
    const [rc] = await w.school.recheck();
    const row = w.store.db.prepare('SELECT receipt_ack FROM receipts WHERE receipt_id = ?').get(r.receipt_id);
    const rrow = w.store.db.prepare('SELECT recheck_ack FROM rechecks WHERE recheck_id = ?').get(rc.recheck_id);
    assert.equal((await verifyAck(row.receipt_ack, doc)).entry_type, 'receipt');
    assert.equal((await verifyAck(rrow.recheck_ack, doc)).entry_type, 'recheck');
  } finally {
    server.close();
  }
});

test('a log without an operator key refuses commits before appending, and its service does not start', async () => {
  const store = openLogStore(':memory:');
  const log = createLog({ store, ots: false });
  assert.throws(() => log.commit({ entry_type: 'receipt', commitment: sha256Hex('r') }), /no log operator key/);
  await assert.rejects(log.acknowledge({ seq: 0 }), /no log operator key/);
  assert.equal(store.entries().length, 0);
  assert.throws(() => createLogServer(log), /needs an operator key/);
});

/** A real acknowledging log, and a fetch that lets a test rewrite its /commit responses. */
async function rewritingLog() {
  const op = await generateEd25519();
  const other = await generateEd25519();
  const log = createLog({ store: openLogStore(':memory:'), ots: false, operatorKey: op.privateJwk });
  const server = createLogServer(log);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const t = {
    log, op, other, doc: operatorDocument(op.publicJwk), logUrl: `http://127.0.0.1:${server.address().port}`,
    rewrite: async (body) => body,
    close: () => server.close(),
  };
  t.fetch = async (u, init) => {
    const res = await fetch(u, init);
    const body = await t.rewrite(await res.json());
    return new Response(JSON.stringify(body), { status: res.status, headers: { 'content-type': 'application/json' } });
  };
  return t;
}

test('the log client rejects a commit whose acknowledgement is missing, malformed, for another entry or under another key', async () => {
  const t = await rewritingLog();
  const commit = () => commitRecord({ logUrl: t.logUrl, entryType: 'receipt', record: `r ${Math.random()}`, salt: newSalt(), operator: t.doc, fetch: t.fetch });
  try {
    t.rewrite = async (b) => b;
    const ok = await commit();
    assert.equal((await verifyAck(ok.ack, t.doc)).seq, ok.response.seq);

    const another = t.log.commit({ entry_type: 'receipt', commitment: sha256Hex('another entry') }).entry;
    const anotherAck = await t.log.acknowledge(another);
    const cases = [
      ['missing', async (b) => { delete b.ack; return b; }, /no acknowledgement/],
      ['null', async (b) => ({ ...b, ack: null }), /no acknowledgement/],
      ['garbage', async (b) => ({ ...b, ack: 'not.a.jws' }), /acknowledgement invalid/],
      ['another entry', async (b) => ({ ...b, ack: anotherAck }), /acknowledgement (seq|entry_hash|commitment) is not the returned entry's/],
      ['another key', async (b) => ({ ...b, ack: await signAck(b, t.other.privateJwk) }), /acknowledgement invalid: acknowledgement is signed for another operator key/],
      ['another key under the operator kid', async (b) => {
        const { header, payload } = decodeJws(b.ack);
        return { ...b, ack: await signJws(payload, header, t.other.privateJwk) };
      }, /acknowledgement invalid/],
      ['entry for another commitment', async (b) => ({ ...b, commitment: sha256Hex('x') }), /entry for another commitment/],
      ['ack ts not the entry ts', async (b) => ({ ...b, ts: '2000-01-01T00:00:00.000Z' }), /acknowledgement ts is not the returned entry's/],
    ];
    for (const [name, rewrite, reason] of cases) {
      t.rewrite = rewrite;
      await assert.rejects(commit(), reason, name);
    }
    await assert.rejects(
      commitRecord({ logUrl: t.logUrl, entryType: 'receipt', record: 'r', salt: newSalt(), fetch: t.fetch }),
      /no published log operator key/,
    );
  } finally {
    t.close();
  }
});

test('the school does not report a commit as posted without a valid acknowledgement, and needs the operator key', async () => {
  const { world } = await import('./helpers/world.mjs');
  const t = await rewritingLog();
  try {
    await assert.rejects(world({ logUrl: t.logUrl }), /needs the published log operator key/);
    t.rewrite = async (b) => { delete b.ack; return b; };
    const w = await world({ logUrl: t.logUrl, operator: t.doc, logFetch: t.fetch });
    const r = await w.school.present({ presentation: await w.present(), consent: w.consent });
    assert.equal(r.ok, true);
    assert.equal(r.log.posted, false);
    assert.match(r.log.error, /no acknowledgement/);
    assert.equal(w.store.db.prepare('SELECT receipt_ack FROM receipts WHERE receipt_id = ?').get(r.receipt_id).receipt_ack, null);
    t.rewrite = async (b) => ({ ...b, ack: await signAck(b, t.other.privateJwk) });
    w.now = new Date('2027-01-01T00:00:00.000Z');
    const [rc] = await w.school.recheck();
    assert.equal(w.store.db.prepare('SELECT recheck_ack FROM rechecks WHERE recheck_id = ?').get(rc.recheck_id).recheck_ack, null);
  } finally {
    t.close();
  }
});
