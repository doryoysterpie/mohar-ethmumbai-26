import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { generatePrivateKey } from 'viem/accounts';
import { sha256Hex } from '../src/shared/encoding.mjs';
import { firstBreak, GENESIS, entryHash } from '../src/log/chain.mjs';
import { logProblems } from '../src/log/integrity.mjs';
import { merkleRoot, merklePath, rootFromPath, EMPTY_LEAF, leafHash, batchRoot } from '../src/log/merkle.mjs';
import { openLogStore } from '../src/log/store.mjs';
import { createLog } from '../src/log/service.mjs';
import { createLogServer } from '../src/log/server.mjs';
import { readAnchor } from '../src/anchor/sepolia.mjs';
import { otsState } from '../src/anchor/ots.mjs';
import { fakeRpc } from './helpers/fake-rpc.mjs';
import { generateEd25519 } from '../src/shared/keys.mjs';
import { otsProof } from './helpers/ots-proof.mjs';

const TYPES = ['consent', 'presentation', 'receipt', 'recheck'];
const OPERATOR = (await generateEd25519()).privateJwk;

function filled(n, config = {}) {
  const store = openLogStore(':memory:');
  let t = Date.UTC(2026, 10, 6, 10, 0, 0);
  const log = createLog({ operatorKey: OPERATOR, store, ots: false, clock: () => new Date((t += 1000)), ...config });
  for (let i = 0; i < n; i += 1) log.commit({ entry_type: TYPES[i % 4], commitment: sha256Hex(`record ${i}`) });
  return { store, log };
}

test('entries chain from the genesis constant and the chain is intact', () => {
  const { store } = filled(6);
  const entries = store.entries();
  assert.equal(entries[0].seq, 0);
  assert.equal(entries[0].prev_hash, GENESIS);
  for (let i = 1; i < entries.length; i += 1) assert.equal(entries[i].prev_hash, entries[i - 1].entry_hash);
  for (const e of entries) assert.equal(e.entry_hash, entryHash(e.prev_hash, e.entry_type, e.commitment, e.ts));
  assert.equal(firstBreak(entries), -1);
});

test('a modified entry breaks the chain', () => {
  for (const [field, value] of [['commitment', sha256Hex('other')], ['ts', '2026-11-06T09:00:00.000Z'], ['entry_type', 'receipt']]) {
    const { store } = filled(5);
    const e = store.entries()[2];
    const v = field === 'entry_type' && e.entry_type === 'receipt' ? 'consent' : value;
    store.db.prepare(`UPDATE entries SET ${field} = ? WHERE seq = 2`).run(v);
    assert.equal(firstBreak(store.entries()), 2, field);
  }
});

test('a removed entry, or an entry rewritten with its own hash, breaks the chain', () => {
  const removed = filled(5).store;
  removed.db.prepare('DELETE FROM entries WHERE seq = 1').run();
  assert.equal(firstBreak(removed.entries()), 2);
  const rewritten = filled(5).store;
  const e = rewritten.entries()[2];
  const c = sha256Hex('substitute');
  rewritten.db.prepare('UPDATE entries SET commitment = ?, entry_hash = ? WHERE seq = 2').run(c, entryHash(e.prev_hash, e.entry_type, c, e.ts));
  assert.equal(firstBreak(rewritten.entries()), 3);
});

test('a batch is not closed over a broken chain', async () => {
  const { store, log } = filled(3);
  store.db.prepare('UPDATE entries SET commitment = ? WHERE seq = 1').run(sha256Hex('other'));
  await assert.rejects(log.closeBatch(), /inconsistent \(hash chain broken at seq 1\)/);
  assert.equal(store.batches().length, 0);
});

test('every entry has a Merkle path to its batch root, for any batch size', () => {
  for (const n of [1, 2, 3, 5, 8, 13]) {
    const hashes = Array.from({ length: n }, (_, i) => sha256Hex(`e${i}`));
    const root = merkleRoot(hashes);
    for (let i = 0; i < n; i += 1) assert.equal(rootFromPath(hashes[i], merklePath(hashes, i)), root, `n=${n} i=${i}`);
  }
});

test('padding is deterministic, distinct from any entry leaf, and never accepted as an entry', () => {
  const hashes = Array.from({ length: 3 }, (_, i) => sha256Hex(`e${i}`));
  assert.equal(merkleRoot(hashes), merkleRoot([...hashes]));
  for (const h of hashes) assert.notEqual(leafHash(h), EMPTY_LEAF);
  const p = merklePath(hashes, 2);
  assert.throws(() => rootFromPath(hashes[2], { ...p, index: 3 }), /not a real entry/);
  const bad = { ...p, siblings: [...p.siblings] };
  bad.siblings[0] = sha256Hex('x');
  assert.notEqual(rootFromPath(hashes[2], bad), merkleRoot(hashes));
});

test('Sepolia calldata equals the batch root', async () => {
  const rpc = await fakeRpc();
  try {
    const { log } = filled(3, { sepolia: { privateKey: generatePrivateKey(), rpcUrls: [rpc.url], pollMs: 10 } });
    const b = await log.closeBatch();
    assert.equal(b.sepolia.state, 'confirmed');
    assert.equal(b.sepolia.chain_id, 11155111);
    const tx = await readAnchor({ txHash: b.sepolia.tx_hash, rpcUrls: [rpc.url] });
    assert.equal(tx.calldata, b.root);
    assert.equal(tx.to, tx.from);
  } finally {
    rpc.close();
  }
});

test('the Sepolia write falls back to the second RPC and sends one transaction', async () => {
  const down = await fakeRpc({ fail: true });
  const up = await fakeRpc();
  try {
    const { log } = filled(2, { sepolia: { privateKey: generatePrivateKey(), rpcUrls: [down.url, up.url], pollMs: 10, timeoutMs: 5000 } });
    const b = await log.closeBatch();
    assert.equal(b.sepolia.state, 'confirmed');
    assert.equal(up.state.txs.size, 1);
    assert.equal(down.state.txs.size, 0);
    assert.ok(down.state.calls.length > 0, 'the first RPC was tried');
  } finally {
    down.close();
    up.close();
  }
});

test('OTS state is read from the proof: pending, then complete with a Bitcoin height', async () => {
  const { log } = filled(2, { ots: true, stamp: async (root) => otsProof(root), upgrade: async (proof) => ({ proof, changed: false }) });
  const b = await log.closeBatch();
  assert.equal(b.ots.state, 'pending');
  assert.equal(b.ots.bitcoin_height, null);
  assert.equal(otsState(Buffer.from(b.ots.proof, 'base64'), b.root).state, 'pending');
  const same = await log.upgradePending();
  assert.deepEqual(same.map((x) => x.state), ['pending']);
  const { log: log2, store } = filled(2, { ots: true, stamp: async (root) => otsProof(root), upgrade: async () => ({ proof: otsProof(store.batches()[0].root, { bitcoinHeight: 905123 }), changed: true }) });
  await log2.closeBatch();
  const up = await log2.upgradePending();
  assert.deepEqual(up, [{ batch_id: 1, state: 'complete', bitcoin_height: 905123 }]);
  assert.equal(log2.batch(1).ots.state, 'complete');
});

test('the two anchors are reported separately and one failing does not hide the other', async () => {
  const rpc = await fakeRpc();
  try {
    const { log } = filled(2, {
      ots: true, stamp: async () => { throw new Error('calendars unreachable'); },
      sepolia: { privateKey: generatePrivateKey(), rpcUrls: [rpc.url], pollMs: 10 },
    });
    const b = await log.closeBatch();
    assert.equal(b.sepolia.state, 'confirmed');
    assert.equal(b.ots.state, 'not_anchored');
    assert.match(b.ots.error, /calendars unreachable/);
  } finally {
    rpc.close();
  }
  const down = await fakeRpc({ fail: true });
  try {
    const { log } = filled(2, { ots: true, stamp: async (root) => otsProof(root), sepolia: { privateKey: generatePrivateKey(), rpcUrls: [down.url], pollMs: 10, timeoutMs: 300 } });
    const b = await log.closeBatch();
    assert.equal(b.sepolia.state, 'not_anchored');
    assert.equal(b.ots.state, 'pending');
  } finally {
    down.close();
  }
});

test('a batch closed without a Sepolia anchor is anchored later, once, without touching its OTS proof', async () => {
  const rpc = await fakeRpc();
  try {
    const store = openLogStore(':memory:');
    const before = createLog({ operatorKey: OPERATOR, store, ots: true, stamp: async (root) => otsProof(root) });
    before.commit({ entry_type: 'receipt', commitment: sha256Hex('r') });
    const b = await before.closeBatch();
    assert.equal(b.sepolia.state, 'not_anchored');
    const proof = b.ots.proof;
    const after = createLog({ operatorKey: OPERATOR, store, ots: true, stamp: async () => { throw new Error('must not restamp'); }, sepolia: { privateKey: generatePrivateKey(), rpcUrls: [rpc.url], pollMs: 10 } });
    const [a] = await after.anchorPending();
    assert.equal(a.sepolia.state, 'confirmed');
    assert.equal(a.ots.proof, proof);
    assert.equal((await readAnchor({ txHash: a.sepolia.tx_hash, rpcUrls: [rpc.url] })).calldata, b.root);
    assert.deepEqual(await after.anchorPending(), []);
    assert.equal(rpc.state.txs.size, 1);
  } finally {
    rpc.close();
  }
});

test('an OTS proof for another root is not accepted as this batch’s proof', async () => {
  const { log } = filled(2, { ots: true, stamp: async () => otsProof(sha256Hex('another root')) });
  const b = await log.closeBatch();
  assert.equal(b.ots.state, 'not_anchored');
  assert.match(b.ots.error, /another digest/);
});

test('a proof gives the entry, its path and the batch; before batching it gives the entry only', async () => {
  const { log } = filled(3);
  const c = sha256Hex('record 1');
  assert.equal(log.proof(c).batch, null);
  await log.closeBatch();
  const p = log.proof(c);
  assert.equal(rootFromPath(p.entry.entry_hash, p.merkle_path), p.batch.tree_root);
  assert.equal(batchRoot({ batch_id: p.batch.batch_id, first_seq: p.batch.first_seq, size: p.batch.size, closed_at: p.batch.closed_at }, p.batch.tree_root), p.batch.root);
  assert.equal(log.proof(sha256Hex('never committed')), null);
  assert.equal(log.proof('not a hash'), null);
});

test('operator routes need the token and are off without one', async () => {
  const { log } = filled(1);
  const open = createLogServer(log);
  const closed = createLogServer(log, { adminToken: 'operator-token-0123456789' });
  await new Promise((r) => open.listen(0, '127.0.0.1', r));
  await new Promise((r) => closed.listen(0, '127.0.0.1', r));
  const post = (s, path, h = {}) => fetch(`http://127.0.0.1:${s.address().port}${path}`, { method: 'POST', headers: { 'content-type': 'application/json', ...h }, body: '{}' });
  try {
    assert.equal((await post(open, '/batch')).status, 403);
    assert.equal((await post(closed, '/batch')).status, 401);
    assert.equal((await post(closed, '/upgrade', { authorization: 'Bearer operator-token-012345678X' })).status, 401);
    assert.equal((await post(closed, '/batch', { authorization: 'Bearer operator-token-0123456789' })).status, 200);
  } finally {
    open.close();
    closed.close();
  }
});

test('deleting the final unbatched entry is detected, and its sequence number is never reused', async () => {
  const { store, log } = filled(3);
  store.db.prepare('DELETE FROM entries WHERE seq = 2').run();
  assert.deepEqual(logProblems(store), ['tail is seq 1 but the head checkpoint is seq 2']);
  assert.throws(() => log.commit({ entry_type: 'consent', commitment: sha256Hex('replacement') }), /does not match its head checkpoint/);
  assert.equal(store.db.prepare('SELECT count(*) AS n FROM entries WHERE seq = 2').get().n, 0);
  await assert.rejects(log.closeBatch(), /inconsistent/);
});

test('deleting the final batched entries is detected, even with the head rewritten to match', async () => {
  const { store, log } = filled(3);
  await log.closeBatch();
  store.db.pragma('foreign_keys = OFF');
  store.db.prepare('DELETE FROM entries WHERE seq = 2').run();
  store.db.prepare('UPDATE head SET seq = 1, entry_hash = (SELECT entry_hash FROM entries WHERE seq = 1)').run();
  assert.deepEqual(logProblems(store), ['batch 1 does not hold seq 0–2 exactly']);
  assert.throws(() => log.commit({ entry_type: 'consent', commitment: sha256Hex('after') }), /closed batch ends at seq 2, after the log tail/);
  assert.equal(store.db.prepare('SELECT count(*) AS n FROM entries WHERE seq = 2').get().n, 0);
});

test('a corrupted entry in a closed batch stops the next batch from closing', async () => {
  const { store, log } = filled(2);
  await log.closeBatch();
  store.db.prepare('UPDATE entries SET commitment = ? WHERE seq = 0').run(sha256Hex('rewritten'));
  log.commit({ entry_type: 'receipt', commitment: sha256Hex('later') });
  await assert.rejects(log.closeBatch(), /hash chain broken at seq 0/);
  assert.equal(store.batches().length, 1);
});

test('a modified stored root is not anchored', async () => {
  const rpc = await fakeRpc();
  try {
    const store = openLogStore(':memory:');
    const before = createLog({ operatorKey: OPERATOR, store, ots: false });
    before.commit({ entry_type: 'receipt', commitment: sha256Hex('r') });
    await before.closeBatch();
    store.db.prepare('UPDATE batches SET root = ? WHERE batch_id = 1').run(sha256Hex('other root'));
    const after = createLog({ operatorKey: OPERATOR, store, ots: false, sepolia: { privateKey: generatePrivateKey(), rpcUrls: [rpc.url], pollMs: 10 } });
    await assert.rejects(after.anchorPending(), /batch 1 root does not recompute/);
    assert.equal(rpc.state.txs.size, 0);
  } finally {
    rpc.close();
  }
});

test('the same commitment under two entry types gives two proofs, each to its own batch root', async () => {
  const { log } = filled(0);
  const c = sha256Hex('shared');
  log.commit({ entry_type: 'consent', commitment: c });
  const b1 = await log.closeBatch();
  log.commit({ entry_type: 'receipt', commitment: c });
  const b2 = await log.closeBatch();
  const consent = log.proof(c, 'consent');
  const receipt = log.proof(c, 'receipt');
  assert.equal(consent.entry.entry_type, 'consent');
  assert.equal(receipt.entry.entry_type, 'receipt');
  assert.equal(batchRoot({ batch_id: b1.batch_id, first_seq: b1.first_seq, size: b1.size, closed_at: b1.closed_at }, rootFromPath(consent.entry.entry_hash, consent.merkle_path)), b1.root);
  assert.equal(batchRoot({ batch_id: b2.batch_id, first_seq: b2.first_seq, size: b2.size, closed_at: b2.closed_at }, rootFromPath(receipt.entry.entry_hash, receipt.merkle_path)), b2.root);
  assert.throws(() => log.proof(c), (e) => e.code === 'ambiguous' && e.types.join() === 'consent,receipt');
  assert.equal(log.proof(c, 'recheck'), null);

  const server = createLogServer(log);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}/proof/${c}`;
  try {
    const amb = await fetch(base);
    assert.equal(amb.status, 409);
    assert.deepEqual((await amb.json()).entry_types, ['consent', 'receipt']);
    const r = await fetch(`${base}?entry_type=receipt`);
    assert.equal(r.status, 200);
    assert.equal((await r.json()).batch.batch_id, b2.batch_id);
  } finally {
    server.close();
  }
});

test('deleting the final unbatched entry and the head checkpoint, then restarting, is refused', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mohar-head-'));
  const file = path.join(dir, 'log.sqlite');
  try {
    let store = openLogStore(file);
    let t = Date.UTC(2026, 10, 6, 10, 0, 0);
    for (let i = 0; i < 3; i += 1) store.append('receipt', sha256Hex(`r${i}`), new Date((t += 1000)).toISOString());
    store.db.prepare('DELETE FROM entries WHERE seq = 2').run();
    store.db.prepare('DELETE FROM head').run();
    store.close();
    store = openLogStore(file);
    assert.deepEqual(logProblems(store), ['head checkpoint is missing']);
    assert.throws(() => store.append('receipt', sha256Hex('replacement'), new Date(t + 5000).toISOString()), /head checkpoint is missing/);
    assert.equal(store.db.prepare('SELECT count(*) AS n FROM entries WHERE seq = 2').get().n, 0);
    store.close();
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('with a head key, a checkpoint rewritten without the key is refused', () => {
  const key = 'cd'.repeat(32);
  const store = openLogStore(':memory:', { headKey: key });
  let t = Date.UTC(2026, 10, 6, 10, 0, 0);
  for (let i = 0; i < 3; i += 1) store.append('receipt', sha256Hex(`r${i}`), new Date((t += 1000)).toISOString());
  store.db.prepare('DELETE FROM entries WHERE seq = 2').run();
  store.db.prepare('UPDATE head SET seq = 1, entry_hash = (SELECT entry_hash FROM entries WHERE seq = 1)').run();
  assert.deepEqual(logProblems(store), ['head checkpoint is not authenticated by the head key']);
  assert.throws(() => store.append('receipt', sha256Hex('replacement'), new Date(t + 5000).toISOString()), /not authenticated/);
});

test('adopting a head checkpoint is explicit, one-time, and refused over a broken chain', () => {
  const store = openLogStore(':memory:');
  store.append('receipt', sha256Hex('a'), '2026-11-06T10:00:00.000Z');
  store.append('receipt', sha256Hex('b'), '2026-11-06T10:00:01.000Z');
  assert.throws(() => store.adoptHead(), /already has a valid head checkpoint/);
  store.db.prepare('DELETE FROM head').run();
  store.db.prepare('UPDATE entries SET ts = ? WHERE seq = 0').run('2026-01-01T00:00:00.000Z');
  assert.throws(() => store.adoptHead(), /chain is broken/);
  store.db.prepare('UPDATE entries SET ts = ? WHERE seq = 0').run('2026-11-06T10:00:00.000Z');
  assert.deepEqual(store.adoptHead().seq, 1);
  assert.deepEqual(logProblems(store), []);
});

test('the anchored root commits to batch id, first seq, size and closing time (fixed vector)', async () => {
  assert.equal(batchRoot({ batch_id: 1, first_seq: 0, size: 6, closed_at: '2026-11-06T10:00:00.000Z' }, '44'.repeat(32)),
    '8e2cdb140d1572454151cc8f383bb8a078bc81520ff345afdefb7f61fc621e43');
  const { log } = filled(3);
  const b = await log.closeBatch();
  const header = { batch_id: b.batch_id, first_seq: b.first_seq, size: b.size, closed_at: b.closed_at };
  assert.equal(batchRoot(header, b.tree_root), b.root);
  for (const [field, value] of [['batch_id', 2], ['first_seq', 1], ['size', 2], ['closed_at', '2026-11-06T10:00:01.000Z']]) {
    assert.notEqual(batchRoot({ ...header, [field]: value }, b.tree_root), b.root, field);
  }
});

test('a stored batch header changed after closing is detected', async () => {
  const { store, log } = filled(3);
  await log.closeBatch();
  store.db.prepare('UPDATE batches SET closed_at = ? WHERE batch_id = 1').run('2026-01-01T00:00:00.000Z');
  assert.deepEqual(logProblems(store), ['batch 1 root does not recompute']);
});
