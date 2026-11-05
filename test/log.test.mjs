import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generatePrivateKey } from 'viem/accounts';
import { sha256Hex } from '../src/shared/encoding.mjs';
import { firstBreak, GENESIS, entryHash } from '../src/log/chain.mjs';
import { merkleRoot, merklePath, rootFromPath, EMPTY_LEAF, leafHash } from '../src/log/merkle.mjs';
import { openLogStore } from '../src/log/store.mjs';
import { createLog } from '../src/log/service.mjs';
import { createLogServer } from '../src/log/server.mjs';
import { readAnchor } from '../src/anchor/sepolia.mjs';
import { otsState } from '../src/anchor/ots.mjs';
import { fakeRpc } from './helpers/fake-rpc.mjs';
import { otsProof } from './helpers/ots-proof.mjs';

const TYPES = ['consent', 'presentation', 'receipt', 'recheck'];

function filled(n, config = {}) {
  const store = openLogStore(':memory:');
  let t = Date.UTC(2026, 10, 6, 10, 0, 0);
  const log = createLog({ store, ots: false, clock: () => new Date((t += 1000)), ...config });
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
  await assert.rejects(log.closeBatch(), /chain is broken/);
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
    const before = createLog({ store, ots: true, stamp: async (root) => otsProof(root) });
    before.commit({ entry_type: 'receipt', commitment: sha256Hex('r') });
    const b = await before.closeBatch();
    assert.equal(b.sepolia.state, 'not_anchored');
    const proof = b.ots.proof;
    const after = createLog({ store, ots: true, stamp: async () => { throw new Error('must not restamp'); }, sepolia: { privateKey: generatePrivateKey(), rpcUrls: [rpc.url], pollMs: 10 } });
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
  assert.equal(rootFromPath(p.entry.entry_hash, p.merkle_path), p.batch.root);
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
