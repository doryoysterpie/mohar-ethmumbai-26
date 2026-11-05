import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { verifyBundle } from '../src/inspector/verify.mjs';
import { scenario } from './helpers/scenario.mjs';
import { cert } from './helpers/world.mjs';

const leaves = (v) => (v === null || typeof v !== 'object' ? [String(v)] : Object.values(v).flatMap(leaves));
const PERSONAL = ['name', 'roll_no', 'dob', 'category', 'mother_name', 'father_or_husband_name', 'marks']
  .flatMap((f) => leaves(cert[f])).filter((s) => s.length > 3);

test('the export verifies with both service databases deleted and both services down', async () => {
  const s = await scenario({ bitcoinHeight: 905321 });
  try {
    const receipt = await (await s.fetchBundle(s.receipt.receipt_id)).json();
    const recheck = await (await s.fetchBundle(s.recheck.recheck_id)).json();
    const { schoolUrl, logUrl } = s;
    await s.destroyServices();
    assert.equal(fs.existsSync(s.dir), false);
    await assert.rejects(fetch(`${schoolUrl}/export/${s.receipt.receipt_id}`));
    await assert.rejects(fetch(`${logUrl}/batches/1`));
    for (const bundle of [receipt, recheck]) {
      const r = await verifyBundle(bundle, { rpcUrls: [s.rpc.url], bitcoinHeader: s.bitcoinHeader });
      assert.deepEqual(r.checks.map((c) => [c.check, c.result]), [['signature', 'pass'], ['entry', 'pass'], ['merkle', 'pass'], ['sepolia', 'pass'], ['ots', 'pass']], bundle.record_type);
      assert.equal(r.ok, true);
    }
  } finally {
    await s.close();
  }
});

test('the verifier contacts nothing but the Sepolia RPC and the Bitcoin header source', async () => {
  const s = await scenario({ bitcoinHeight: 905321 });
  try {
    const bundle = await (await s.fetchBundle(s.receipt.receipt_id)).json();
    await s.destroyServices();
    const realFetch = globalThis.fetch;
    const urls = [];
    globalThis.fetch = (u, init) => { urls.push(String(u instanceof Request ? u.url : u)); return realFetch(u, init); };
    try {
      await verifyBundle(bundle, { rpcUrls: [s.rpc.url], bitcoinHeader: s.bitcoinHeader });
    } finally {
      globalThis.fetch = realFetch;
    }
    assert.ok(urls.length > 0);
    for (const u of urls) assert.ok(u.startsWith(s.rpc.url), `unexpected request to ${u}`);
  } finally {
    await s.close();
  }
});

test('a bundle carries no personal data, no presentation and no consent', async () => {
  const s = await scenario();
  try {
    for (const id of [s.receipt.receipt_id, s.recheck.recheck_id]) {
      const bundle = await (await s.fetchBundle(id)).json();
      assert.deepEqual(Object.keys(bundle).sort(), ['batch', 'entry', 'format', 'merkle_path', 'ots', 'record', 'record_type', 'salt', 'sepolia']);
      const decoded = JSON.parse(Buffer.from(bundle.record.split('.')[1], 'base64url'));
      const text = `${JSON.stringify(bundle)}\n${JSON.stringify(decoded)}`;
      for (const v of PERSONAL) assert.ok(!text.includes(v), `"${v}" in the ${bundle.record_type} bundle`);
      assert.ok(!text.includes(s.presentation), 'presentation in the bundle');
      assert.ok(!text.includes(s.w.consent), 'consent in the bundle');
      assert.ok(!text.includes(s.w.holderDid), 'holder did:key in the bundle');
    }
    await s.destroyServices();
  } finally {
    await s.close();
  }
});
