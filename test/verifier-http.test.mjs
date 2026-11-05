import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createServer } from '../src/verifier/server.mjs';
import { world } from './helpers/world.mjs';

async function serve(w, options) {
  const server = createServer(w.school, options);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return { base: `http://127.0.0.1:${server.address().port}`, close: () => server.close() };
}

const post = (url, body, headers = {}) => fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body });

test('present, replay and status over HTTP', async () => {
  const w = await world();
  w.now = new Date();
  w.consent = await (await import('../src/holder/consent.mjs')).signConsent({
    holderDid: w.holderDid, holderPrivateJwk: w.holder.privateJwk, schoolDid: w.school.did, now: w.now,
  });
  const s = await serve(w, { adminToken: 'staff-token-0123456789' });
  const staff = { authorization: 'Bearer staff-token-0123456789' };
  try {
    const { nonce } = await (await fetch(`${s.base}/nonce`)).json();
    const presentation = await w.present({ nonce });
    const ok = await post(`${s.base}/present`, JSON.stringify({ presentation, consent: w.consent }));
    assert.equal(ok.status, 200);
    const again = await post(`${s.base}/present`, JSON.stringify({ presentation, consent: w.consent }));
    assert.equal(again.status, 422);
    assert.equal((await again.json()).refusal, 'nonce_stale');
    const statusUrl = `${s.base}/status/${encodeURIComponent(w.holderDid)}`;
    assert.equal((await fetch(statusUrl)).status, 401);
    const st = await fetch(statusUrl, { headers: staff });
    assert.equal(st.status, 200);
    assert.equal((await st.json()).status_result, 'not_revoked');
    assert.equal((await fetch(`${s.base}/status/did:key:z6Mkunknown`, { headers: staff })).status, 404);
  } finally {
    s.close();
  }
});

test('the term check over HTTP needs the admin token, and is off without one', async () => {
  const w = await world();
  const off = await serve(w);
  try {
    assert.equal((await post(`${off.base}/recheck`, '{}')).status, 403);
    assert.equal((await fetch(`${off.base}/status/${encodeURIComponent(w.holderDid)}`)).status, 403);
  } finally {
    off.close();
  }
  const on = await serve(w, { adminToken: 'admin-token-0123456789' });
  try {
    assert.equal((await post(`${on.base}/recheck`, '{}')).status, 401);
    assert.equal((await post(`${on.base}/recheck`, '{}', { authorization: 'Bearer admin-token-012345678X' })).status, 401);
    assert.equal((await post(`${on.base}/recheck`, '{}', { authorization: 'Bearer admin-token-0123456789' })).status, 200);
  } finally {
    on.close();
  }
});

test('bad requests are rejected before verification', async () => {
  const w = await world();
  const s = await serve(w);
  try {
    assert.equal((await post(`${s.base}/present`, 'not json')).status, 400);
    assert.equal((await post(`${s.base}/present`, 'x'.repeat(70_000))).status, 413);
    assert.equal((await fetch(`${s.base}/present`, { method: 'POST', body: '{}' })).status, 415);
    assert.equal((await fetch(`${s.base}/export/anything`)).status, 501);
    assert.equal((await fetch(`${s.base}/nowhere`)).status, 404);
    assert.equal(w.store.refusals().length, 0);
  } finally {
    s.close();
  }
});

test('a malformed key binding over HTTP is 422 key_binding_invalid with one stored refusal', async () => {
  const w = await world();
  const s = await serve(w);
  try {
    const parts = (await w.present()).split('~');
    const presentation = [...parts.slice(0, -1), 'not-a-compact-jwt'].join('~');
    const res = await post(`${s.base}/present`, JSON.stringify({ presentation, consent: w.consent }));
    assert.equal(res.status, 422);
    assert.equal((await res.json()).refusal, 'key_binding_invalid');
    assert.equal(w.receiptCount(), 0);
    const rows = w.store.refusals();
    assert.equal(rows.length, 1);
    assert.equal(rows[0].presentation_hash, createHash('sha256').update(presentation).digest('hex'));
  } finally {
    s.close();
  }
});
