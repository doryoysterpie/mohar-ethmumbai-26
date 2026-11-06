import { test } from 'node:test';
import assert from 'node:assert/strict';
import { decodeJws } from '../src/shared/jws.mjs';
import { world, cert, logServer } from './helpers/world.mjs';

const RECEIPT_FIELDS = [
  'receipt_id', 'verifier', 'presentation_hash', 'certificate_commitment', 'consent_hash', 'issuer', 'issuer_sig_valid',
  'key_binding_valid', 'status_result', 'status_checked_at', 'disclosed_claims', 'purpose', 'verified_at', 'recheck_due',
];
const RECHECK_FIELDS = ['recheck_id', 'receipt_id', 'verifier', 'status_result', 'status_checked_at', 'next_recheck_due', 'alert'];
const leaves = (v) => (v === null || typeof v !== 'object' ? [String(v)] : Object.values(v).flatMap(leaves));
const PERSONAL = ['name', 'roll_no', 'dob', 'category', 'mother_name', 'father_or_husband_name', 'marks']
  .flatMap((f) => leaves(cert[f])).filter((s) => s.length > 3);

test('a receipt carries no name, no holder identifier and no certificate detail', async () => {
  const w = await world();
  const r = await w.school.present({ presentation: await w.present(), consent: w.consent });
  assert.equal(r.ok, true);
  const { payload } = decodeJws(r.receipt);
  assert.deepEqual(Object.keys(payload).sort(), [...RECEIPT_FIELDS].sort());
  assert.deepEqual(Object.keys(payload.disclosed_claims).sort(), ['exam_session', 'issuing_body', 'paper', 'qualified', 'stage']);
  const text = JSON.stringify(payload);
  assert.ok(!text.includes(w.holderDid), 'holder did:key on the receipt');
  for (const v of PERSONAL) assert.ok(!text.includes(v), `"${v}" on the receipt`);
});

test('a re-check receipt carries no name, no holder identifier and no certificate detail', async () => {
  const w = await world();
  await w.school.present({ presentation: await w.present(), consent: w.consent });
  w.now = new Date('2027-01-01T00:00:00Z');
  const [rc] = await w.school.recheck();
  const { payload } = decodeJws(rc.recheck);
  assert.deepEqual(Object.keys(payload).sort(), [...RECHECK_FIELDS].sort());
  const text = JSON.stringify(payload);
  assert.ok(!text.includes(w.holderDid));
  for (const v of PERSONAL) assert.ok(!text.includes(v), `"${v}" on the re-check receipt`);
});

test('the school posts only SHA-256 commitments of receipts and re-checks to the log', async () => {
  const log = await logServer();
  try {
    const w = await world({ logUrl: log.url, operator: log.operator });
    const r = await w.school.present({ presentation: await w.present(), consent: w.consent });
    w.now = new Date('2027-01-01T00:00:00Z');
    await w.school.recheck();
    assert.equal(r.log.posted, true);
    assert.deepEqual(log.bodies.map((b) => b.entry_type), ['receipt', 'recheck']);
    for (const b of log.bodies) {
      assert.deepEqual(Object.keys(b).sort(), ['commitment', 'entry_type']);
      assert.match(b.commitment, /^[0-9a-f]{64}$/);
    }
  } finally {
    log.close();
  }
});

test('a refusal is stored as the presentation hash and a reason only', async () => {
  const w = await world();
  const p = await w.present();
  await w.school.present({ presentation: p, consent: w.consent });
  await w.school.present({ presentation: p, consent: w.consent });
  const rows = w.store.refusals();
  assert.equal(rows.length, 1);
  assert.deepEqual(Object.keys(rows[0]).sort(), ['id', 'presentation_hash', 'reason', 'refused_at']);
  assert.match(rows[0].presentation_hash, /^[0-9a-f]{64}$/);
});
