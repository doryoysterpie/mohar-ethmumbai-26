import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { createWalletClient, http as viemHttp } from 'viem';
import { sepolia } from 'viem/chains';
import { generateEd25519 } from '../src/shared/keys.mjs';
import { decodeJws, signJws } from '../src/shared/jws.mjs';
import { sha256Hex } from '../src/shared/encoding.mjs';
import { newSalt } from '../src/shared/commitment.mjs';
import { verifyBundle } from '../src/inspector/verify.mjs';
import { otsProof } from './helpers/ots-proof.mjs';
import { scenario } from './helpers/scenario.mjs';

let s;
let base;
const opts = () => ({ rpcUrls: [s.rpc.url], bitcoinHeader: s.bitcoinHeader });
const clone = () => structuredClone(base);
const results = async (bundle) => Object.fromEntries((await verifyBundle(bundle, opts())).checks.map((c) => [c.check, c]));

test.before(async () => {
  s = await scenario({ bitcoinHeight: 905321 });
  base = await (await s.fetchBundle(s.receipt.receipt_id)).json();
  await s.destroyServices();
});
test.after(async () => { await s.close(); });

test('an untouched bundle passes all five checks', async () => {
  const r = await verifyBundle(clone(), opts());
  assert.equal(r.ok, true);
  assert.deepEqual(r.checks.map((c) => c.result), ['pass', 'pass', 'pass', 'pass', 'pass']);
});

test('a forged receipt fails the signature check by name, and only that check', async () => {
  const b = clone();
  const { header, payload } = decodeJws(b.record);
  const forger = await generateEd25519();
  b.record = await signJws({ ...payload, status_result: 'not_revoked' }, { typ: header.typ, kid: header.kid }, forger.privateJwk);
  const r = await results(b);
  assert.equal(r.signature.result, 'fail');
  assert.match(r.signature.detail, /school signature invalid/);
  // The forged record is not the one the log committed to.
  assert.equal(r.entry.result, 'fail');
  assert.match(r.entry.detail, /commitment does not recompute from the record and its salt/);
  for (const c of ['merkle', 'sepolia', 'ots']) assert.equal(r[c].result, 'pass', c);
});

test('a receipt re-signed under another did:key fails the signature check', async () => {
  const b = clone();
  const { header, payload } = decodeJws(b.record);
  const other = await generateEd25519();
  b.record = await signJws(payload, { typ: header.typ, kid: header.kid }, other.privateJwk);
  assert.equal((await results(b)).signature.result, 'fail');
});

test('a wrong Merkle path fails the merkle check by name, and only that check', async () => {
  const b = clone();
  b.merkle_path.siblings[0] = sha256Hex('not the sibling');
  const r = await results(b);
  assert.equal(r.merkle.result, 'fail');
  assert.match(r.merkle.detail, /Merkle path leads to a different root/);
  for (const c of ['signature', 'entry', 'sepolia', 'ots']) assert.equal(r[c].result, 'pass', c);
});

test('a valid receipt whose path leads to another batch root is refused', async () => {
  const b = clone();
  b.merkle_path.index = (b.merkle_path.index + 1) % b.batch.size;
  const r = await results(b);
  assert.equal(r.signature.result, 'pass');
  assert.equal(r.merkle.result, 'fail');
  assert.equal((await verifyBundle(b, opts())).ok, false);
});

test('a mismatched calldata root fails the sepolia check by name, and only that check', async () => {
  const b = clone();
  const wallet = createWalletClient({ account: privateKeyToAccount(generatePrivateKey()), chain: sepolia, transport: viemHttp(s.rpc.url) });
  b.sepolia.tx_hash = await wallet.sendTransaction({ to: wallet.account.address, value: 0n, data: `0x${sha256Hex('another root')}` });
  const r = await results(b);
  assert.equal(r.sepolia.result, 'fail');
  assert.match(r.sepolia.detail, /Sepolia calldata does not match the batch root/);
  for (const c of ['signature', 'entry', 'merkle', 'ots']) assert.equal(r[c].result, 'pass', c);
});

test('a missing or unknown Sepolia transaction fails the sepolia check', async () => {
  const none = clone();
  none.sepolia = null;
  assert.match((await results(none)).sepolia.detail, /no Sepolia anchor/);
  const unknown = clone();
  unknown.sepolia.tx_hash = `0x${'ab'.repeat(32)}`;
  assert.match((await results(unknown)).sepolia.detail, /not found/);
  const otherChain = clone();
  otherChain.sepolia.chain_id = 1;
  assert.match((await results(otherChain)).sepolia.detail, /not Sepolia/);
});

test('a tampered OTS proof fails the ots check by name, and only that check', async () => {
  // Flip one byte of an operation on the path from the root to the Bitcoin attestation.
  const flipped = clone();
  const bytes = Buffer.from(flipped.ots.proof, 'base64');
  const at = bytes.indexOf(Buffer.from('00112233445566778899aabbccddeeff', 'hex'));
  assert.ok(at > 0, 'operand found in the proof');
  bytes[at + 4] ^= 0xff;
  flipped.ots.proof = bytes.toString('base64');
  const r1 = await results(flipped);
  assert.equal(r1.ots.result, 'fail');
  assert.match(r1.ots.detail, /OTS attestation does not match Bitcoin block 905321/);
  for (const c of ['signature', 'entry', 'merkle', 'sepolia']) assert.equal(r1[c].result, 'pass', c);

  const otherDigest = clone();
  otherDigest.ots.proof = Buffer.from(otsProof(sha256Hex('another root'), { bitcoinHeight: 905321 })).toString('base64');
  assert.match((await results(otherDigest)).ots.detail, /for another digest/);

  const wrongBlock = clone();
  wrongBlock.ots.proof = Buffer.from(otsProof(wrongBlock.batch.root, { bitcoinHeight: 905321 })).toString('base64');
  s.headers.set(905321, { merkleroot: sha256Hex('some other block'), time: 1 });
  try {
    const r3 = await results(wrongBlock);
    assert.equal(r3.ots.result, 'fail');
    assert.match(r3.ots.detail, /OTS attestation does not match Bitcoin block 905321/);
  } finally {
    s.headers.clear();
    const real = await (await import('../src/anchor/ots.mjs')).otsBitcoinAttestations(Buffer.from(base.ots.proof, 'base64'), base.batch.root);
    for (const a of real) s.headers.set(a.height, { merkleroot: Buffer.from(a.msg, 'hex').reverse().toString('hex'), time: 1_793_000_000 });
  }
});

test('the verifier passes with the correct salt and fails with the named reason on a wrong or missing salt', async () => {
  const right = await verifyBundle(clone(), opts());
  assert.equal(right.checks[1].result, 'pass');
  assert.equal(right.ok, true);
  const wrong = clone();
  wrong.salt = newSalt();
  const rw = await results(wrong);
  assert.equal(rw.entry.result, 'fail');
  assert.match(rw.entry.detail, /commitment does not recompute from the record and its salt/);
  for (const c of ['signature', 'merkle', 'sepolia', 'ots']) assert.equal(rw[c].result, 'pass', c);
  const missing = clone();
  delete missing.salt;
  const rm = await results(missing);
  assert.equal(rm.entry.result, 'fail');
  assert.match(rm.entry.detail, /bundle has no salt for the record/);
  const malformed = clone();
  malformed.salt = 'AB'.repeat(32);
  assert.match((await results(malformed)).entry.detail, /bundle salt is not 32 bytes of hex/);
  assert.equal((await verifyBundle(missing, opts())).ok, false);
});

test('a pending OTS proof is reported as pending, not pass or fail', async () => {
  const b = clone();
  b.ots.proof = Buffer.from(otsProof(b.batch.root)).toString('base64');
  const r = await verifyBundle(b, opts());
  assert.equal(r.checks[4].result, 'pending');
  assert.equal(r.ok, true);
});

test('a modified log entry fails the entry check by name', async () => {
  const b = clone();
  b.entry.ts = '2026-01-01T00:00:00.000Z';
  const r = await results(b);
  assert.equal(r.entry.result, 'fail');
  assert.match(r.entry.detail, /entry_hash does not recompute/);
});

test('a bundle that is not a Mohar bundle fails every check', async () => {
  const r = await verifyBundle({ format: 'other' }, opts());
  assert.equal(r.ok, false);
  assert.ok(r.checks.every((c) => c.result === 'fail'));
});
