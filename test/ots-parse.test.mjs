import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import { parseOts, otsProofState } from '../src/anchor/ots-parse.mjs';
import { otsState, otsBitcoinAttestations } from '../src/anchor/ots.mjs';
import { sha256Hex } from '../src/shared/encoding.mjs';
import { otsProof } from './helpers/ots-proof.mjs';

const OTS = createRequire(import.meta.url)('opentimestamps');

/** A proof with two calendar branches and Bitcoin attestations on both, built with the library. */
function forkedProof(rootHex) {
  const d = OTS.DetachedTimestampFile.fromHash(new OTS.Ops.OpSHA256(), Buffer.from(rootHex, 'hex'));
  const a = d.timestamp.add(new OTS.Ops.OpAppend(Array.from(Buffer.from('aa'.repeat(16), 'hex')))).add(new OTS.Ops.OpSHA256());
  a.attestations.push(new OTS.Notary.PendingAttestation('https://a.example.test'));
  a.attestations.push(new OTS.Notary.BitcoinBlockHeaderAttestation(905001));
  const b = d.timestamp.add(new OTS.Ops.OpPrepend(Array.from(Buffer.from('bb'.repeat(8), 'hex')))).add(new OTS.Ops.OpSHA256()).add(new OTS.Ops.OpReverse());
  b.attestations.push(new OTS.Notary.BitcoinBlockHeaderAttestation(905000));
  return new Uint8Array(d.serializeToBytes());
}

function sample() {
  const b = JSON.parse(fs.readFileSync(new URL('../site/sample/bundle.json', import.meta.url), 'utf8'));
  return [Uint8Array.from(Buffer.from(b.ots.proof, 'base64')), b.batch.root];
}

test('the reader agrees with the OpenTimestamps library on every proof shape', () => {
  const r = sha256Hex('root');
  const cases = [['pending', otsProof(r), r], ['complete', otsProof(r, { bitcoinHeight: 905123 }), r], ['forked', forkedProof(r), r], ['sample bundle', ...sample()]];
  for (const [name, proof, root] of cases) {
    const mine = otsProofState(proof, root);
    const lib = otsState(proof, root);
    assert.equal(mine.state, lib.state, name);
    assert.equal(mine.bitcoin_height ?? null, lib.bitcoin_height ?? null, name);
    assert.deepEqual([...mine.calendars].sort(), [...lib.calendars].sort(), name);
    assert.deepEqual(mine.bitcoin.map((a) => `${a.height}:${a.msg}`).sort(), otsBitcoinAttestations(proof, root).map((a) => `${a.height}:${a.msg}`).sort(), name);
  }
});

test('the reader refuses a proof for another digest, and malformed or hostile proofs', () => {
  const r = sha256Hex('root');
  const good = otsProof(r);
  assert.throws(() => otsProofState(good, sha256Hex('other')), /another digest/);
  assert.throws(() => parseOts(new Uint8Array([1, 2, 3])), /ends early|not an OpenTimestamps/);
  assert.throws(() => parseOts(good.slice(0, good.length - 5)), /ends early/);
  assert.throws(() => parseOts(new Uint8Array([...good, 0])), /trailing bytes/);
  assert.throws(() => parseOts(new Uint8Array(70 * 1024)), /too large/);
  const badMagic = Uint8Array.from(good);
  badMagic[1] ^= 0xff;
  assert.throws(() => parseOts(badMagic), /not an OpenTimestamps proof/);
  // An unknown operation tag right after the file digest.
  const header = good.slice(0, 31 + 1 + 1 + 32);
  assert.throws(() => parseOts(new Uint8Array([...header, 0x99])), /unknown OTS operation/);
  // 300 nested sha256 operations exceed the depth limit.
  assert.throws(() => parseOts(new Uint8Array([...header, ...new Array(300).fill(0x08), 0x00])), /nests too deeply|ends early/);
  assert.throws(() => parseOts('not bytes'), /must be bytes/);
});
