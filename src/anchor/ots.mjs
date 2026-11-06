import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
/** @type {any} */
const OTS = require('opentimestamps');

/**
 * State of an OpenTimestamps proof, read from the proof itself:
 * `complete` when it carries a Bitcoin block header attestation (with the lowest such height),
 * otherwise `pending` with the calendars it is waiting on.
 * @param {Uint8Array} proof serialized detached timestamp
 * @param {string} rootHex the 32-byte digest the proof must be for
 * @returns {{ state: 'pending' | 'complete', bitcoin_height?: number, calendars: string[] }}
 */
export function otsState(proof, rootHex) {
  let d;
  try {
    d = OTS.DetachedTimestampFile.deserialize(Buffer.from(proof));
  } catch {
    throw new Error('OTS proof cannot be parsed');
  }
  const digest = Buffer.from(d.fileDigest()).toString('hex');
  if (digest !== rootHex) throw new Error('OTS proof is for another digest');
  const heights = [];
  const calendars = [];
  // Walk the whole tree: the library's allAttestations() keys by message, so it drops attestations that share one.
  const walk = (t) => {
    for (const a of t.attestations) {
      if (a instanceof OTS.Notary.BitcoinBlockHeaderAttestation) heights.push(a.height);
      else if (a instanceof OTS.Notary.PendingAttestation) calendars.push(a.uri);
    }
    for (const [, child] of t.ops) walk(child);
  };
  walk(d.timestamp);
  return heights.length ? { state: 'complete', bitcoin_height: Math.min(...heights), calendars } : { state: 'pending', calendars };
}

/**
 * Every Bitcoin block header attestation in a proof, with the message it commits to (hex, as hashed). A block whose
 * merkle root equals this message byte-reversed confirms the attestation. Throws when the proof is for another digest
 * or cannot be parsed.
 * @param {Uint8Array} proof
 * @param {string} rootHex
 * @returns {Array<{ height: number, msg: string }>}
 */
export function otsBitcoinAttestations(proof, rootHex) {
  let d;
  try {
    d = OTS.DetachedTimestampFile.deserialize(Buffer.from(proof));
  } catch {
    throw new Error('OTS proof cannot be parsed');
  }
  if (Buffer.from(d.fileDigest()).toString('hex') !== rootHex) throw new Error('OTS proof is for another digest');
  const out = [];
  const walk = (t) => {
    for (const a of t.attestations) {
      if (a instanceof OTS.Notary.BitcoinBlockHeaderAttestation) out.push({ height: a.height, msg: Buffer.from(t.msg).toString('hex') });
    }
    for (const [, child] of t.ops) walk(child);
  };
  walk(d.timestamp);
  return out;
}

/**
 * Stamps a 32-byte root on the public OpenTimestamps calendars.
 * @param {string} rootHex
 * @returns {Promise<Uint8Array>} serialized detached timestamp
 */
export async function otsStamp(rootHex) {
  if (!/^[0-9a-f]{64}$/.test(rootHex)) throw new Error('root must be 64 lowercase hex characters');
  const d = OTS.DetachedTimestampFile.fromHash(new OTS.Ops.OpSHA256(), Buffer.from(rootHex, 'hex'));
  await OTS.stamp(d);
  return new Uint8Array(d.serializeToBytes());
}

/**
 * Asks the calendars for a Bitcoin attestation. Returns the (possibly unchanged) proof and whether it changed.
 * @param {Uint8Array} proof
 * @returns {Promise<{ proof: Uint8Array, changed: boolean }>}
 */
export async function otsUpgrade(proof) {
  const d = OTS.DetachedTimestampFile.deserialize(Buffer.from(proof));
  const changed = await OTS.upgrade(d);
  return { proof: new Uint8Array(d.serializeToBytes()), changed: Boolean(changed) };
}
