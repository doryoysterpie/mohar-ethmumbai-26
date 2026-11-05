// Builds OpenTimestamps proofs offline for tests: a pending proof (calendar attestation only) and a complete one.
import { createRequire } from 'node:module';

const OTS = createRequire(import.meta.url)('opentimestamps');

/**
 * @param {string} rootHex
 * @param {{ bitcoinHeight?: number }} [options] add a Bitcoin block header attestation at this height
 * @returns {Uint8Array}
 */
export function otsProof(rootHex, options = {}) {
  const d = OTS.DetachedTimestampFile.fromHash(new OTS.Ops.OpSHA256(), Buffer.from(rootHex, 'hex'));
  const leaf = d.timestamp.add(new OTS.Ops.OpAppend(Buffer.from('00112233445566778899aabbccddeeff', 'hex'))).add(new OTS.Ops.OpSHA256());
  leaf.attestations.push(new OTS.Notary.PendingAttestation('https://calendar.example.test'));
  if (options.bitcoinHeight) leaf.attestations.push(new OTS.Notary.BitcoinBlockHeaderAttestation(options.bitcoinHeight));
  return new Uint8Array(d.serializeToBytes());
}
