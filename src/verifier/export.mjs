import { sha256Hex } from '../shared/encoding.mjs';

export const BUNDLE_FORMAT = 'mohar-bundle/1';

/**
 * Asks the log service for the proof of a record's commitment.
 * @param {{ logUrl: string, commitment: string, fetch?: typeof fetch }} p
 * @returns {Promise<object | null>} null when the log has no entry for it
 */
export async function fetchProof({ logUrl, commitment, fetch: f = fetch }) {
  const res = await f(new URL(`proof/${commitment}`, logUrl.endsWith('/') ? logUrl : `${logUrl}/`), { signal: AbortSignal.timeout(10_000) });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`log service answered HTTP ${res.status}`);
  return res.json();
}

/**
 * Export bundle for a signed receipt or re-check receipt: the record, its log entry, its Merkle path, the batch root
 * and both anchors. Everything an inspector needs; nothing from the presentation or the consent.
 * @param {{ record: string, recordType: 'receipt' | 'recheck', proof: any }} p
 */
export function buildBundle({ record, recordType, proof }) {
  if (!proof?.entry) throw new Error('the log has no entry for this record');
  if (proof.entry.commitment !== sha256Hex(record)) throw new Error('the log entry is for another record');
  if (!proof.batch || !proof.merkle_path) throw new Error('the record is not in a closed batch yet');
  const { batch } = proof;
  return {
    format: BUNDLE_FORMAT,
    record_type: recordType,
    record,
    entry: {
      seq: proof.entry.seq,
      prev_hash: proof.entry.prev_hash,
      entry_type: proof.entry.entry_type,
      commitment: proof.entry.commitment,
      ts: proof.entry.ts,
      entry_hash: proof.entry.entry_hash,
    },
    merkle_path: { index: proof.merkle_path.index, size: proof.merkle_path.size, siblings: [...proof.merkle_path.siblings] },
    batch: { batch_id: batch.batch_id, root: batch.root, size: batch.size, closed_at: batch.closed_at },
    sepolia: batch.sepolia?.tx_hash
      ? { chain_id: batch.sepolia.chain_id, tx_hash: batch.sepolia.tx_hash, block_number: batch.sepolia.block_number }
      : null,
    ots: batch.ots?.proof ? { proof: batch.ots.proof } : null,
  };
}
