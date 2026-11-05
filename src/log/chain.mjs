import { sha256Hex } from '../shared/encoding.mjs';

export const ENTRY_TYPES = ['consent', 'presentation', 'receipt', 'recheck'];

/** prev_hash of the first entry (seq 0). */
export const GENESIS = '0'.repeat(64);

const HEX64 = /^[0-9a-f]{64}$/;
const TS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

/**
 * Throws unless the entry type is known and the commitment is a lowercase SHA-256 hex string.
 * This is the only input the log accepts.
 */
export function assertCommitment(entryType, commitment) {
  if (!ENTRY_TYPES.includes(entryType)) throw new Error(`unknown entry type ${entryType}`);
  if (typeof commitment !== 'string' || !HEX64.test(commitment)) throw new Error('commitment must be 64 lowercase hex characters');
}

/**
 * entry_hash = SHA-256(prev_hash || entry_type || commitment || ts), all as UTF-8 text.
 * Every field has a fixed format, so the concatenation is unambiguous.
 */
export function entryHash(prevHash, entryType, commitment, ts) {
  if (!HEX64.test(prevHash)) throw new Error('prev_hash must be 64 lowercase hex characters');
  assertCommitment(entryType, commitment);
  if (!TS.test(ts)) throw new Error('ts must be an ISO 8601 UTC timestamp with milliseconds');
  return sha256Hex(`${prevHash}${entryType}${commitment}${ts}`);
}

/**
 * Next entry after `prev` (or the first entry when `prev` is null).
 * @param {{ seq: number, entry_hash: string } | null} prev
 */
export function nextEntry(prev, entryType, commitment, ts) {
  const seq = prev ? prev.seq + 1 : 0;
  const prevHash = prev ? prev.entry_hash : GENESIS;
  return { seq, prev_hash: prevHash, entry_type: entryType, commitment, ts, entry_hash: entryHash(prevHash, entryType, commitment, ts) };
}

/**
 * Checks a run of consecutive entries. Returns the seq of the first broken entry, or -1 when the run is intact.
 * When `prev` is given, the run must continue from it; otherwise it must start at seq 0 from GENESIS.
 * @param {Array<{ seq: number, prev_hash: string, entry_type: string, commitment: string, ts: string, entry_hash: string }>} entries
 * @param {{ seq: number, entry_hash: string } | null} [prev]
 */
export function firstBreak(entries, prev = null) {
  let expectSeq = prev ? prev.seq + 1 : 0;
  let expectPrev = prev ? prev.entry_hash : GENESIS;
  for (const e of entries) {
    let ok = e.seq === expectSeq && e.prev_hash === expectPrev;
    if (ok) {
      try { ok = entryHash(e.prev_hash, e.entry_type, e.commitment, e.ts) === e.entry_hash; } catch { ok = false; }
    }
    if (!ok) return e.seq;
    expectSeq += 1;
    expectPrev = e.entry_hash;
  }
  return -1;
}
