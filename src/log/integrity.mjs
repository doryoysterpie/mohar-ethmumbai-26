import { firstBreak } from './chain.mjs';
import { merkleRoot } from './merkle.mjs';

/**
 * Checks the whole stored log: the hash chain from the genesis constant, the tail against the head checkpoint,
 * and every closed batch (consecutive, non-overlapping, sizes right, root recomputed from its entries).
 * Returns the problems found; an empty list means the stored log is consistent with itself.
 * With a head key, the checkpoint cannot be rewritten without that key; without one, a change made consistently to
 * the entries, the head and the batches together is visible only by comparing stored roots with their external
 * anchors (see `check --anchors`), for anchored batches.
 * @param {ReturnType<typeof import('./store.mjs').openLogStore>} store
 * @returns {string[]}
 */
export function logProblems(store) {
  const problems = [];
  const entries = store.entries();
  const at = firstBreak(entries);
  if (at !== -1) problems.push(`hash chain broken at seq ${at}`);

  const head = store.head();
  const tail = entries.at(-1) ?? null;
  problems.push(...store.headProblems());
  if (head === null && tail === null) { /* empty log */ } else if (head === null) { /* reported by headProblems */ } else if (tail === null) problems.push('head checkpoint names an entry but the log is empty');
  else if (head && (head.seq !== tail.seq || head.entry_hash !== tail.entry_hash)) {
    problems.push(`tail is seq ${tail.seq} but the head checkpoint is seq ${head.seq}`);
  }

  let next = 0;
  for (const b of store.batches()) {
    if (b.first_seq !== next) problems.push(`batch ${b.batch_id} starts at seq ${b.first_seq}, expected ${next}`);
    const rows = store.batchEntries(b.batch_id);
    const seqs = rows.map((r) => r.seq);
    const contiguous = rows.length === b.size && b.last_seq - b.first_seq + 1 === b.size
      && seqs.every((s, i) => s === b.first_seq + i);
    if (!contiguous) problems.push(`batch ${b.batch_id} does not hold seq ${b.first_seq}–${b.last_seq} exactly`);
    else if (merkleRoot(rows.map((r) => r.entry_hash)) !== b.root) problems.push(`batch ${b.batch_id} root does not recompute`);
    next = b.last_seq + 1;
  }
  const loose = entries.filter((e) => e.batch_id === null);
  if (loose.some((e) => e.seq < next)) problems.push('an unbatched entry sits before the last closed batch');
  return problems;
}
