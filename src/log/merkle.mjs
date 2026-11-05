import { sha256 } from '../shared/encoding.mjs';

const hex = (b) => Buffer.from(b).toString('hex');
const bytes = (h) => {
  if (typeof h !== 'string' || !/^[0-9a-f]{64}$/.test(h)) throw new Error('expected 64 lowercase hex characters');
  return Buffer.from(h, 'hex');
};

/** Leaf for a log entry: SHA-256(0x00 || entry_hash). */
export const leafHash = (entryHashHex) => hex(sha256(Buffer.concat([Buffer.from([0x00]), bytes(entryHashHex)])));

/** Padding leaf: SHA-256(0x02). No entry can produce it, because entry leaves are prefixed with 0x00. */
export const EMPTY_LEAF = hex(sha256(Buffer.from([0x02])));

/** Inner node: SHA-256(0x01 || left || right). */
export const nodeHash = (l, r) => hex(sha256(Buffer.concat([Buffer.from([0x01]), bytes(l), bytes(r)])));

/** Smallest power of two ≥ n (n ≥ 1). */
export const paddedSize = (n) => {
  if (!Number.isInteger(n) || n < 1) throw new Error('a batch needs at least one entry');
  let p = 1;
  while (p < n) p *= 2;
  return p;
};

/** All levels of the tree over the entries, padded to a power of two with EMPTY_LEAF. levels[0] = leaves. */
function levels(entryHashes) {
  const size = paddedSize(entryHashes.length);
  let level = entryHashes.map(leafHash);
  while (level.length < size) level.push(EMPTY_LEAF);
  const out = [level];
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) next.push(nodeHash(level[i], level[i + 1]));
    out.push(next);
    level = next;
  }
  return out;
}

/** Root of a batch. */
export function merkleRoot(entryHashes) {
  return levels(entryHashes).at(-1)[0];
}

/**
 * Path from the entry at `index` to the root: one sibling per level, bottom up.
 * @returns {{ index: number, size: number, siblings: string[] }}
 */
export function merklePath(entryHashes, index) {
  if (!Number.isInteger(index) || index < 0 || index >= entryHashes.length) throw new Error('index out of range');
  const ls = levels(entryHashes);
  const siblings = [];
  let i = index;
  for (let d = 0; d < ls.length - 1; d += 1) {
    siblings.push(ls[d][i ^ 1]);
    i >>= 1;
  }
  return { index, size: entryHashes.length, siblings };
}

/**
 * Recomputes the root from an entry hash and its path. `size` is the number of real entries in the batch;
 * the path must have exactly log2(paddedSize(size)) siblings and `index` must be below `size`.
 * @returns {string} the root the path leads to
 */
export function rootFromPath(entryHashHex, { index, size, siblings }) {
  const depth = Math.log2(paddedSize(size));
  if (!Number.isInteger(index) || index < 0 || index >= size) throw new Error('index is not a real entry of the batch');
  if (!Array.isArray(siblings) || siblings.length !== depth) throw new Error(`path must have ${depth} siblings`);
  let h = leafHash(entryHashHex);
  let i = index;
  for (const s of siblings) {
    h = i & 1 ? nodeHash(s, h) : nodeHash(h, s);
    i >>= 1;
  }
  return h;
}
