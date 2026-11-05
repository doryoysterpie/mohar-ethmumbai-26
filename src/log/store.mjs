import Database from 'better-sqlite3';
import { createHmac, timingSafeEqual } from 'node:crypto';
import { nextEntry, firstBreak } from './chain.mjs';

const SCHEMA = `
CREATE TABLE IF NOT EXISTS entries (
  seq INTEGER PRIMARY KEY,
  prev_hash TEXT NOT NULL,
  entry_type TEXT NOT NULL,
  commitment TEXT NOT NULL,
  ts TEXT NOT NULL,
  entry_hash TEXT NOT NULL UNIQUE,
  batch_id INTEGER REFERENCES batches (batch_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS entries_commitment ON entries (entry_type, commitment);
CREATE TABLE IF NOT EXISTS head (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  seq INTEGER NOT NULL,
  entry_hash TEXT NOT NULL,
  mac TEXT
);
CREATE TABLE IF NOT EXISTS batches (
  batch_id INTEGER PRIMARY KEY AUTOINCREMENT,
  first_seq INTEGER NOT NULL,
  last_seq INTEGER NOT NULL,
  size INTEGER NOT NULL,
  root TEXT NOT NULL,
  closed_at TEXT NOT NULL,
  sepolia_tx TEXT,
  sepolia_block INTEGER,
  sepolia_error TEXT,
  ots_proof BLOB,
  ots_state TEXT,
  ots_height INTEGER,
  ots_error TEXT
);
`;

/** HMAC-SHA256 of the head checkpoint under the operator's head key (hex). */
function headMac(keyHex, seq, entryHash) {
  return createHmac('sha256', Buffer.from(keyHex, 'hex')).update(`mohar/head/v1|${seq}|${entryHash}`).digest('hex');
}

/**
 * The log service's store (one SQLite file). Holds only entry types, commitments, hashes, roots and anchor data.
 * The head checkpoint (seq and entry_hash of the last entry ever appended) is authenticated with an HMAC under
 * `headKey` when one is given; the key is kept outside the database. A log with entries and no checkpoint is refused
 * until an operator adopts one explicitly with `adoptHead()`.
 * @param {string} file
 * @param {{ headKey?: string }} [options] 32-byte key as 64 hex characters
 */
export function openLogStore(file, options = {}) {
  const headKey = options.headKey;
  if (headKey !== undefined && !/^[0-9a-f]{64}$/.test(headKey)) throw new Error('head key must be 32 bytes as 64 lowercase hex characters');
  const db = new Database(file);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  db.exec(SCHEMA);
  if (!db.prepare('PRAGMA table_info(head)').all().some((c) => c.name === 'mac')) db.exec('ALTER TABLE head ADD COLUMN mac TEXT');

  const last = db.prepare('SELECT seq, entry_hash FROM entries ORDER BY seq DESC LIMIT 1');
  const byCommitment = db.prepare('SELECT * FROM entries WHERE entry_type = ? AND commitment = ?');
  const insert = db.prepare(`INSERT INTO entries (seq, prev_hash, entry_type, commitment, ts, entry_hash)
    VALUES (@seq, @prev_hash, @entry_type, @commitment, @ts, @entry_hash)`);
  const getHead = db.prepare('SELECT seq, entry_hash, mac FROM head WHERE id = 1');
  const lastClosed = db.prepare('SELECT max(last_seq) AS s FROM batches');
  const putHead = db.prepare('INSERT INTO head (id, seq, entry_hash, mac) VALUES (1, @seq, @entry_hash, @mac) ON CONFLICT (id) DO UPDATE SET seq = @seq, entry_hash = @entry_hash, mac = @mac');
  const setHead = (e) => putHead.run({ seq: e.seq, entry_hash: e.entry_hash, mac: headKey ? headMac(headKey, e.seq, e.entry_hash) : null });

  /** Problems with the head checkpoint itself: missing while entries exist, or not authenticated under the head key. */
  function headProblems() {
    const head = getHead.get() ?? null;
    const tail = last.get() ?? null;
    if (!head) return tail ? ['head checkpoint is missing'] : [];
    if (headKey) {
      const want = Buffer.from(headMac(headKey, head.seq, head.entry_hash), 'hex');
      const got = Buffer.from(typeof head.mac === 'string' ? head.mac : '', 'hex');
      if (got.length !== want.length || !timingSafeEqual(got, want)) return ['head checkpoint is not authenticated by the head key'];
    }
    return [];
  }

  return {
    db,
    close: () => db.close(),

    /** The head checkpoint: seq and entry_hash of the last entry ever appended, or null for an empty log. */
    head: () => { const h = getHead.get(); return h ? { seq: h.seq, entry_hash: h.entry_hash } : null; },
    headProblems,

    /**
     * Explicit one-time adoption of the current tail as the head checkpoint, for a log that has none (or whose
     * checkpoint predates the head key). Refuses unless the whole chain is intact.
     */
    adoptHead: db.transaction(() => {
      const tail = last.get();
      if (!tail) throw new Error('the log is empty; nothing to adopt');
      const problems = headProblems();
      if (problems.length === 0 && getHead.get()) throw new Error('the log already has a valid head checkpoint');
      const all = db.prepare('SELECT * FROM entries ORDER BY seq').all();
      if (firstBreak(all) !== -1) throw new Error('the log chain is broken; no head checkpoint adopted');
      setHead(tail);
      return { seq: tail.seq, entry_hash: tail.entry_hash };
    }),

    /**
     * Appends an entry, or returns the existing one for the same type and commitment.
     * Refuses when the last stored entry is not the head checkpoint (the tail was removed or replaced).
     */
    append: db.transaction((entryType, commitment, ts) => {
      const existing = byCommitment.get(entryType, commitment);
      if (existing) return { entry: existing, created: false };
      const tail = last.get() ?? null;
      const head = getHead.get() ?? null;
      const bad = headProblems();
      if (bad.length) throw new Error(`${bad[0]}; nothing appended`);
      if ((head === null) !== (tail === null) || (head && (head.seq !== tail.seq || head.entry_hash !== tail.entry_hash))) {
        throw new Error('the log tail does not match its head checkpoint; nothing appended');
      }
      const closedTo = lastClosed.get().s;
      if (closedTo !== null && (tail === null || closedTo > tail.seq)) {
        throw new Error(`a closed batch ends at seq ${closedTo}, after the log tail; nothing appended`);
      }
      const e = nextEntry(tail, entryType, commitment, ts);
      insert.run(e);
      setHead(e);
      return { entry: { ...e, batch_id: null }, created: true };
    }),

    entriesByCommitment: (commitment) => db.prepare('SELECT * FROM entries WHERE commitment = ? ORDER BY seq').all(commitment),
    entryByTypeAndCommitment: (entryType, commitment) => byCommitment.get(entryType, commitment),
    entries: () => db.prepare('SELECT * FROM entries ORDER BY seq').all(),
    unbatched: () => db.prepare('SELECT * FROM entries WHERE batch_id IS NULL ORDER BY seq').all(),
    batchEntries: (batchId) => db.prepare('SELECT * FROM entries WHERE batch_id = ? ORDER BY seq').all(batchId),
    batch: (batchId) => db.prepare('SELECT * FROM batches WHERE batch_id = ?').get(batchId),
    batches: () => db.prepare('SELECT * FROM batches ORDER BY batch_id').all(),

    /** Records a closed batch over the given consecutive entries. */
    closeBatch: db.transaction((entries, root, closedAt) => {
      const info = db.prepare('INSERT INTO batches (first_seq, last_seq, size, root, closed_at) VALUES (?, ?, ?, ?, ?)')
        .run(entries[0].seq, entries.at(-1).seq, entries.length, root, closedAt);
      const id = Number(info.lastInsertRowid);
      const mark = db.prepare('UPDATE entries SET batch_id = ? WHERE seq = ? AND batch_id IS NULL');
      for (const e of entries) {
        if (mark.run(id, e.seq).changes !== 1) throw new Error(`entry ${e.seq} is already in a batch`);
      }
      return id;
    }),

    setSepolia(batchId, { tx, block, error }) {
      db.prepare('UPDATE batches SET sepolia_tx = ?, sepolia_block = ?, sepolia_error = ? WHERE batch_id = ?')
        .run(tx ?? null, block ?? null, error ?? null, batchId);
    },

    setOts(batchId, { proof, state, height, error }) {
      db.prepare('UPDATE batches SET ots_proof = ?, ots_state = ?, ots_height = ?, ots_error = ? WHERE batch_id = ?')
        .run(proof ? Buffer.from(proof) : null, state ?? null, height ?? null, error ?? null, batchId);
    },
  };
}
