import Database from 'better-sqlite3';
import { nextEntry } from './chain.mjs';

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

/** The log service's store (one SQLite file). Holds only entry types, commitments, hashes, roots and anchor data. */
export function openLogStore(file) {
  const db = new Database(file);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  db.exec(SCHEMA);

  const last = db.prepare('SELECT seq, entry_hash FROM entries ORDER BY seq DESC LIMIT 1');
  const byCommitment = db.prepare('SELECT * FROM entries WHERE entry_type = ? AND commitment = ?');
  const insert = db.prepare(`INSERT INTO entries (seq, prev_hash, entry_type, commitment, ts, entry_hash)
    VALUES (@seq, @prev_hash, @entry_type, @commitment, @ts, @entry_hash)`);

  return {
    db,
    close: () => db.close(),

    /** Appends an entry, or returns the existing one for the same type and commitment. */
    append: db.transaction((entryType, commitment, ts) => {
      const existing = byCommitment.get(entryType, commitment);
      if (existing) return { entry: existing, created: false };
      const e = nextEntry(last.get() ?? null, entryType, commitment, ts);
      insert.run(e);
      return { entry: { ...e, batch_id: null }, created: true };
    }),

    entryByCommitment: (commitment) => db.prepare('SELECT * FROM entries WHERE commitment = ? ORDER BY seq LIMIT 1').get(commitment),
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
