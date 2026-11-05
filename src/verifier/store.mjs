import Database from 'better-sqlite3';
import { randomBytes } from 'node:crypto';
import { toBase64url } from '../shared/encoding.mjs';

const SCHEMA = `
CREATE TABLE IF NOT EXISTS nonces (
  nonce TEXT PRIMARY KEY,
  issued_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at INTEGER
);
CREATE TABLE IF NOT EXISTS receipts (
  receipt_id TEXT PRIMARY KEY,
  holder_did TEXT NOT NULL,
  presentation TEXT NOT NULL,
  consent TEXT NOT NULL,
  receipt TEXT NOT NULL,
  status_ref TEXT NOT NULL,
  issuer TEXT NOT NULL,
  status_result TEXT NOT NULL,
  verified_at TEXT NOT NULL,
  recheck_due TEXT NOT NULL,
  valid_until TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS receipts_holder ON receipts (holder_did, verified_at);
CREATE TABLE IF NOT EXISTS rechecks (
  recheck_id TEXT PRIMARY KEY,
  receipt_id TEXT NOT NULL REFERENCES receipts (receipt_id),
  recheck TEXT NOT NULL,
  status_result TEXT NOT NULL,
  checked_at TEXT NOT NULL,
  next_recheck_due TEXT NOT NULL,
  alert INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS rechecks_receipt ON rechecks (receipt_id, checked_at);
CREATE TABLE IF NOT EXISTS refusals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  presentation_hash TEXT NOT NULL,
  reason TEXT NOT NULL,
  refused_at TEXT NOT NULL
);
`;

/**
 * The school's local store (one SQLite file).
 * @param {string} file path, or ':memory:'
 */
export function openStore(file) {
  const db = new Database(file);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  db.exec(SCHEMA);

  const consume = db.prepare('UPDATE nonces SET used_at = ? WHERE nonce = ? AND used_at IS NULL AND expires_at >= ?');
  const lookup = db.prepare('SELECT used_at, expires_at FROM nonces WHERE nonce = ?');

  return {
    db,
    close: () => db.close(),

    /** New single-use nonce valid for `ttlSeconds`. */
    issueNonce(nowSeconds, ttlSeconds = 600) {
      const nonce = toBase64url(randomBytes(24));
      db.prepare('INSERT INTO nonces (nonce, issued_at, expires_at) VALUES (?, ?, ?)').run(nonce, nowSeconds, nowSeconds + ttlSeconds);
      return { nonce, expires_at: nowSeconds + ttlSeconds };
    },

    /**
     * Marks a nonce used. Returns 'ok' only the first time, for a nonce this school issued and that has not expired.
     * @returns {'ok' | 'unknown' | 'used' | 'expired'}
     */
    consumeNonce(nonce, nowSeconds) {
      if (typeof nonce !== 'string') return 'unknown';
      if (consume.run(nowSeconds, nonce, nowSeconds).changes === 1) return 'ok';
      const row = lookup.get(nonce);
      if (!row) return 'unknown';
      return row.used_at !== null ? 'used' : 'expired';
    },

    saveReceipt(r) {
      db.prepare(`INSERT INTO receipts (receipt_id, holder_did, presentation, consent, receipt, status_ref, issuer, status_result,
        verified_at, recheck_due, valid_until) VALUES (@receipt_id, @holder_did, @presentation, @consent, @receipt, @status_ref,
        @issuer, @status_result, @verified_at, @recheck_due, @valid_until)`).run(r);
    },

    saveRecheck(r) {
      db.prepare(`INSERT INTO rechecks (recheck_id, receipt_id, recheck, status_result, checked_at, next_recheck_due, alert)
        VALUES (@recheck_id, @receipt_id, @recheck, @status_result, @checked_at, @next_recheck_due, @alert)`).run(r);
    },

    saveRefusal(presentationHash, reason, refusedAt) {
      db.prepare('INSERT INTO refusals (presentation_hash, reason, refused_at) VALUES (?, ?, ?)').run(presentationHash, reason, refusedAt);
    },

    receipt: (id) => db.prepare('SELECT * FROM receipts WHERE receipt_id = ?').get(id),
    latestReceipt: (holderDid) => db.prepare('SELECT * FROM receipts WHERE holder_did = ? ORDER BY verified_at DESC, rowid DESC LIMIT 1').get(holderDid),
    latestRecheck: (receiptId) => db.prepare('SELECT * FROM rechecks WHERE receipt_id = ? ORDER BY checked_at DESC, rowid DESC LIMIT 1').get(receiptId),
    /** Receipts whose consent is still valid at `atIso`. */
    activeReceipts: (atIso) => db.prepare('SELECT * FROM receipts WHERE valid_until >= ? ORDER BY verified_at').all(atIso),
    refusals: () => db.prepare('SELECT * FROM refusals ORDER BY id').all(),
  };
}
