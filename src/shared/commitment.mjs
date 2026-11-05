import { createHash, randomBytes } from 'node:crypto';

/** Domain string of every log commitment. */
export const COMMIT_DOMAIN = 'mohar/commit/v1';

const SALT_HEX = /^[0-9a-f]{64}$/;

/** A fresh 32-byte salt from the system CSPRNG, as 64 lowercase hex characters. */
export function newSalt() {
  return randomBytes(32).toString('hex');
}

/** True for a 32-byte salt written as 64 lowercase hex characters. */
export const isSalt = (s) => typeof s === 'string' && SALT_HEX.test(s);

/**
 * Commitment to a record: SHA-256("mohar/commit/v1" || salt || record), with the domain as ASCII bytes, the salt as
 * its 32 raw bytes and the record as the UTF-8 bytes of the exact string that was signed or sent.
 * Without the salt, the commitment cannot be recomputed from the record or from anything inside it.
 * @param {string} record
 * @param {string} salt 64 lowercase hex characters
 * @returns {string} 64 lowercase hex characters
 */
export function saltedCommitment(record, salt) {
  if (typeof record !== 'string' || record.length === 0) throw new Error('record must be a non-empty string');
  if (!isSalt(salt)) throw new Error('salt must be 32 bytes as 64 lowercase hex characters');
  return createHash('sha256')
    .update(Buffer.from(COMMIT_DOMAIN, 'ascii'))
    .update(Buffer.from(salt, 'hex'))
    .update(Buffer.from(record, 'utf8'))
    .digest('hex');
}
