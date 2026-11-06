import { test } from 'node:test';
import assert from 'node:assert/strict';
import { saltedCommitment, newSalt, isSalt, COMMIT_DOMAIN } from '../src/shared/commitment.mjs';

test('the commitment is SHA-256("mohar/commit/v1" || salt || record) (fixed vectors)', () => {
  assert.equal(COMMIT_DOMAIN, 'mohar/commit/v1');
  // Computed independently of this module: sha256(ascii domain || 32 raw salt bytes || UTF-8 record).
  assert.equal(saltedCommitment('record', '11'.repeat(32)), '325d7b729f704875e75dfdd01ca8a242bc7235254aea504c5bdc163658a239b7');
  assert.equal(saltedCommitment('नमस्ते', `${'00'.repeat(31)}01`), 'f0cf77fc25644f88a1b5e7306ddac1d4a903ed59fa0c2749b7cc7ff2d90bad03');
});

test('salts are 32 fresh bytes and malformed salts are refused', () => {
  const salts = new Set(Array.from({ length: 100 }, newSalt));
  assert.equal(salts.size, 100);
  for (const s of salts) assert.ok(isSalt(s));
  for (const bad of [undefined, '', 'ab', 'AB'.repeat(32), '0'.repeat(63), '0'.repeat(65), 12]) {
    assert.throws(() => saltedCommitment('record', bad), /salt must be 32 bytes/);
  }
  assert.throws(() => saltedCommitment('', newSalt()), /record must be a non-empty string/);
});

test('the certificate commitment is SHA-256("mohar/cert/v1" || salt || canonical JSON) (fixed vector)', async () => {
  const { certificateCommitment, CERT_DOMAIN } = await import('../src/issuer/credential.mjs');
  assert.equal(CERT_DOMAIN, 'mohar/cert/v1');
  // Computed independently: sha256(ascii domain || 32 raw salt bytes || UTF-8 canonical JSON {"a":1,"b":"x"}).
  assert.equal(certificateCommitment({ b: 'x', a: 1 }, '22'.repeat(32)), 'c08051d97fe16f4bb7b4bfe3493ef65d8e4ac68b3dfb68b912078f7a57526f09');
  assert.throws(() => certificateCommitment({ a: 1 }, 'ab'), /certificate salt must be 32 bytes/);
});
