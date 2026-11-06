import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

const ROOT = new URL('..', import.meta.url).pathname;

test('the inspector page builds into one self-contained HTML file without service or Node-only code', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mohar-page-'));
  const out = path.join(dir, 'index.html');
  try {
    execFileSync(process.execPath, [path.join(ROOT, 'bin', 'build-inspector.mjs'), '--out', out], { stdio: 'pipe' });
    const html = fs.readFileSync(out, 'utf8');
    assert.match(html, /<title>Mohar inspector<\/title>/);
    assert.match(html, /SIMULATED\./);
    const scripts = html.match(/<script\b[^>]*>/g) ?? [];
    assert.deepEqual(scripts, ['<script type="module">'], 'one inline module script, nothing loaded from elsewhere');
    assert.equal(html.match(/<\/script/gi).length, 1, 'no </script inside the bundle');
    assert.ok(!/src=["']https?:/.test(html) && !/<link\b/.test(html), 'no external resources');
    for (const marker of ['better-sqlite3', 'bitcore', 'request-promise', 'node:fs']) assert.ok(!html.includes(marker), marker);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('the sample bundle the page loads is a well-formed Mohar bundle', () => {
  const b = JSON.parse(fs.readFileSync(path.join(ROOT, 'site', 'sample', 'bundle.json'), 'utf8'));
  assert.equal(b.format, 'mohar-bundle/1');
  assert.deepEqual(Object.keys(b.batch).sort(), ['batch_id', 'closed_at', 'first_seq', 'root', 'size']);
  assert.equal(b.sepolia.chain_id, 11155111);
  assert.equal(typeof b.ots.proof, 'string');
});
