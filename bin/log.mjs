#!/usr/bin/env node
// Log service. Commands:
//   serve      HTTP service on PORT (default 8081); closes a batch every MOHAR_BATCH_SECONDS (default 3600) when entries wait
//   batch      closes and anchors a batch now, prints it
//   anchor     anchors every closed batch still missing a Sepolia transaction or an OpenTimestamps proof
//   upgrade    upgrades pending OpenTimestamps proofs, prints their states
//   operator-keygen  makes the operator signing key (.keys/log-operator.json) and writes site/operator.json
//   equivocation <ack-a> <ack-b> [--operator operator.json]  reports two signed acknowledgements for the same seq
//              with different entry hashes (exit 3), showing both signatures
//   adopt-head one-time, explicit: takes the current tail as the head checkpoint of a log that has none (or none under
//              the current head key); refuses unless the chain is intact
//   check      re-checks the chain, the head checkpoint and every closed batch root; --anchors also compares each
//              anchored root with its Sepolia calldata; prints the problems or "intact"
// Environment: MOHAR_LOG_DB (default log.sqlite), MOHAR_ADMIN_TOKEN (operator routes), MOHAR_SEPOLIA_KEY (0x… operator key),
// MOHAR_SEPOLIA_RPCS (comma-separated, first is preferred), MOHAR_OTS=off to skip OpenTimestamps,
// MOHAR_LOG_HEAD_KEY (32-byte hex key that authenticates the head checkpoint; kept outside the database).
// Keep secrets in a local .env file and run with: node --env-file=.env bin/log.mjs <command>
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { openLogStore } from '../src/log/store.mjs';
import { createLog } from '../src/log/service.mjs';
import { createLogServer } from '../src/log/server.mjs';
import { logProblems } from '../src/log/integrity.mjs';
import { readAnchor } from '../src/anchor/sepolia.mjs';
import { generateEd25519 } from '../src/shared/keys.mjs';
import { operatorDocument, compareAcks } from '../src/log/ack.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OPERATOR_KEY_FILE = process.env.MOHAR_LOG_OPERATOR_KEY_FILE ?? path.join(ROOT, '.keys', 'log-operator.json');
const OPERATOR_DOC = path.join(ROOT, 'site', 'operator.json');
const operatorKey = fs.existsSync(OPERATOR_KEY_FILE) ? JSON.parse(fs.readFileSync(OPERATOR_KEY_FILE, 'utf8')).privateJwk : undefined;
const store = openLogStore(process.env.MOHAR_LOG_DB ?? path.join(ROOT, 'log.sqlite'), { headKey: process.env.MOHAR_LOG_HEAD_KEY || undefined });

function sepoliaConfig() {
  const key = process.env.MOHAR_SEPOLIA_KEY;
  const rpcUrls = (process.env.MOHAR_SEPOLIA_RPCS ?? '').split(',').map((s) => s.trim()).filter(Boolean);
  if (!key && rpcUrls.length === 0) return null;
  if (!/^0x[0-9a-fA-F]{64}$/.test(key ?? '')) throw new Error('MOHAR_SEPOLIA_KEY must be a 0x-prefixed 32-byte hex key');
  if (rpcUrls.length === 0) throw new Error('MOHAR_SEPOLIA_RPCS is empty');
  return { privateKey: /** @type {`0x${string}`} */ (key), rpcUrls };
}

const log = createLog({ store, sepolia: sepoliaConfig(), ots: process.env.MOHAR_OTS !== 'off', operatorKey });
const print = (v) => process.stdout.write(`${JSON.stringify(v, null, 2)}\n`);
const [cmd] = process.argv.slice(2);

if (cmd === 'serve') {
  const port = Number(process.env.PORT ?? 8081);
  const every = Number(process.env.MOHAR_BATCH_SECONDS ?? 3600);
  createLogServer(log, { adminToken: process.env.MOHAR_ADMIN_TOKEN }).listen(port, () => {
    console.error(`log listening on ${port}; batch every ${every} s${process.env.MOHAR_ADMIN_TOKEN ? '' : '; operator routes disabled'}`);
  });
  let running = false;
  setInterval(async () => {
    if (running) return;
    running = true;
    try {
      const b = await log.closeBatch();
      if (b) console.error(`batch ${b.batch_id}: ${b.size} entries, root ${b.root}, sepolia ${b.sepolia.state}, ots ${b.ots.state}`);
      await log.anchorPending();
      await log.upgradePending();
    } catch (e) {
      console.error(`batch failed: ${e.message}`);
    } finally {
      running = false;
    }
  }, every * 1000).unref?.();
} else if (cmd === 'batch') {
  print(await log.closeBatch());
} else if (cmd === 'anchor') {
  print(await log.anchorPending());
} else if (cmd === 'upgrade') {
  print(await log.upgradePending());
} else if (cmd === 'operator-keygen') {
  if (fs.existsSync(OPERATOR_KEY_FILE)) throw new Error(`${OPERATOR_KEY_FILE} exists`);
  const { privateJwk, publicJwk } = await generateEd25519();
  fs.mkdirSync(path.dirname(OPERATOR_KEY_FILE), { recursive: true });
  fs.writeFileSync(OPERATOR_KEY_FILE, `${JSON.stringify({ privateJwk }, null, 2)}\n`, { mode: 0o600 });
  fs.writeFileSync(OPERATOR_DOC, `${JSON.stringify(operatorDocument(publicJwk), null, 2)}\n`);
  print(operatorDocument(publicJwk));
} else if (cmd === 'equivocation') {
  const [, a, b] = process.argv.slice(2);
  const docFile = process.argv.includes('--operator') ? process.argv[process.argv.indexOf('--operator') + 1] : OPERATOR_DOC;
  if (!a || !b) throw new Error('usage: log equivocation <ack-a> <ack-b> [--operator operator.json]');
  const read = (x) => fs.readFileSync(x, 'utf8').trim();
  const out = await compareAcks(read(a), read(b), JSON.parse(read(docFile)));
  print({ equivocation: out.equivocation, reason: out.reason, seq: out.seq, a: { ...out.a, signature: read(a).split('.')[2] }, b: { ...out.b, signature: read(b).split('.')[2] } });
  process.exit(out.equivocation ? 3 : 0);
} else if (cmd === 'adopt-head') {
  print(store.adoptHead());
} else if (cmd === 'check') {
  const problems = logProblems(store);
  if (process.argv.includes('--anchors')) {
    const rpcUrls = (process.env.MOHAR_SEPOLIA_RPCS ?? '').split(',').map((s) => s.trim()).filter(Boolean);
    for (const b of store.batches()) {
      if (!b.sepolia_tx) continue;
      try {
        const tx = await readAnchor({ txHash: b.sepolia_tx, rpcUrls });
        if (tx.calldata !== b.root) problems.push(`batch ${b.batch_id} stored root differs from its Sepolia anchor`);
      } catch (e) {
        problems.push(`batch ${b.batch_id} Sepolia anchor could not be read: ${e.message}`);
      }
    }
  }
  process.stdout.write(problems.length ? `${problems.join('\n')}\n` : 'intact\n');
  process.exit(problems.length ? 1 : 0);
} else {
  console.error('usage: log serve | batch | anchor | upgrade | check [--anchors] | adopt-head | operator-keygen | equivocation <ack-a> <ack-b>');
  process.exit(2);
}
