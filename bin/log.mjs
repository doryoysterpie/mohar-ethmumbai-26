#!/usr/bin/env node
// Log service. Commands:
//   serve      HTTP service on PORT (default 8081); closes a batch every MOHAR_BATCH_SECONDS (default 3600) when entries wait
//   batch      closes and anchors a batch now, prints it
//   anchor     anchors every closed batch still missing a Sepolia transaction or an OpenTimestamps proof
//   upgrade    upgrades pending OpenTimestamps proofs, prints their states
//   check      re-checks the whole hash chain, prints the first broken seq or "intact"
// Environment: MOHAR_LOG_DB (default log.sqlite), MOHAR_ADMIN_TOKEN (operator routes), MOHAR_SEPOLIA_KEY (0x… operator key),
// MOHAR_SEPOLIA_RPCS (comma-separated, first is preferred), MOHAR_OTS=off to skip OpenTimestamps.
// Keep secrets in a local .env file and run with: node --env-file=.env bin/log.mjs <command>
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { openLogStore } from '../src/log/store.mjs';
import { createLog } from '../src/log/service.mjs';
import { createLogServer } from '../src/log/server.mjs';
import { firstBreak } from '../src/log/chain.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const store = openLogStore(process.env.MOHAR_LOG_DB ?? path.join(ROOT, 'log.sqlite'));

function sepoliaConfig() {
  const key = process.env.MOHAR_SEPOLIA_KEY;
  const rpcUrls = (process.env.MOHAR_SEPOLIA_RPCS ?? '').split(',').map((s) => s.trim()).filter(Boolean);
  if (!key && rpcUrls.length === 0) return null;
  if (!/^0x[0-9a-fA-F]{64}$/.test(key ?? '')) throw new Error('MOHAR_SEPOLIA_KEY must be a 0x-prefixed 32-byte hex key');
  if (rpcUrls.length === 0) throw new Error('MOHAR_SEPOLIA_RPCS is empty');
  return { privateKey: /** @type {`0x${string}`} */ (key), rpcUrls };
}

const log = createLog({ store, sepolia: sepoliaConfig(), ots: process.env.MOHAR_OTS !== 'off' });
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
} else if (cmd === 'check') {
  const at = firstBreak(store.entries());
  process.stdout.write(`${at === -1 ? 'intact' : `broken at seq ${at}`}\n`);
  process.exit(at === -1 ? 0 : 1);
} else {
  console.error('usage: log serve | batch | anchor | upgrade | check');
  process.exit(2);
}
