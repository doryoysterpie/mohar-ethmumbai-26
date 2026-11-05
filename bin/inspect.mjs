#!/usr/bin/env node
// Standalone verifier. Usage: node bin/inspect.mjs <bundle.json>
// Runs five checks on the bundle alone: school signature, log entry, Merkle path, Sepolia calldata, OpenTimestamps.
// Contacts only a public Sepolia RPC (MOHAR_SEPOLIA_RPCS, comma-separated; public defaults otherwise) and a public
// Bitcoin block explorer (MOHAR_ESPLORA_URL, default https://blockstream.info/api). Exit code 0 when the bundle verifies.
import fs from 'node:fs';
import { verifyBundle, esploraHeaders } from '../src/inspector/verify.mjs';

const DEFAULT_RPCS = ['https://ethereum-sepolia-rpc.publicnode.com', 'https://1rpc.io/sepolia'];

const [file] = process.argv.slice(2);
if (!file) {
  console.error('usage: inspect <bundle.json>');
  process.exit(2);
}
let bundle;
try {
  bundle = JSON.parse(fs.readFileSync(file, 'utf8'));
} catch (e) {
  console.error(`cannot read bundle: ${e.message}`);
  process.exit(2);
}
const rpcUrls = (process.env.MOHAR_SEPOLIA_RPCS ?? '').split(',').map((s) => s.trim()).filter(Boolean);
const { ok, checks } = await verifyBundle(bundle, {
  rpcUrls: rpcUrls.length ? rpcUrls : DEFAULT_RPCS,
  bitcoinHeader: esploraHeaders(process.env.MOHAR_ESPLORA_URL),
});
for (const [i, c] of checks.entries()) process.stdout.write(`${i + 1}. ${c.check.padEnd(9)} ${c.result.padEnd(7)} ${c.detail}\n`);
process.stdout.write(ok ? 'verified\n' : 'NOT verified\n');
process.exit(ok ? 0 : 1);
