#!/usr/bin/env node
// Standalone verifier.
// Usage: node bin/inspect.mjs <bundle.json> [--operator operator.json] [--certificate <certificate.json> --certificate-salt <hex>]
// Runs six checks on the bundle alone: school signature, log entry, Merkle path, Sepolia calldata, OpenTimestamps and
// the log operator's acknowledgement, checked under the published operator key (site/operator.json by default); and a
// seventh, certificate binding, when a certificate and its salt (from the school's presentation) are supplied.
// Contacts only a public Sepolia RPC (MOHAR_SEPOLIA_RPCS, comma-separated; public defaults otherwise) and a public
// Bitcoin block explorer (MOHAR_ESPLORA_URL, default https://blockstream.info/api). Exit code 0 when the bundle verifies.
import fs from 'node:fs';
import { verifyBundle, esploraHeaders } from '../src/inspector/verify.mjs';

const DEFAULT_RPCS = ['https://ethereum-sepolia-rpc.publicnode.com', 'https://1rpc.io/sepolia'];
const USAGE = 'usage: inspect <bundle.json> [--operator operator.json] [--certificate <certificate.json> --certificate-salt <hex>]';

const argv = process.argv.slice(2);
const given = (name) => argv.includes(name);
const flag = (name) => { const i = argv.indexOf(name); return i === -1 ? undefined : argv[i + 1]; };
const file = argv[0];
const missingValue = ['--operator', '--certificate', '--certificate-salt'].some((f) => given(f) && (!flag(f) || flag(f).startsWith('--')));
if (!file || file.startsWith('--') || missingValue) {
  console.error(USAGE);
  process.exit(2);
}
const operatorFile = flag('--operator') ?? new URL('../site/operator.json', import.meta.url).pathname;
let operator;
try {
  operator = JSON.parse(fs.readFileSync(operatorFile, 'utf8'));
} catch (e) {
  console.error(`cannot read operator key: ${e.message}`);
  process.exit(2);
}
const certificateFile = flag('--certificate');
const certificateSalt = flag('--certificate-salt');
const certificate = certificateFile ? JSON.parse(fs.readFileSync(certificateFile, 'utf8')) : undefined;
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
  operator,
  certificate,
  certificateSalt,
});
for (const [i, c] of checks.entries()) process.stdout.write(`${i + 1}. ${c.check.padEnd(19)} ${c.result.padEnd(12)} ${c.detail}\n`);
process.stdout.write(ok ? 'verified\n' : 'NOT verified\n');
process.exit(ok ? 0 : 1);
