#!/usr/bin/env node
// Builds the inspector page: bundles src/inspector/page/page.mjs for the browser and writes one self-contained HTML file
// to site/inspector/index.html. Usage: node bin/build-inspector.mjs [--out <file>]
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PAGE = path.join(ROOT, 'src', 'inspector', 'page');
const outIndex = process.argv.indexOf('--out');
const OUT = outIndex === -1 ? path.join(ROOT, 'site', 'inspector', 'index.html') : path.resolve(process.argv[outIndex + 1]);

const result = await build({
  entryPoints: [path.join(PAGE, 'page.mjs')],
  bundle: true,
  write: false,
  format: 'esm',
  platform: 'browser',
  target: ['es2022'],
  minify: true,
  legalComments: 'none',
  metafile: true,
  alias: {
    'node:crypto': path.join(PAGE, 'shims', 'crypto.mjs'),
    crypto: path.join(PAGE, 'shims', 'crypto.mjs'),
  },
  inject: [path.join(PAGE, 'shims', 'buffer.mjs'), path.join(PAGE, 'shims', 'process.mjs')],
  logLevel: 'warning',
});

const inputs = Object.keys(result.metafile.inputs);
const forbidden = inputs.filter((p) => /node_modules\/(opentimestamps|bitcore-lib|request|better-sqlite3)\//.test(p)
  || /src\/(verifier|log)\/(school|server|store|service|client)\.mjs$/.test(p));
if (forbidden.length) throw new Error(`the inspector page must not include: ${forbidden.join(', ')}`);

const js = result.outputFiles[0].text.replace(/<\/script/gi, '<\\/script');
const html = fs.readFileSync(path.join(PAGE, 'index.html'), 'utf8').replace('/*BUNDLE*/', () => js);
fs.mkdirSync(path.dirname(OUT), { recursive: true });
fs.writeFileSync(OUT, html);
console.error(`wrote ${path.relative(ROOT, OUT)} (${Buffer.byteLength(html)} bytes, ${inputs.length} modules)`);
