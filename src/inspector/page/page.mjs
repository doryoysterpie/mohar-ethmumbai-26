// Inspector page: loads a bundle (sample, file or pasted text), runs the standalone verifier in the browser and shows
// one line per check.
import { verifyBundle, esploraHeaders } from '../verify.mjs';

const DEFAULT_RPCS = ['https://ethereum-sepolia-rpc.publicnode.com', 'https://1rpc.io/sepolia'];
const $ = (id) => document.getElementById(id);

async function loadSample() {
  $('status').textContent = 'Loading the sample bundle…';
  try {
    const res = await fetch('../sample/bundle.json', { cache: 'no-store' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    $('bundle').value = JSON.stringify(await res.json(), null, 2);
    $('status').textContent = 'Sample bundle loaded.';
  } catch (e) {
    $('status').textContent = `The sample bundle could not be loaded (${e.message}). Paste or choose a bundle.`;
  }
}

function render(checks, ok) {
  const list = $('results');
  list.replaceChildren();
  // The optional certificate-binding line is shown only when a certificate and salt were supplied.
  checks.filter((c) => !(c.check === 'certificate binding' && c.result === 'not supplied')).forEach((c, i) => {
    const li = document.createElement('li');
    li.className = `check ${c.result.replace(' ', '-')}`;
    const name = document.createElement('span');
    name.className = 'name';
    name.textContent = `${i + 1}. ${c.check}`;
    const result = document.createElement('span');
    result.className = 'result';
    result.textContent = c.result;
    const detail = document.createElement('span');
    detail.className = 'detail';
    detail.textContent = c.detail;
    li.append(name, result, detail);
    list.append(li);
  });
  const verdict = $('verdict');
  verdict.textContent = ok ? 'Verified' : 'Not verified';
  verdict.className = ok ? 'verdict ok' : 'verdict bad';
}

async function run() {
  $('verify').disabled = true;
  $('status').textContent = 'Checking…';
  $('results').replaceChildren();
  $('verdict').textContent = '';
  try {
    let bundle;
    try {
      bundle = JSON.parse($('bundle').value);
    } catch {
      throw new Error('the bundle is not valid JSON');
    }
    const options = { rpcUrls: DEFAULT_RPCS, bitcoinHeader: esploraHeaders() };
    const certText = $('certificate').value.trim();
    const salt = $('salt').value.trim();
    if (certText || salt) {
      if (certText) {
        try { options.certificate = JSON.parse(certText); } catch { throw new Error('the certificate is not valid JSON'); }
      }
      if (salt) options.certificateSalt = salt;
    }
    const { ok, checks } = await verifyBundle(bundle, options);
    render(checks, ok);
    $('status').textContent = 'Done. Only a public Sepolia RPC and a public Bitcoin block explorer were contacted.';
  } catch (e) {
    $('status').textContent = `Could not check: ${e.message}`;
  } finally {
    $('verify').disabled = false;
  }
}

$('file').addEventListener('change', async (ev) => {
  const f = ev.target.files?.[0];
  if (!f) return;
  $('bundle').value = await f.text();
  $('status').textContent = `Loaded ${f.name}.`;
});
$('sample').addEventListener('click', loadSample);
$('verify').addEventListener('click', run);
loadSample();
