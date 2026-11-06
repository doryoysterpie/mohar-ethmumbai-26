// End-to-end scenario for export tests: teacher, school and log service with file databases in a temporary folder,
// one closed batch anchored to a local JSON-RPC and stamped with an offline OpenTimestamps proof.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { generatePrivateKey } from 'viem/accounts';
import { openStore } from '../../src/verifier/store.mjs';
import { createSchool } from '../../src/verifier/school.mjs';
import { createServer } from '../../src/verifier/server.mjs';
import { openLogStore } from '../../src/log/store.mjs';
import { createLog } from '../../src/log/service.mjs';
import { createLogServer } from '../../src/log/server.mjs';
import { commitRecord } from '../../src/log/client.mjs';
import { newSalt } from '../../src/shared/commitment.mjs';
import { otsBitcoinAttestations } from '../../src/anchor/ots.mjs';
import { world } from './world.mjs';
import { fakeRpc } from './fake-rpc.mjs';
import { otsProof } from './ots-proof.mjs';
import { generateEd25519 } from '../../src/shared/keys.mjs';
import { operatorDocument } from '../../src/log/ack.mjs';

const listen = (server) => new Promise((r) => server.listen(0, '127.0.0.1', () => r(`http://127.0.0.1:${server.address().port}`)));

/**
 * @param {{ bitcoinHeight?: number }} [options] stamp with a Bitcoin attestation at this height (else pending)
 */
export async function scenario(options = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mohar-export-'));
  const rpc = await fakeRpc();
  const logStore = openLogStore(path.join(dir, 'log.sqlite'));
  const operatorKey = await generateEd25519();
  const operator = operatorDocument(operatorKey.publicJwk);
  const log = createLog({
    store: logStore, ots: true, stamp: async (root) => otsProof(root, { bitcoinHeight: options.bitcoinHeight }),
    sepolia: { privateKey: generatePrivateKey(), rpcUrls: [rpc.url], pollMs: 10 },
    operatorKey: operatorKey.privateJwk,
  });
  const logServer = createLogServer(log);
  const logUrl = await listen(logServer);

  const w = await world({ logUrl });
  const schoolStore = openStore(path.join(dir, 'school.sqlite'));
  const school = createSchool({
    store: schoolStore, schoolPrivateJwk: w.schoolKey.privateJwk, didFetch: w.didFetch, fetchText: w.fetchText, logUrl, clock: () => w.now,
  });
  const schoolServer = createServer(school);
  const schoolUrl = await listen(schoolServer);

  const presentation = await w.present({ nonce: school.nonce().nonce, aud: school.did });
  const consentSalt = newSalt();
  const presentationSalt = newSalt();
  await commitRecord({ logUrl, entryType: 'consent', record: w.consent, salt: consentSalt });
  await commitRecord({ logUrl, entryType: 'presentation', record: presentation, salt: presentationSalt });
  const r = await school.present({ presentation, consent: w.consent, presentation_salt: presentationSalt });
  if (!r.ok) throw new Error(`scenario presentation refused: ${r.refusal} ${r.detail}`);
  w.now = new Date('2027-01-01T00:00:00.000Z');
  const [recheck] = await school.recheck();
  const batch = await log.closeBatch();

  /** A Bitcoin header source that knows the attested block of this batch. */
  const headers = new Map();
  if (options.bitcoinHeight) {
    for (const a of otsBitcoinAttestations(Buffer.from(batch.ots.proof, 'base64'), batch.root)) {
      headers.set(a.height, { merkleroot: Buffer.from(a.msg, 'hex').reverse().toString('hex'), time: 1_793_000_000 });
    }
  }
  const bitcoinHeader = async (h) => {
    const x = headers.get(h);
    if (!x) throw new Error(`no Bitcoin block at height ${h}`);
    return x;
  };

  const fetchBundle = async (id) => fetch(`${schoolUrl}/export/${id}`);
  /** The certificate_salt the teacher disclosed to the school in the presentation. */
  const certificateSalt = presentation.split('~').slice(1, -1)
    .map((d) => JSON.parse(Buffer.from(d, 'base64url')))
    .find((d) => d[1] === 'certificate_salt')[2];

  /** Closes both services and deletes both databases (and their WAL files). Safe to call more than once. */
  let destroyed = false;
  const destroyServices = async () => {
    if (destroyed) return;
    destroyed = true;
    await new Promise((r2) => schoolServer.close(r2));
    await new Promise((r2) => logServer.close(r2));
    schoolStore.close();
    logStore.close();
    for (const f of fs.readdirSync(dir)) fs.rmSync(path.join(dir, f));
    fs.rmdirSync(dir);
  };

  return {
    w, school, schoolStore, logStore, certificateSalt, log, rpc, dir, consentSalt, presentationSalt, schoolUrl, logUrl, receipt: r, recheck, batch, presentation, bitcoinHeader, headers, operator,
    fetchBundle, destroyServices, close: async () => { await destroyServices(); rpc.close(); },
  };
}
