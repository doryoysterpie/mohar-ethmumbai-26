// Standalone verifier for an export bundle. It reads only the bundle, a public Sepolia RPC and a source of Bitcoin
// block headers; it never contacts the platform or the school.
import { saltedCommitment, isSalt } from '../shared/commitment.mjs';
import { jwkFromDidKey } from '../shared/keys.mjs';
import { decodeJws, verifyJws } from '../shared/jws.mjs';
import { entryHash } from '../log/chain.mjs';
import { rootFromPath, batchRoot } from '../log/merkle.mjs';
import { readAnchorFrom } from '../anchor/sepolia.mjs';
import { otsState, otsBitcoinAttestations } from '../anchor/ots.mjs';
import { certificateCommitment } from '../issuer/credential.mjs';
import { verifyAck } from '../log/ack.mjs';

export const SEPOLIA_CHAIN_ID = 11155111;
const TYP = { receipt: 'receipt+jwt', recheck: 'recheck+jwt' };

/** @typedef {{ check: string, result: 'pass' | 'fail' | 'pending' | 'not supplied', detail: string }} CheckResult */

const pass = (check, detail) => ({ check, result: 'pass', detail });
const fail = (check, detail) => ({ check, result: 'fail', detail });

/** 1. The record is signed by the school did:key it names, resolved offline. */
async function checkSignature(b) {
  try {
    const typ = TYP[b.record_type];
    if (!typ) return fail('signature', `unknown record type ${b.record_type}`);
    const { header, payload } = decodeJws(b.record);
    const school = payload.verifier;
    if (typeof school !== 'string' || !school.startsWith('did:key:')) return fail('signature', 'record names no school did:key');
    if (header.kid !== `${school}#${school.slice('did:key:'.length)}`) return fail('signature', 'record key id is not the school did:key');
    await verifyJws(b.record, jwkFromDidKey(school), typ);
    return pass('signature', `signed by ${school}`);
  } catch (e) {
    return fail('signature', `school signature invalid: ${e.message}`);
  }
}

/** 2. The log entry commits to this record under its salt, and the entry hash recomputes. */
function checkEntry(b) {
  try {
    const e = b.entry;
    if (e.entry_type !== b.record_type) return fail('entry', `log entry type ${e.entry_type} is not ${b.record_type}`);
    if (b.salt === undefined || b.salt === null) return fail('entry', 'bundle has no salt for the record');
    if (!isSalt(b.salt)) return fail('entry', 'bundle salt is not 32 bytes of hex');
    if (e.commitment !== saltedCommitment(b.record, b.salt)) return fail('entry', 'commitment does not recompute from the record and its salt');
    if (entryHash(e.prev_hash, e.entry_type, e.commitment, e.ts) !== e.entry_hash) return fail('entry', 'entry_hash does not recompute');
    return pass('entry', `entry ${e.seq} recomputes`);
  } catch (e) {
    return fail('entry', `log entry malformed: ${e.message}`);
  }
}

/**
 * 3. The entry's Merkle path and the batch header (id, first seq, size, closing time) together recompute the
 * batch root, and the entry's seq is its position in that batch.
 */
function checkMerkle(b) {
  try {
    if (b.merkle_path.size !== b.batch.size) return fail('merkle', 'path size is not the batch size');
    const tree = rootFromPath(b.entry.entry_hash, b.merkle_path);
    const header = { batch_id: b.batch.batch_id, first_seq: b.batch.first_seq, size: b.batch.size, closed_at: b.batch.closed_at };
    if (batchRoot(header, tree) !== b.batch.root) return fail('merkle', 'Merkle path and batch header lead to a different root');
    if (b.entry.seq !== b.batch.first_seq + b.merkle_path.index) return fail('merkle', 'entry seq is not its position in the batch');
    return pass('merkle', `entry seq ${b.entry.seq}, position ${b.merkle_path.index} of ${b.batch.size} in batch ${b.batch.batch_id} closed ${b.batch.closed_at}`);
  } catch (e) {
    return fail('merkle', `Merkle path invalid: ${e.message}`);
  }
}

/** 4. The Sepolia transaction exists and its calldata is the batch root. */
async function checkSepolia(b, rpcUrls) {
  if (!b.sepolia?.tx_hash) return fail('sepolia', 'bundle has no Sepolia anchor');
  if (b.sepolia.chain_id !== SEPOLIA_CHAIN_ID) return fail('sepolia', `anchor is on chain ${b.sepolia.chain_id}, not Sepolia`);
  if (!rpcUrls?.length) return fail('sepolia', 'no Sepolia RPC configured for the check');
  // One RPC answers everything: its chain id, the transaction and its receipt. The first RPC that reports Sepolia
  // and has the transaction is used; any other RPC is skipped.
  const tried = [];
  for (const url of rpcUrls) {
    let tx;
    try {
      tx = await readAnchorFrom(url, b.sepolia.tx_hash);
    } catch (e) {
      tried.push(`${new URL(url).host}: ${e.shortMessage ?? e.message}`);
      continue;
    }
    if (tx.chain_id !== SEPOLIA_CHAIN_ID) { tried.push(`${new URL(url).host}: chain ${tx.chain_id}, not Sepolia`); continue; }
    if (tx.missing) { tried.push(`${new URL(url).host}: no such transaction`); continue; }
    if (tx.status !== 'success') return fail('sepolia', 'Sepolia transaction did not succeed');
    if (tx.calldata !== b.batch.root) return fail('sepolia', 'Sepolia calldata does not match the batch root');
    if (b.sepolia.block_number !== tx.block_number) return fail('sepolia', `bundle says block ${b.sepolia.block_number}; the transaction is in block ${tx.block_number}`);
    return pass('sepolia', `root in tx ${b.sepolia.tx_hash}, block ${tx.block_number} (${new URL(url).host})`);
  }
  return fail('sepolia', `Sepolia transaction not found on a Sepolia RPC: ${tried.join('; ')}`);
}

/** 5. The OpenTimestamps proof is for the batch root, and any Bitcoin attestation matches its block header. */
async function checkOts(b, bitcoinHeader) {
  if (!b.ots?.proof) return fail('ots', 'bundle has no OpenTimestamps proof');
  try {
    const proof = Buffer.from(b.ots.proof, 'base64');
    const state = otsState(proof, b.batch.root);
    if (state.state === 'pending') {
      return { check: 'ots', result: 'pending', detail: `calendar attestation only (${state.calendars.length} calendars); no Bitcoin block yet` };
    }
    const atts = otsBitcoinAttestations(proof, b.batch.root);
    for (const a of atts) {
      const header = await bitcoinHeader(a.height);
      if (header.merkleroot === Buffer.from(a.msg, 'hex').reverse().toString('hex')) {
        return pass('ots', `root in Bitcoin block ${a.height} (${new Date(header.time * 1000).toISOString()})`);
      }
    }
    return fail('ots', `OTS attestation does not match Bitcoin block ${atts.map((a) => a.height).join(', ')}`);
  } catch (e) {
    return fail('ots', `OTS proof invalid: ${e.message}`);
  }
}

/**
 * 6. The log operator's acknowledgement: signed by the published operator key, and its seq, entry_hash and commitment
 * are those of the bundle's log entry. A bundle without one reports 'not supplied'.
 */
async function checkAck(b, operator) {
  if (b.ack === undefined || b.ack === null) return { check: 'acknowledgement', result: 'not supplied', detail: 'bundle carries no acknowledgement from the log operator' };
  if (!operator) return fail('acknowledgement', 'no published operator key configured for the check');
  let a;
  try {
    a = await verifyAck(b.ack, operator);
  } catch (e) {
    return fail('acknowledgement', `acknowledgement invalid: ${e.message}`);
  }
  for (const f of ['seq', 'entry_hash', 'commitment']) {
    if (a[f] !== b.entry?.[f]) return fail('acknowledgement', `acknowledgement ${f} ${a[f]} is not the bundle entry's ${b.entry?.[f]}`);
  }
  return pass('acknowledgement', `operator ${operator.id} acknowledged entry ${a.seq} at ${a.ts}`);
}

/**
 * 7 (optional). The certificate and its salt, obtained from the school's presentation, recompute the receipt's
 * certificate_commitment. Reported as "not supplied" when no certificate and salt are given.
 */
function checkCertificate(b, certificate, salt) {
  if (certificate === undefined && salt === undefined) return { check: 'certificate binding', result: 'not supplied', detail: 'no certificate and salt supplied' };
  try {
    if (certificate === undefined || salt === undefined) return fail('certificate binding', 'certificate and salt must be supplied together');
    const { payload } = decodeJws(b.record);
    if (typeof payload.certificate_commitment !== 'string') return fail('certificate binding', 'record carries no certificate_commitment');
    if (certificateCommitment(certificate, salt) !== payload.certificate_commitment) {
      return fail('certificate binding', 'certificate and salt do not recompute the receipt certificate_commitment');
    }
    return pass('certificate binding', 'certificate and salt recompute the receipt certificate_commitment');
  } catch (e) {
    return fail('certificate binding', `certificate binding cannot be checked: ${e.message}`);
  }
}

/** Bitcoin block header by height from a public Esplora API (default blockstream.info). Returns { merkleroot, time }. */
export function esploraHeaders(base = 'https://blockstream.info/api') {
  return async (height) => {
    const h = await fetch(`${base}/block-height/${height}`, { signal: AbortSignal.timeout(15_000) });
    if (!h.ok) throw new Error(`no Bitcoin block at height ${height}`);
    const hash = (await h.text()).trim();
    const r = await fetch(`${base}/block/${hash}`, { signal: AbortSignal.timeout(15_000) });
    if (!r.ok) throw new Error(`Bitcoin block ${hash} not found`);
    const blk = await r.json();
    return { merkleroot: blk.merkle_root, time: blk.timestamp };
  };
}

/**
 * Runs the six checks on a bundle, and the optional seventh (certificate binding) when a certificate and its salt are
 * supplied. Each check runs whatever the others found. `ok` is true when signature, entry, merkle and sepolia pass,
 * ots passes or is pending, the acknowledgement passes or is not supplied, and certificate binding passes or is not
 * supplied.
 * @param {any} bundle
 * @param {{ rpcUrls?: string[], bitcoinHeader?: (height: number) => Promise<{ merkleroot: string, time: number }>,
 *   operator?: { id: string }, certificate?: Record<string, unknown>, certificateSalt?: string }} [options]
 *   operator is the published operator document (operator.json)
 * @returns {Promise<{ ok: boolean, checks: CheckResult[] }>}
 */
export async function verifyBundle(bundle, options = {}) {
  if (bundle?.format !== 'mohar-bundle/1') {
    const r = fail('format', `not a mohar-bundle/1 bundle`);
    return { ok: false, checks: ['signature', 'entry', 'merkle', 'sepolia', 'ots', 'acknowledgement', 'certificate binding'].map((check) => ({ ...r, check })) };
  }
  const checks = [
    await checkSignature(bundle),
    checkEntry(bundle),
    checkMerkle(bundle),
    await checkSepolia(bundle, options.rpcUrls),
    await checkOts(bundle, options.bitcoinHeader ?? esploraHeaders()),
    await checkAck(bundle, options.operator),
    checkCertificate(bundle, options.certificate, options.certificateSalt),
  ];
  const ok = checks.slice(0, 4).every((c) => c.result === 'pass') && checks.slice(4).every((c) => c.result !== 'fail');
  return { ok, checks };
}
