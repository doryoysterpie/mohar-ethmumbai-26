// Reader for OpenTimestamps detached proofs, with no dependency on Node built-ins, so the same code runs in the
// browser. It parses the proof, applies every operation, and lists each attestation with the message it attests.
import { sha256 } from '@noble/hashes/sha256';
import { sha1 } from '@noble/hashes/sha1';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { keccak_256 } from '@noble/hashes/sha3';

const MAGIC = Uint8Array.from([
  0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00, 0x00, 0x50, 0x72, 0x6f,
  0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94,
]);
const PENDING = '83dfe30d2ef90c8e';
const BITCOIN = '0588960d73d71901';
const MAX_PROOF = 64 * 1024;
const MAX_DEPTH = 256;
const MAX_MSG = 4096;

const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const concat = (a, b) => { const o = new Uint8Array(a.length + b.length); o.set(a, 0); o.set(b, a.length); return o; };

const UNARY = {
  0x02: (m) => sha1(m),
  0x03: (m) => ripemd160(m),
  0x08: (m) => sha256(m),
  0x67: (m) => keccak_256(m),
  0xf2: (m) => Uint8Array.from(m).reverse(),
  0xf3: (m) => new TextEncoder().encode(hex(m)),
};
const BINARY = {
  0xf0: (m, arg) => concat(m, arg),
  0xf1: (m, arg) => concat(arg, m),
};
const FILE_HASH = { 0x02: 20, 0x03: 20, 0x08: 32, 0x67: 32 };

class Reader {
  constructor(bytes) { this.b = bytes; this.i = 0; }
  byte() {
    if (this.i >= this.b.length) throw new Error('OTS proof ends early');
    return this.b[this.i++];
  }
  bytes(n) {
    if (this.i + n > this.b.length) throw new Error('OTS proof ends early');
    const out = this.b.slice(this.i, this.i + n);
    this.i += n;
    return out;
  }
  varuint() {
    let value = 0;
    let shift = 0;
    for (;;) {
      const b = this.byte();
      value += (b & 0x7f) * 2 ** shift;
      if (!(b & 0x80)) return value;
      shift += 7;
      if (shift > 49) throw new Error('OTS varuint too long');
    }
  }
  varbytes(max) {
    const n = this.varuint();
    if (n > max) throw new Error('OTS field too long');
    return this.bytes(n);
  }
}

function readAttestation(r, msg, out) {
  const tag = hex(r.bytes(8));
  const payload = new Reader(r.varbytes(8192));
  if (tag === PENDING) out.push({ kind: 'pending', uri: new TextDecoder().decode(payload.varbytes(1000)), msg: hex(msg) });
  else if (tag === BITCOIN) out.push({ kind: 'bitcoin', height: payload.varuint(), msg: hex(msg) });
  else out.push({ kind: 'unknown', tag, msg: hex(msg) });
}

function readTimestamp(r, msg, depth, out) {
  if (depth > MAX_DEPTH) throw new Error('OTS proof nests too deeply');
  const item = (tag) => {
    if (tag === 0x00) return readAttestation(r, msg, out);
    let next;
    if (UNARY[tag]) next = UNARY[tag](msg);
    else if (BINARY[tag]) next = BINARY[tag](msg, r.varbytes(MAX_MSG));
    else throw new Error(`unknown OTS operation 0x${tag.toString(16)}`);
    if (next.length > MAX_MSG) throw new Error('OTS message too long');
    readTimestamp(r, next, depth + 1, out);
  };
  let tag = r.byte();
  while (tag === 0xff) {
    item(r.byte());
    tag = r.byte();
  }
  item(tag);
}

/**
 * Parses a detached OpenTimestamps proof.
 * @param {Uint8Array} proof
 * @returns {{ digest: string, attestations: Array<{ kind: 'pending', uri: string, msg: string } | { kind: 'bitcoin', height: number, msg: string } | { kind: 'unknown', tag: string, msg: string }> }}
 */
export function parseOts(proof) {
  if (!(proof instanceof Uint8Array)) throw new Error('OTS proof must be bytes');
  if (proof.length > MAX_PROOF) throw new Error('OTS proof too large');
  const r = new Reader(proof);
  const magic = r.bytes(MAGIC.length);
  if (magic.some((x, i) => x !== MAGIC[i])) throw new Error('not an OpenTimestamps proof');
  if (r.varuint() !== 1) throw new Error('unsupported OTS proof version');
  const op = r.byte();
  if (!FILE_HASH[op]) throw new Error('unsupported OTS file hash');
  const digest = r.bytes(FILE_HASH[op]);
  const attestations = [];
  readTimestamp(r, digest, 0, attestations);
  if (r.i !== proof.length) throw new Error('OTS proof has trailing bytes');
  return { digest: hex(digest), attestations };
}

/**
 * State of a proof for `rootHex`, read from the proof: `complete` with the lowest Bitcoin height when it has a Bitcoin
 * attestation, `pending` otherwise. Throws when the proof is for another digest or cannot be parsed.
 * @param {Uint8Array} proof
 * @param {string} rootHex
 */
export function otsProofState(proof, rootHex) {
  const p = parseOts(proof);
  if (p.digest !== rootHex) throw new Error('OTS proof is for another digest');
  const bitcoin = p.attestations.filter((a) => a.kind === 'bitcoin');
  const calendars = p.attestations.filter((a) => a.kind === 'pending').map((a) => a.uri);
  return bitcoin.length
    ? { state: 'complete', bitcoin_height: Math.min(...bitcoin.map((a) => a.height)), calendars, bitcoin }
    : { state: 'pending', calendars, bitcoin: [] };
}
