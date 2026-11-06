// Signed commit acknowledgements. The log operator signs one for every accepted commit; the client keeps it.
// Two acknowledgements for the same seq with different entry hashes prove that the operator replaced an entry.
import { signJws, verifyJws, decodeJws } from '../shared/jws.mjs';
import { didKeyFromJwk, jwkFromDidKey, publicOf } from '../shared/keys.mjs';

export const ACK_TYP = 'log-ack+jwt';
const FIELDS = ['seq', 'entry_hash', 'entry_type', 'commitment', 'ts', 'operator_key_id'];

/** did:key of the operator's Ed25519 key; this is the acknowledgement's operator_key_id. */
export const operatorKeyId = (jwk) => didKeyFromJwk(publicOf(jwk));

/** Contents of the published operator.json for an operator key. */
export function operatorDocument(publicJwk) {
  const id = operatorKeyId(publicJwk);
  return { id, type: 'log operator key', publicKeyJwk: publicOf(publicJwk) };
}

/**
 * Signs an acknowledgement for a log entry.
 * @param {{ seq: number, entry_hash: string, entry_type: string, commitment: string, ts: string }} entry
 * @param {import('../shared/keys.mjs').Ed25519Jwk} operatorPrivateJwk
 * @returns {Promise<string>} compact JWS
 */
export function signAck(entry, operatorPrivateJwk) {
  const id = operatorKeyId(operatorPrivateJwk);
  const payload = {
    seq: entry.seq, entry_hash: entry.entry_hash, entry_type: entry.entry_type, commitment: entry.commitment, ts: entry.ts,
    operator_key_id: id,
  };
  return signJws(payload, { typ: ACK_TYP, kid: `${id}#${id.slice('did:key:'.length)}` }, operatorPrivateJwk);
}

/**
 * Verifies an acknowledgement under the published operator key and returns its payload.
 * Throws when the signature, type, key id or shape is wrong.
 * @param {string} ack
 * @param {{ id: string }} operator the published operator document (only its id, a did:key, is used)
 */
export async function verifyAck(ack, operator) {
  if (typeof ack !== 'string') throw new Error('acknowledgement is not a compact JWS');
  if (!operator || typeof operator.id !== 'string' || !operator.id.startsWith('did:key:')) throw new Error('no published operator key');
  const { header, payload } = decodeJws(ack);
  if (payload.operator_key_id !== operator.id) throw new Error('acknowledgement is signed for another operator key');
  if (header.kid !== `${operator.id}#${operator.id.slice('did:key:'.length)}`) throw new Error('acknowledgement key id is not the operator key');
  await verifyJws(ack, jwkFromDidKey(operator.id), ACK_TYP);
  const keys = Object.keys(payload).sort();
  if (keys.join() !== [...FIELDS].sort().join()) throw new Error('acknowledgement fields are not the expected set');
  if (!Number.isInteger(payload.seq) || payload.seq < 0) throw new Error('acknowledgement seq is not a non-negative integer');
  return payload;
}

/**
 * Compares two acknowledgements. Both must verify under the operator key. Returns equivocation when they name the same
 * seq with different entry hashes.
 * @returns {Promise<{ equivocation: boolean, seq: number, a: object, b: object, reason: string }>}
 */
export async function compareAcks(ackA, ackB, operator) {
  const a = await verifyAck(ackA, operator);
  const b = await verifyAck(ackB, operator);
  if (a.seq !== b.seq) return { equivocation: false, seq: a.seq, a, b, reason: `different seq (${a.seq} and ${b.seq})` };
  if (a.entry_hash === b.entry_hash) return { equivocation: false, seq: a.seq, a, b, reason: 'same entry' };
  return { equivocation: true, seq: a.seq, a, b, reason: `the operator signed two different entries at seq ${a.seq}` };
}
