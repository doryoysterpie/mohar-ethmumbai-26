import { saltedCommitment } from '../shared/commitment.mjs';
import { verifyAck } from './ack.mjs';

export const ENTRY_TYPES = ['consent', 'presentation', 'receipt', 'recheck'];

/**
 * Posts the salted commitment of a record to the log service and checks the log operator's acknowledgement. The record
 * and its salt never leave the caller. Rejects unless the response carries an acknowledgement signed under the
 * published operator key whose fields are those of the returned entry, and the entry is for the commitment and type sent.
 * @param {{ logUrl: string, entryType: string, record: string, salt: string, operator: { id: string },
 *   fetch?: typeof fetch }} p  operator is the published operator document (operator.json)
 * @returns {Promise<{ commitment: string, response: any, ack: string }>}
 */
export async function commitRecord({ logUrl, entryType, record, salt, operator, fetch: f = fetch }) {
  if (!ENTRY_TYPES.includes(entryType)) throw new Error(`unknown entry type ${entryType}`);
  if (!operator) throw new Error('no published log operator key to check the acknowledgement against');
  const commitment = saltedCommitment(record, salt);
  const res = await f(new URL('commit', logUrl.endsWith('/') ? logUrl : `${logUrl}/`), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ entry_type: entryType, commitment }),
    signal: AbortSignal.timeout(10_000),
  });
  if (!res.ok) throw new Error(`log service refused the commitment: HTTP ${res.status}`);
  const response = await res.json();
  if (response?.entry_type !== entryType || response?.commitment !== commitment) {
    throw new Error('log service returned an entry for another commitment');
  }
  if (response.ack === undefined || response.ack === null) throw new Error('log service returned no acknowledgement');
  let a;
  try {
    a = await verifyAck(response.ack, operator);
  } catch (e) {
    throw new Error(`log acknowledgement invalid: ${e.message}`);
  }
  for (const k of ['seq', 'entry_hash', 'entry_type', 'commitment', 'ts']) {
    if (a[k] !== response[k]) throw new Error(`log acknowledgement ${k} is not the returned entry's`);
  }
  return { commitment, response, ack: response.ack };
}
