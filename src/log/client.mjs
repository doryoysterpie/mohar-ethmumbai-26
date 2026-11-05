import { saltedCommitment } from '../shared/commitment.mjs';

export const ENTRY_TYPES = ['consent', 'presentation', 'receipt', 'recheck'];

/**
 * Posts the salted commitment of a record to the log service. The record and its salt never leave the caller.
 * @param {{ logUrl: string, entryType: string, record: string, salt: string, fetch?: typeof fetch }} p
 * @returns {Promise<{ commitment: string, response: unknown }>}
 */
export async function commitRecord({ logUrl, entryType, record, salt, fetch: f = fetch }) {
  if (!ENTRY_TYPES.includes(entryType)) throw new Error(`unknown entry type ${entryType}`);
  const commitment = saltedCommitment(record, salt);
  const res = await f(new URL('commit', logUrl.endsWith('/') ? logUrl : `${logUrl}/`), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ entry_type: entryType, commitment }),
    signal: AbortSignal.timeout(10_000),
  });
  if (!res.ok) throw new Error(`log service refused the commitment: HTTP ${res.status}`);
  return { commitment, response: await res.json() };
}
