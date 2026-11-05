import { sha256Hex } from '../shared/encoding.mjs';

export const ENTRY_TYPES = ['consent', 'presentation', 'receipt', 'recheck'];

/**
 * Posts the SHA-256 commitment of a record to the log service. The record itself never leaves the caller.
 * @param {{ logUrl: string, entryType: string, record: string, fetch?: typeof fetch }} p
 * @returns {Promise<{ commitment: string, response: unknown }>}
 */
export async function commitRecord({ logUrl, entryType, record, fetch: f = fetch }) {
  if (!ENTRY_TYPES.includes(entryType)) throw new Error(`unknown entry type ${entryType}`);
  if (typeof record !== 'string' || record.length === 0) throw new Error('record must be a non-empty string');
  const commitment = sha256Hex(record);
  const res = await f(new URL('commit', logUrl.endsWith('/') ? logUrl : `${logUrl}/`), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ entry_type: entryType, commitment }),
    signal: AbortSignal.timeout(10_000),
  });
  if (!res.ok) throw new Error(`log service refused the commitment: HTTP ${res.status}`);
  return { commitment, response: await res.json() };
}
