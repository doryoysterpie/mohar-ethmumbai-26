import http from 'node:http';
import { timingSafeEqual } from 'node:crypto';

const MAX_BODY = 4 * 1024;

function send(res, code, body) {
  res.writeHead(code, { 'content-type': 'application/json', 'cache-control': 'no-store' });
  res.end(JSON.stringify(body));
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => { size += c.length; if (size <= MAX_BODY) chunks.push(c); });
    req.on('end', () => {
      if (size > MAX_BODY) return reject(Object.assign(new Error('body too large'), { code: 413 }));
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch { reject(Object.assign(new Error('body is not JSON'), { code: 400 })); }
    });
    req.on('error', reject);
  });
}

function tokenMatches(header, expected) {
  const given = typeof header === 'string' && header.startsWith('Bearer ') ? header.slice(7) : '';
  if (!expected || !given) return false;
  const a = Buffer.from(given);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

/**
 * HTTP service for the log:
 *   POST /commit                { entry_type, commitment } -> 201 new entry, 200 existing entry, 400 anything else
 *   GET  /proof/{commitment}    entry, Merkle path and batch with both anchors; 404 when unknown
 *   GET  /batches/{id}          batch summary
 *   POST /batch                 closes and anchors a batch now; operator token
 *   POST /upgrade               upgrades pending OpenTimestamps proofs; operator token
 * Operator routes take `authorization: Bearer <adminToken>` and are off when no token is set.
 * @param {ReturnType<typeof import('./service.mjs').createLog>} log
 * @param {{ adminToken?: string }} [options]
 */
export function createLogServer(log, options = {}) {
  const operator = (req, res) => {
    if (!options.adminToken) { send(res, 403, { error: 'operator routes are disabled on this service' }); return false; }
    if (!tokenMatches(req.headers.authorization, options.adminToken)) { send(res, 401, { error: 'unauthorized' }); return false; }
    return true;
  };
  return http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? '/', 'http://localhost');
      const parts = url.pathname.split('/').filter(Boolean);
      if (req.method === 'POST' && url.pathname === '/commit') {
        if (!(req.headers['content-type'] ?? '').startsWith('application/json')) return send(res, 415, { error: 'content-type must be application/json' });
        const body = await readJson(req);
        const keys = body && typeof body === 'object' ? Object.keys(body).sort() : [];
        if (keys.join(',') !== 'commitment,entry_type') return send(res, 400, { error: 'body must be exactly { entry_type, commitment }' });
        let out;
        try {
          out = log.commit(body);
        } catch (e) {
          return send(res, 400, { error: e.message });
        }
        return send(res, out.created ? 201 : 200, out.entry);
      }
      if (req.method === 'GET' && parts[0] === 'proof' && parts.length === 2) {
        const p = log.proof(parts[1]);
        return p ? send(res, 200, p) : send(res, 404, { error: 'no entry for this commitment' });
      }
      if (req.method === 'GET' && parts[0] === 'batches' && parts.length === 2) {
        const b = /^\d+$/.test(parts[1]) ? log.batch(Number(parts[1])) : null;
        return b ? send(res, 200, b) : send(res, 404, { error: 'no such batch' });
      }
      if (req.method === 'POST' && url.pathname === '/batch') {
        if (!operator(req, res)) return undefined;
        return send(res, 200, { batch: await log.closeBatch() });
      }
      if (req.method === 'POST' && url.pathname === '/upgrade') {
        if (!operator(req, res)) return undefined;
        return send(res, 200, { batches: await log.upgradePending() });
      }
      return send(res, 404, { error: 'not found' });
    } catch (e) {
      const code = typeof e.code === 'number' ? e.code : 500;
      return send(res, code, { error: code === 500 ? 'internal error' : e.message });
    }
  });
}
