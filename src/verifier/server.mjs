import http from 'node:http';
import { timingSafeEqual } from 'node:crypto';

const MAX_BODY = 64 * 1024;

function send(res, code, body) {
  res.writeHead(code, { 'content-type': 'application/json', 'cache-control': 'no-store' });
  res.end(JSON.stringify(body));
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size <= MAX_BODY) chunks.push(c);
    });
    req.on('end', () => {
      if (size > MAX_BODY) return reject(Object.assign(new Error('body too large'), { code: 413 }));
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch { reject(Object.assign(new Error('body is not JSON'), { code: 400 })); }
    });
    req.on('error', reject);
  });
}

function tokenMatches(given, expected) {
  if (typeof given !== 'string' || !expected) return false;
  const a = Buffer.from(given);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

/**
 * HTTP service for a school:
 *   GET  /nonce                 single-use nonce for a presentation
 *   POST /present               { presentation, consent } -> 200 receipt, or 422 typed refusal
 *   GET  /status/{holder_did}   latest receipt and re-check summary; requires the staff token
 *   POST /recheck               term status check of every active receipt; requires the staff token
 *   GET  /export/{id}           export bundle for a receipt or re-check receipt id (no token; the bundle carries no personal data)
 * The staff token is sent as `authorization: Bearer <adminToken>`; both staff routes are disabled when no token is set.
 * @param {ReturnType<typeof import('./school.mjs').createSchool>} school
 * @param {{ adminToken?: string }} [options]
 */
export function createServer(school, options = {}) {
  /** Sends 403 or 401 and returns false unless the request carries the staff token. */
  const staff = (req, res) => {
    if (!options.adminToken) { send(res, 403, { error: 'staff routes are disabled on this service' }); return false; }
    const auth = req.headers.authorization ?? '';
    if (!tokenMatches(auth.startsWith('Bearer ') ? auth.slice(7) : '', options.adminToken)) { send(res, 401, { error: 'unauthorized' }); return false; }
    return true;
  };
  return http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? '/', 'http://localhost');
      const parts = url.pathname.split('/').filter(Boolean).map(decodeURIComponent);
      if (req.method === 'GET' && url.pathname === '/nonce') return send(res, 200, school.nonce());
      if (req.method === 'POST' && url.pathname === '/present') {
        if (!(req.headers['content-type'] ?? '').startsWith('application/json')) return send(res, 415, { error: 'content-type must be application/json' });
        const body = await readJson(req);
        const out = await school.present({ presentation: body?.presentation, consent: body?.consent });
        return send(res, out.ok ? 200 : 422, out);
      }
      if (req.method === 'GET' && parts[0] === 'status' && parts.length === 2) {
        if (!staff(req, res)) return undefined;
        const s = school.status(parts[1]);
        return s ? send(res, 200, s) : send(res, 404, { error: 'no receipt for this holder' });
      }
      if (req.method === 'POST' && url.pathname === '/recheck') {
        if (!staff(req, res)) return undefined;
        return send(res, 200, { rechecks: await school.recheck() });
      }
      if (req.method === 'GET' && parts[0] === 'export' && parts.length === 2) {
        const out = await school.exportBundle(parts[1]);
        return out.ok ? send(res, 200, out.bundle) : send(res, out.code, { error: out.error });
      }
      return send(res, 404, { error: 'not found' });
    } catch (e) {
      const code = typeof e.code === 'number' ? e.code : 500;
      return send(res, code, { error: code === 500 ? 'internal error' : e.message });
    }
  });
}
