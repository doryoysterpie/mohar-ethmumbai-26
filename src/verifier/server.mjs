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
 *   GET  /status/{holder_did}   latest receipt and re-check summary
 *   POST /recheck               term status check of every active receipt; requires `authorization: Bearer <adminToken>`
 *   GET  /export/{receipt_id}   not in this version (501)
 * @param {ReturnType<typeof import('./school.mjs').createSchool>} school
 * @param {{ adminToken?: string }} [options] /recheck is disabled when no admin token is set
 */
export function createServer(school, options = {}) {
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
        const s = school.status(parts[1]);
        return s ? send(res, 200, s) : send(res, 404, { error: 'no receipt for this holder' });
      }
      if (req.method === 'POST' && url.pathname === '/recheck') {
        if (!options.adminToken) return send(res, 403, { error: 'term check is disabled on this service' });
        const auth = req.headers.authorization ?? '';
        if (!tokenMatches(auth.startsWith('Bearer ') ? auth.slice(7) : '', options.adminToken)) return send(res, 401, { error: 'unauthorized' });
        return send(res, 200, { rechecks: await school.recheck() });
      }
      if (req.method === 'GET' && parts[0] === 'export' && parts.length === 2) return send(res, 501, { error: 'export is not in this version' });
      return send(res, 404, { error: 'not found' });
    } catch (e) {
      const code = typeof e.code === 'number' ? e.code : 500;
      return send(res, code, { error: code === 500 ? 'internal error' : e.message });
    }
  });
}
