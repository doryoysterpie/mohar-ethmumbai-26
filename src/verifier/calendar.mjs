/**
 * Term boundaries as MM-DD (UTC, 00:00). Default: 1 October and 1 January.
 * Set MOHAR_TERM_BOUNDARIES=MM-DD,MM-DD,... to change them.
 */
export function termBoundaries(spec = process.env.MOHAR_TERM_BOUNDARIES ?? '10-01,01-01') {
  const list = spec.split(',').map((s) => s.trim()).filter(Boolean).map((s) => {
    const m = /^(\d{2})-(\d{2})$/.exec(s);
    if (!m) throw new Error(`term boundary ${s} is not MM-DD`);
    return [Number(m[1]), Number(m[2])];
  });
  if (list.length === 0) throw new Error('no term boundaries');
  return list;
}

/**
 * First term boundary strictly after `now`.
 * @param {Date} now
 * @param {Array<[number, number]>} [boundaries]
 * @returns {Date}
 */
export function nextTermBoundary(now, boundaries = termBoundaries()) {
  const y = now.getUTCFullYear();
  const candidates = [y, y + 1].flatMap((year) => boundaries.map(([m, d]) => new Date(Date.UTC(year, m - 1, d))));
  return candidates.filter((c) => c > now).sort((a, b) => a - b)[0];
}
