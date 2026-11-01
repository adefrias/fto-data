'use strict';
// Shared-database API. `query(text, params)` must resolve to an array of row objects.
const COLS = ['users','cands','rides','evals','notifs','audit','templates','rtTpls','evTpls','levels','comps','messages','ceTpls','cevals'];
const IMMUTABLE = new Set(['evals', 'cevals']); // submitted evaluations are never changed or removed
const MAX_DOC = 524288;

function makeHandler(query) {
  let ready = null;
  const init = () => ready || (ready = (async () => {
    await query('CREATE TABLE IF NOT EXISTS docs(c text NOT NULL, id text NOT NULL, j jsonb NOT NULL, PRIMARY KEY(c,id))', []);
    await query('CREATE TABLE IF NOT EXISTS rev(c text PRIMARY KEY, n integer NOT NULL)', []);
    await query('CREATE TABLE IF NOT EXISTS leases(k text PRIMARY KEY, holder text NOT NULL, until_ts bigint NOT NULL)', []);
  })().catch(e => { ready = null; throw e; }));

  const bump = 'INSERT INTO rev(c,n) SELECT $1,1 FROM w ON CONFLICT (c) DO UPDATE SET n = rev.n + 1';

  return async function handler(req, res) {
    const send = (code, obj) => { res.statusCode = code; res.setHeader('Content-Type', 'application/json; charset=utf-8'); res.setHeader('Cache-Control', 'no-store'); res.setHeader('X-Content-Type-Options', 'nosniff'); res.end(JSON.stringify(obj)); };
    try {
      const origin = req.headers.origin;
      if (origin) { let oh = ''; try { oh = new URL(origin).host; } catch (e) {} if (oh !== req.headers.host) return send(403, { error: 'Forbidden' }); }
      await init();

      if (req.method === 'GET') {
        const want = {};
        String((req.query && req.query.v) || '').split(',').forEach(p => { const kv = p.split(':'); if (kv.length === 2 && COLS.includes(kv[0]) && /^-?\d+$/.test(kv[1])) want[kv[0]] = Number(kv[1]); });
        const names = Object.keys(want), cols = {};
        if (names.length) {
          const cur = {}; (await query('SELECT c, n FROM rev', [])).forEach(r => { cur[r.c] = Number(r.n); });
          for (const c of names) {
            const n = cur[c] || 0; if (n === want[c]) continue;
            const rows = await query('SELECT id, j FROM docs WHERE c = $1 ORDER BY id', [c]);
            cols[c] = { v: n, docs: rows.map(r => ({ id: r.id, data: typeof r.j === 'string' ? JSON.parse(r.j) : r.j })) };
          }
        }
        return send(200, { cols });
      }

      if (req.method !== 'POST') return send(405, { error: 'Method not allowed' });
      if (!/^application\/json/i.test(req.headers['content-type'] || '') || req.headers['x-requested-with'] !== 'onboard') return send(400, { error: 'Bad request' });
      let b = req.body; if (typeof b === 'string') { try { b = JSON.parse(b); } catch (e) { b = null; } }
      if (!b || typeof b !== 'object' || Array.isArray(b)) return send(400, { error: 'Bad request' });

      if (b.op === 'acquire') {
        const k = String(b.k || ''), holder = String(b.holder || ''), ttl = Math.max(1000, Math.min(120000, Number(b.ttlMs) || 30000)), now = Date.now();
        if (!/^[A-Za-z0-9_\/.-]{1,64}$/.test(k) || !holder || holder.length > 64) return send(400, { error: 'Bad request' });
        const rows = await query('INSERT INTO leases(k,holder,until_ts) VALUES($1,$2,$3) ON CONFLICT (k) DO UPDATE SET holder = EXCLUDED.holder, until_ts = EXCLUDED.until_ts WHERE leases.until_ts < $4 OR leases.holder = EXCLUDED.holder RETURNING 1 AS ok', [k, holder, now + ttl, now]);
        return send(200, { acquired: rows.length > 0 });
      }

      const c = String(b.c || ''), id = String(b.id || '');
      if (!COLS.includes(c) || !/^[A-Za-z0-9_.-]{1,64}$/.test(id)) return send(400, { error: 'Bad request' });
      if (b.op === 'set') {
        if (!b.data || typeof b.data !== 'object' || Array.isArray(b.data)) return send(400, { error: 'Bad request' });
        const j = JSON.stringify(b.data); if (j.length > MAX_DOC) return send(413, { error: 'Document too large' });
        if (IMMUTABLE.has(c)) await query('WITH w AS (INSERT INTO docs(c,id,j) VALUES($1,$2,$3::jsonb) ON CONFLICT (c,id) DO NOTHING RETURNING 1) ' + bump, [c, id, j]);
        else await query('WITH w AS (INSERT INTO docs(c,id,j) VALUES($1,$2,$3::jsonb) ON CONFLICT (c,id) DO UPDATE SET j = EXCLUDED.j WHERE docs.j IS DISTINCT FROM EXCLUDED.j RETURNING 1) ' + bump, [c, id, j]);
        return send(200, { ok: true });
      }
      if (b.op === 'delete') {
        if (!IMMUTABLE.has(c)) await query('WITH w AS (DELETE FROM docs WHERE c = $1 AND id = $2 RETURNING 1) ' + bump, [c, id]);
        return send(200, { ok: true });
      }
      return send(400, { error: 'Bad request' });
    } catch (e) {
      console.error(e);
      return send(500, { error: 'Database error. Check the DATABASE_URL setting.' });
    }
  };
}
module.exports = { makeHandler, COLS };
