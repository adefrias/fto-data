'use strict';
// Shared-database API with server-side sign-in, sessions and role-based permissions.
// `query(text, params)` must resolve to an array of row objects (Postgres syntax).
const crypto = require('crypto');
const COLS = ['users','cands','rides','evals','notifs','audit','templates','rtTpls','evTpls','levels','comps','messages','ceTpls','cevals','assigns','reqTpls','settings'];
const IMMUTABLE = new Set(['evals', 'cevals']);
const ROLES = ['admin', 'instructor', 'fto', 'candidate'];
const MAX_DOC = 524288, IDLE = 30 * 60, COOKIE = 'cmts_s';
const PW_RE = /^[0-9a-f]{32}:[0-9a-f]{64}$/;

const pbkdf2 = (pw, salt) => new Promise((res, rej) => crypto.pbkdf2(pw, salt, 150000, 32, 'sha256', (e, k) => e ? rej(e) : res(k.toString('hex'))));
const hashPw = async pw => { const salt = crypto.randomBytes(16).toString('hex'); return salt + ':' + await pbkdf2(pw, salt); };
const checkPw = async (pw, stored) => {
  if (typeof stored !== 'string' || stored.indexOf(':') < 0) { await pbkdf2(pw, 'x'.repeat(32)); return false; }
  const [salt, h] = stored.split(':'); const c = await pbkdf2(pw, salt);
  return h.length === c.length && crypto.timingSafeEqual(Buffer.from(h), Buffer.from(c));
};
const keysChanged = (o, n) => { const k = new Set([...Object.keys(o || {}), ...Object.keys(n || {})]); return [...k].filter(x => JSON.stringify((o || {})[x]) !== JSON.stringify((n || {})[x])); };
const within = (o, n, allowed) => keysChanged(o, n).every(k => allowed.includes(k));

// 'ok' | 'ignore' | 'deny'
function authorize(user, ownCid, c, op, old, nu) {
  const role = user.role, me = user.id, isNew = !old;
  if (IMMUTABLE.has(c)) {
    if (op === 'delete') return 'ignore';
    if (old) return 'ignore';
    if (role === 'admin' && c === 'evals') return 'deny';
    if (c === 'evals') return role === 'fto' && nu.fto === me ? 'ok' : 'deny';
    return role === 'candidate' && ownCid && nu.cid === ownCid && nu.by === me ? 'ok' : 'deny';
  }
  if (c === 'audit') return op === 'delete' ? 'ignore' : old ? 'ignore' : (nu.u === me || nu.u === 'system') ? 'ok' : 'deny';
  if (c === 'notifs') { if (!old) return op === 'set' ? 'ok' : 'deny'; return old.u === me || role === 'admin' ? 'ok' : 'deny'; }
  if (role === 'admin') return 'ok';
  switch (c) {
    case 'cands': if (op === 'delete') return 'deny'; if (isNew) return role === 'instructor' ? 'ok' : 'deny'; return role === 'instructor' ? 'ok' : role === 'fto' && within(old, nu, ['remed']) ? 'ok' : 'deny';
    case 'comps': return op === 'set' && (role === 'instructor' || role === 'fto') ? 'ok' : 'deny';
    case 'assigns': if (op === 'delete') return 'deny'; if (role === 'instructor') return 'ok';
      return role === 'fto' && old && old.fto === me && within(old, nu, ['status', 'rid', 'done']) ? 'ok' : 'deny';
    case 'rides': if (op === 'delete') return 'deny';
      if (role === 'fto') return isNew && nu.fto === me ? 'ok' : 'deny';
      return role === 'candidate' && old && ownCid && old.cid === ownCid && within(old, nu, ['ack', 'ackt']) ? 'ok' : 'deny';
    case 'messages': if (role !== 'candidate' || op === 'delete') return 'deny';
      return isNew ? (nu.from === me ? 'ok' : 'deny') : (old.from === me && within(old, nu, ['rseen']) ? 'ok' : 'deny');
    case 'templates': case 'rtTpls': case 'evTpls': case 'levels': return role === 'instructor' ? 'ok' : 'deny';
    case 'users': // instructors may create new candidate-level accounts (never edit or delete existing users)
      return role === 'instructor' && isNew && op === 'set' && nu.role === 'candidate' && nu.active === true && PW_RE.test(String(nu.pw || '')) ? 'ok' : 'deny';
    default: return 'deny'; // users, ceTpls, reqTpls, settings: admin only
  }
}

function makeHandler(query, opts = {}) {
  const env = opts.env || process.env;
  const sendMail = opts.sendMail !== undefined ? opts.sendMail : defaultMail(env);
  let ready = null;
  const init = () => ready || (ready = (async () => {
    await query('CREATE TABLE IF NOT EXISTS docs(c text NOT NULL, id text NOT NULL, j jsonb NOT NULL, PRIMARY KEY(c,id))', []);
    await query('CREATE TABLE IF NOT EXISTS rev(c text PRIMARY KEY, n integer NOT NULL)', []);
    await query('CREATE TABLE IF NOT EXISTS sessions(h text PRIMARY KEY, uid text NOT NULL, last bigint NOT NULL)', []);
    await query('CREATE TABLE IF NOT EXISTS attempts(k text PRIMARY KEY, n integer NOT NULL, until_ts bigint NOT NULL, first_ts bigint NOT NULL)', []);
    await query('CREATE TABLE IF NOT EXISTS sent(k text PRIMARY KEY, ts bigint NOT NULL)', []);
  })().catch(e => { ready = null; throw e; }));
  const bumpSql = 'INSERT INTO rev(c,n) SELECT $1,1 FROM w ON CONFLICT (c) DO UPDATE SET n = rev.n + 1';
  const now = () => Math.floor(Date.now() / 1000);
  const parse = j => typeof j === 'string' ? JSON.parse(j) : j;
  const getDoc = async (c, id) => { const r = await query('SELECT j FROM docs WHERE c=$1 AND id=$2', [c, id]); return r.length ? parse(r[0].j) : null; };
  const putDoc = async (c, id, o, replaceOnly) => query('WITH w AS (INSERT INTO docs(c,id,j) VALUES($1,$2,$3::jsonb) ON CONFLICT (c,id) DO UPDATE SET j = EXCLUDED.j WHERE docs.j IS DISTINCT FROM EXCLUDED.j RETURNING 1) ' + bumpSql, [c, id, JSON.stringify(o)]);
  const delDoc = async (c, id) => query('WITH w AS (DELETE FROM docs WHERE c=$1 AND id=$2 RETURNING 1) ' + bumpSql, [c, id]);
  const cookieOf = req => { const m = String(req.headers.cookie || '').split(/;\s*/).find(x => x.startsWith(COOKIE + '=')); return m ? m.slice(COOKIE.length + 1) : ''; };
  const sha = s => crypto.createHash('sha256').update(s).digest('hex');
  const ipOf = req => String(req.headers['x-forwarded-for'] || (req.socket && req.socket.remoteAddress) || '').split(',')[0].trim();
  const secure = req => !/^(localhost|127\.|\[::1\])/.test(String(req.headers.host || ''));

  async function session(req) {
    const tok = cookieOf(req); if (!/^[0-9a-f]{64}$/.test(tok)) return null;
    const h = sha(tok), r = await query('SELECT uid, last FROM sessions WHERE h=$1', [h]); if (!r.length) return null;
    const t = now();
    if (Number(r[0].last) < t - IDLE) { await query('DELETE FROM sessions WHERE h=$1', [h]); return null; }
    const u = await getDoc('users', r[0].uid); if (!u || !u.active || !ROLES.includes(u.role)) return null;
    if (Number(r[0].last) < t - 60) await query('UPDATE sessions SET last=$2 WHERE h=$1', [h, t]);
    return { user: { ...u, id: r[0].uid }, h };
  }
  async function newSession(req, res, uid) {
    const tok = crypto.randomBytes(32).toString('hex'), t = now();
    await query('INSERT INTO sessions(h,uid,last) VALUES($1,$2,$3)', [sha(tok), uid, t]);
    await query('DELETE FROM sessions WHERE last < $1', [t - 86400]);
    res.setHeader('Set-Cookie', `${COOKIE}=${tok}; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400${secure(req) ? '; Secure' : ''}`);
  }
  const clearCookie = (req, res) => res.setHeader('Set-Cookie', `${COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${secure(req) ? '; Secure' : ''}`);
  async function locked(keys) {
    const t = now();
    for (const [k] of keys) { const r = await query('SELECT n, until_ts, first_ts FROM attempts WHERE k=$1', [k]); if (r.length && Number(r[0].until_ts) > t) return Number(r[0].until_ts) - t; }
    return 0;
  }
  async function fail(keys) {
    const t = now();
    for (const [k, max] of keys) {
      const r = await query('SELECT n, until_ts, first_ts FROM attempts WHERE k=$1', [k]);
      let n = 1, first = t; if (r.length && t - Number(r[0].first_ts) < 900) { n = Number(r[0].n) + 1; first = Number(r[0].first_ts); }
      await query('INSERT INTO attempts(k,n,until_ts,first_ts) VALUES($1,$2,$3,$4) ON CONFLICT (k) DO UPDATE SET n=EXCLUDED.n, until_ts=EXCLUDED.until_ts, first_ts=EXCLUDED.first_ts', [k, n, n >= max ? t + 300 : 0, first]);
    }
  }
  async function ownCandId(uid) { const r = await query("SELECT id FROM docs WHERE c='cands' AND j->>'uid'=$1", [uid]); return r.length ? r[0].id : null; }

  async function readCol(c, user, own) {
    const role = user.role, me = user.id; let rows;
    const all = () => query('SELECT id, j FROM docs WHERE c=$1 ORDER BY id', [c]);
    const where = (cond, p) => query('SELECT id, j FROM docs WHERE c=$1 AND ' + cond + ' ORDER BY id', [c, p]);
    if (c === 'notifs') rows = await where("j->>'u'=$2", me);
    else if (c === 'audit') rows = role === 'admin' ? await all() : [];
    else if (c === 'messages') rows = role === 'admin' ? await all() : role === 'candidate' ? await where("j->>'from'=$2", me) : [];
    else if (c === 'cevals') rows = role === 'admin' ? await all() : role === 'candidate' && own ? await where("j->>'cid'=$2", own) : [];
    else if (role === 'candidate' && ['cands'].includes(c)) rows = await where("j->>'uid'=$2", me);
    else if (role === 'candidate' && ['rides', 'evals', 'assigns'].includes(c)) rows = own ? await where("j->>'cid'=$2", own) : [];
    else if (role === 'candidate' && c === 'comps') rows = own ? await where('id=$2', own) : [];
    else if (role === 'candidate' && c === 'users') rows = await where("(j->>'role')<>'candidate' OR id=$2", me);
    else rows = await all();
    return rows.map(r => {
      const o = { ...parse(r.j) };
      if (c === 'users') delete o.pw;
      if (c === 'cevals' && role === 'candidate') return { id: r.id, data: { id: o.id, cid: o.cid, rid: o.rid, date: o.date, unit: o.unit, sub: o.sub, by: o.by, _t: o._t } };
      return { id: r.id, data: o };
    });
  }

  async function mailTo(uid, subject, text) {
    if (!sendMail) return false;
    try { const u = await getDoc('users', uid); if (!u || !u.active || !u.email) return false; await sendMail({ to: u.email, subject, text: text + '\n\n' + (env.SITE_URL || '') }); return true; } catch (e) { console.error('mail failed', e && e.message); return false; }
  }
  const tzDate = (off) => { const d = new Date(Date.now() + off * 86400000); return d.toLocaleDateString('en-CA', { timeZone: env.APP_TZ || 'America/New_York' }); };
  async function remind() {
    const load = async c => (await query('SELECT id, j FROM docs WHERE c=$1', [c])).map(r => ({ ...parse(r.j), id: r.id }));
    const [assigns, rides, evals, cevals, users, cands, sett] = await Promise.all(['assigns', 'rides', 'evals', 'cevals', 'users', 'cands', 'settings'].map(load));
    const today = tzDate(0), tomorrow = tzDate(1), days = Math.max(1, Number((sett.find(s => s.id === 'main') || {}).reviewDays) || 3);
    const once = async k => { const r = await query('INSERT INTO sent(k,ts) VALUES($1,$2) ON CONFLICT (k) DO NOTHING RETURNING 1 AS ok', [k, now()]); return r.length > 0; };
    const uname = id => (users.find(u => u.id === id) || {}).name || '';
    let n = 0;
    for (const a of assigns.filter(a => a.status === 'Scheduled' && a.date === tomorrow)) {
      const c = cands.find(x => x.id === a.cid), when = `${a.date} ${a.start}-${a.end}`;
      for (const [uid, who] of [[a.fto, 'with ' + uname(c && c.uid)], [c && c.uid, 'with FTO ' + uname(a.fto)]]) if (uid && await once(`a:${a.id}:${a.date}:${uid}`) && await mailTo(uid, 'Ride time tomorrow', `Reminder: ride time tomorrow, ${when} ${who}${a.unit ? ' (' + a.unit + ')' : ''}.`)) n++;
    }
    const pendEv = {}; rides.filter(r => r.evreq && !r.void && r.date < today && !evals.some(e => e.rid === r.id)).forEach(r => { pendEv[r.fto] = (pendEv[r.fto] || 0) + 1; });
    for (const [uid, k] of Object.entries(pendEv)) if (await once(`e:${uid}:${today}`) && await mailTo(uid, 'Evaluations waiting', `You have ${k} ride-time shift${k > 1 ? 's' : ''} waiting for your FTO evaluation.`)) n++;
    const cutoff = new Date(Date.parse(today) - days * 86400000).toISOString().slice(0, 10), pendRv = {};
    rides.filter(r => !r.void && r.date < cutoff && !cevals.some(e => e.rid === r.id)).forEach(r => { const c = cands.find(x => x.id === r.cid); if (c) pendRv[c.uid] = (pendRv[c.uid] || 0) + 1; });
    for (const [uid, k] of Object.entries(pendRv)) if (await once(`r:${uid}:${today}`) && await mailTo(uid, 'FTO review waiting', `You have ${k} ride-time shift${k > 1 ? 's' : ''} waiting for your FTO review.`)) n++;
    return n;
  }

  return async function handler(req, res) {
    const send = (code, obj) => { res.statusCode = code; res.setHeader('Content-Type', 'application/json; charset=utf-8'); res.setHeader('Cache-Control', 'no-store'); res.setHeader('X-Content-Type-Options', 'nosniff'); res.end(JSON.stringify(obj)); };
    try {
      const origin = req.headers.origin;
      if (origin) { let oh = ''; try { oh = new URL(origin).host; } catch (e) {} if (oh !== req.headers.host) return send(403, { error: 'Forbidden' }); }
      await init();
      const q = req.query || {};

      if (req.method === 'GET' && q.a === 'remind') {
        const key = q.key || String(req.headers.authorization || '').replace(/^Bearer /, '');
        if (!env.CRON_SECRET || key !== env.CRON_SECRET) return send(403, { error: 'Forbidden' });
        return send(200, { sent: await remind() });
      }
      const sess = await session(req);
      if (req.method === 'GET' && q.a === 'me') {
        if (sess) return send(200, { user: { id: sess.user.id, name: sess.user.name, role: sess.user.role }, setup: false });
        const c = await query("SELECT 1 AS x FROM docs WHERE c='users' LIMIT 1", []);
        return send(200, { user: null, setup: c.length === 0 });
      }
      if (req.method === 'GET') {
        if (!sess) return send(401, { error: 'auth' });
        const want = {}; String(q.v || '').split(',').forEach(p => { const kv = p.split(':'); if (kv.length === 2 && COLS.includes(kv[0]) && /^-?\d+$/.test(kv[1])) want[kv[0]] = Number(kv[1]); });
        const cur = {}; (await query('SELECT c, n FROM rev', [])).forEach(r => { cur[r.c] = Number(r.n); });
        const own = sess.user.role === 'candidate' ? await ownCandId(sess.user.id) : null, cols = {};
        for (const c of Object.keys(want)) { const n = cur[c] || 0; if (n === want[c]) continue; cols[c] = { v: n, docs: await readCol(c, sess.user, own) }; }
        return send(200, { cols });
      }
      if (req.method !== 'POST') return send(405, { error: 'Method not allowed' });
      if (!/^application\/json/i.test(req.headers['content-type'] || '') || req.headers['x-requested-with'] !== 'onboard') return send(400, { error: 'Bad request' });
      let b = req.body; if (typeof b === 'string') { try { b = JSON.parse(b); } catch (e) { b = null; } }
      if (!b || typeof b !== 'object' || Array.isArray(b)) return send(400, { error: 'Bad request' });

      if (b.op === 'login') {
        const email = String(b.email || '').trim().toLowerCase().slice(0, 200), pw = String(b.pw || '').slice(0, 200);
        const keys = [['e:' + email, 5], ['i:' + ipOf(req), 30]], wait = await locked(keys);
        if (wait) return send(429, { error: `Too many attempts. Try again in ${Math.ceil(wait / 60)} minute(s).` });
        const r = await query("SELECT id, j FROM docs WHERE c='users' AND lower(j->>'email')=$1", [email]);
        const u = r.length ? parse(r[0].j) : null;
        const good = await checkPw(pw, u && u.pw);
        if (!u || !good) { await fail(keys); return send(401, { error: 'Email or password is incorrect.' }); }
        if (!u.active) return send(403, { error: 'This account is deactivated. Contact an administrator.' });
        await query('DELETE FROM attempts WHERE k=$1', ['e:' + email]);
        await newSession(req, res, r[0].id);
        return send(200, { user: { id: r[0].id, mustChange: !!u.mustChange } });
      }
      if (b.op === 'setup') {
        const name = String(b.name || '').trim().slice(0, 120), email = String(b.email || '').trim().toLowerCase().slice(0, 200), pw = String(b.pw || '');
        if (!name || !/^[^@\s]+@[^@\s]+$/.test(email) || pw.length < 8) return send(400, { error: 'Enter a name, a valid email and a password of 8+ characters.' });
        const id = 'u' + crypto.randomBytes(5).toString('hex'), doc = { id, name, email, role: 'admin', active: true, pw: await hashPw(pw), created: new Date().toISOString().slice(0, 10), _t: Date.now() * 1000 };
        const ins = await query("WITH w AS (INSERT INTO docs(c,id,j) SELECT 'users',$1,$2::jsonb WHERE NOT EXISTS (SELECT 1 FROM docs WHERE c='users') RETURNING 1) INSERT INTO rev(c,n) SELECT 'users',1 FROM w ON CONFLICT (c) DO UPDATE SET n = rev.n + 1 RETURNING 1 AS ok", [id, JSON.stringify(doc)]);
        if (!ins.length) return send(409, { error: 'An administrator already exists. Reload and sign in.' });
        const st = b.starter && typeof b.starter === 'object' ? b.starter : {};
        for (const c of Object.keys(st)) { if (!COLS.includes(c) || c === 'users' || !Array.isArray(st[c])) continue; let t = Date.now() * 1000; for (const o of st[c]) { if (o && typeof o === 'object' && /^[A-Za-z0-9_.-]{1,64}$/.test(o.id || '') && JSON.stringify(o).length < MAX_DOC) await putDoc(c, o.id, { ...o, _t: o._t == null ? t++ : o._t }); } }
        await newSession(req, res, id);
        return send(200, { user: { id } });
      }
      if (!sess) return send(401, { error: 'auth' });
      const me = sess.user;
      if (b.op === 'logout') { await query('DELETE FROM sessions WHERE h=$1', [sess.h]); clearCookie(req, res); return send(200, { ok: true }); }
      if (b.op === 'password') {
        const oldPw = String(b.old || ''), nw = String(b.new || '');
        if (nw.length < 8 || nw.length > 200) return send(400, { error: 'Use at least 8 characters.' });
        if (!(await checkPw(oldPw, me.pw))) return send(403, { error: 'Your current password is incorrect.' });
        const u = { ...me }; delete u.id; u.id = me.id; u.pw = await hashPw(nw); delete u.mustChange;
        await putDoc('users', me.id, u); await query('DELETE FROM sessions WHERE uid=$1 AND h<>$2', [me.id, sess.h]);
        return send(200, { ok: true });
      }

      const c = String(b.c || ''), id = String(b.id || '');
      if (!COLS.includes(c) || !/^[A-Za-z0-9_.-]{1,64}$/.test(id) || (b.op !== 'set' && b.op !== 'delete')) return send(400, { error: 'Bad request' });
      let nu = null;
      if (b.op === 'set') {
        if (!b.data || typeof b.data !== 'object' || Array.isArray(b.data)) return send(400, { error: 'Bad request' });
        nu = { ...b.data, id }; if (JSON.stringify(nu).length > MAX_DOC) return send(413, { error: 'Document too large' });
      }
      const old = await getDoc(c, id), own = me.role === 'candidate' ? await ownCandId(me.id) : null;
      if (b.op === 'set' && old && keysChanged(old, nu).length === 0) return send(200, { ok: true, ignored: true }); // identical re-send (e.g. after a sync race)
      const d = authorize(me, own, c, b.op, old, nu);
      if (d === 'deny') return send(403, { error: 'You do not have permission to make that change.' });
      if (d === 'ignore') return send(200, { ok: true, ignored: true });
      if (b.op === 'delete') { if (c === 'users' && id === me.id) return send(403, { error: 'You cannot delete your own account.' }); await delDoc(c, id); return send(200, { ok: true }); }
      if (c === 'users') {
        if (nu.pw !== undefined && !(typeof nu.pw === 'string' && PW_RE.test(nu.pw))) return send(400, { error: 'Bad request' });
        if (!ROLES.includes(nu.role)) return send(400, { error: 'Bad request' });
        if (nu.pw === undefined && old && old.pw) nu.pw = old.pw;
        if (id === me.id && (nu.role !== me.role || nu.active === false)) return send(403, { error: 'You cannot change your own role or deactivate yourself.' });
      }
      await putDoc(c, id, nu);
      if (c === 'notifs' && !old && nu.u && nu.m) mailTo(nu.u, 'Coastal Onboard Tracking', String(nu.m).slice(0, 500));
      return send(200, { ok: true });
    } catch (e) {
      console.error(e);
      return send(500, { error: 'Server error. Check the database settings.' });
    }
  };
}

function defaultMail(env) {
  if (env.MAIL_DRY_RUN) return async m => { console.log('MAIL', JSON.stringify(m)); };
  if (!env.RESEND_API_KEY || !env.MAIL_FROM) return null;
  return async m => {
    const r = await fetch('https://api.resend.com/emails', { method: 'POST', headers: { Authorization: 'Bearer ' + env.RESEND_API_KEY, 'Content-Type': 'application/json' }, body: JSON.stringify({ from: env.MAIL_FROM, to: [m.to], subject: m.subject, text: m.text }) });
    if (!r.ok) throw new Error('Resend ' + r.status);
  };
}
module.exports = { makeHandler, COLS, authorize };
