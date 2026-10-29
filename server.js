// Supernova server. Hosts the page AND the AI so Supernova works on any device, outside Claude.
// Zero dependencies, Node 18+.   Run:  node server.js     then open http://localhost:8787
//
// Environment variables (set these on your host, never inside the page):
//   ANTHROPIC_API_KEY  required for chat   (console.anthropic.com)
//   SECRET             long random text that signs login tokens
//   ADMIN_PASSWORD     optional: your own admin password (a default one is built in as a hash)
//   MODEL / MODEL_FAST / MODEL_DEEP   models for Medium / Instant / High effort
//   PAY_URL            your payment link (Stripe / Razorpay / PayPal) shown on the Upgrade screen
//   PRICE_TEXT         text shown on the Upgrade screen, e.g. "Rs 299 / month"
//   RESEND_API_KEY     optional, emails feedback to FEEDBACK_TO (default devaniviaan@gmail.com)
//   LIMIT_FREE (50) LIMIT_PRO (500) LIMIT_GUEST (20) WINDOW_HOURS (5)
//   ALLOWED_ORIGIN     only needed if the page is hosted somewhere else (e.g. GitHub Pages)
//   DATA_FILE          where accounts are stored. Use a persistent disk/volume on your host!
//   PORT               default 8787
const http = require('node:http');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const E = process.env;
const PORT = +E.PORT || 8787;
const KEY = E.ANTHROPIC_API_KEY || '';
const SECRET = E.SECRET || crypto.randomBytes(32).toString('hex');
const MODEL = E.MODEL || 'claude-sonnet-5-5';
const MODEL_FAST = E.MODEL_FAST || 'claude-haiku-5-5';
const MODEL_DEEP = E.MODEL_DEEP || MODEL;
const ORIGIN = E.ALLOWED_ORIGIN || '*';
const TO = E.FEEDBACK_TO || 'devaniviaan@gmail.com';
const FROM = E.FEEDBACK_FROM || 'Supernova <onboarding@resend.dev>';
const LIMITS = { free: +E.LIMIT_FREE || 50, pro: +E.LIMIT_PRO || 500, guest: +E.LIMIT_GUEST || 20 };
const WINDOW = (+E.WINDOW_HOURS || 5) * 36e5;
const FILE = E.DATA_FILE || path.join(__dirname, 'supernova-data.json');
const UPSTREAM = E.ANTHROPIC_BASE || 'https://api.anthropic.com';

let db = { users: {}, usage: {}, feedback: [] };
try { db = Object.assign(db, JSON.parse(fs.readFileSync(FILE, 'utf8'))); } catch (e) {}
let dirty = false;
const flush = () => { if (!dirty) return; dirty = false; try { fs.writeFileSync(FILE + '.tmp', JSON.stringify(db)); fs.renameSync(FILE + '.tmp', FILE); } catch (e) { console.error('save failed', e.message); } };
setInterval(flush, 3000).unref();
for (const s of ['SIGINT', 'SIGTERM']) process.on(s, () => { flush(); process.exit(0); });

const b64 = (s) => Buffer.from(s).toString('base64url');
const hmac = (s) => crypto.createHmac('sha256', SECRET).update(s).digest('base64url');
const sign = (p) => { const body = b64(JSON.stringify(p)); return body + '.' + hmac(body); };
function verify(tok) {
  try {
    const [body, sig] = tok.split('.'); const good = hmac(body);
    if (sig.length !== good.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(good))) return null;
    const p = JSON.parse(Buffer.from(body, 'base64url').toString()); return p.exp > Date.now() ? p : null;
  } catch (e) { return null; }
}
const hashPw = (pw, salt) => crypto.scryptSync(pw, salt, 64).toString('hex');
const sha = (s) => crypto.createHash('sha256').update(String(s)).digest();
const attempts = new Map();
function throttled(k) { const now = Date.now(), a = (attempts.get(k) || []).filter((t) => now - t < 9e5); a.push(now); attempts.set(k, a); return a.length > 12; }
const dur = (ms) => { const m = Math.ceil(ms / 6e4); return m >= 60 ? `${Math.floor(m / 60)}h ${m % 60}m` : `${m}m`; };

// After the last chat is used, the account locks for WINDOW (5h) and then resets to zero.
function quota(key, max, consume) {
  const now = Date.now(); let u = db.usage[key];
  if (!u || (u.lock && now >= u.lock) || (!u.lock && now - u.start >= WINDOW)) u = db.usage[key] = { start: now, count: 0, lock: 0 };
  const ok = !u.lock && u.count < max;
  if (ok && consume) { u.count++; if (u.count >= max) u.lock = now + WINDOW; dirty = true; }
  return { ok, used: u.count, max, reset: u.lock || u.start + WINDOW };
}
const cors = () => ({ 'Access-Control-Allow-Origin': ORIGIN, 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Access-Control-Allow-Methods': 'GET, POST, PUT, OPTIONS' });
const send = (res, code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json', ...cors() }); res.end(JSON.stringify(obj)); };
function readBody(req, max = 3e6) {
  return new Promise((ok, no) => { let n = 0; const parts = [];
    req.on('data', (c) => { n += c.length; if (n > max) { no(new Error('Request too large')); req.destroy(); } else parts.push(c); });
    req.on('end', () => { try { ok(JSON.parse(Buffer.concat(parts).toString() || '{}')); } catch (e) { no(new Error('Bad JSON')); } });
    req.on('error', no); });
}
function who(req) {
  const t = (req.headers.authorization || '').replace(/^Bearer /, ''); const p = t && verify(t);
  if (!p) return null; if (p.admin) return { admin: true };
  return db.users[p.name] ? { name: p.name, plan: db.users[p.name].plan || 'free' } : null;
}
const cleanName = (n) => String(n || '').trim().toLowerCase().replace(/[^a-z0-9_.-]/g, '').slice(0, 30);

async function recordFeedback(subject, data) {
  db.feedback.push({ t: Date.now(), subject, data }); db.feedback = db.feedback.slice(-300); dirty = true;
  const text = JSON.stringify(data, null, 2).slice(0, 20000);
  if (!E.RESEND_API_KEY) { console.log('[feedback]', subject); return 'saved'; }
  const r = await fetch('https://api.resend.com/emails', { method: 'POST', headers: { Authorization: 'Bearer ' + E.RESEND_API_KEY, 'Content-Type': 'application/json' }, body: JSON.stringify({ from: FROM, to: [TO], subject, text }) });
  if (!r.ok) throw new Error('email failed ' + r.status); return 'emailed';
}
// Default admin password check uses a salted scrypt hash (no plain text in this file).
// Set ADMIN_PASSWORD on your host to use a different password.
const ADMIN_DEFAULT = { salt: '87f0393119090dbf70b67f9362cb5ff2', hash: '3facabdfd7f8ce292e5c8e0869a32e50955b8d251c0ee61360ea47f764bce2b726f4e10aa5a9639474a9d62b4d9e7b1cb02a4812f46415c706b9b7edcb141213' };
const adminOk = (pw) => E.ADMIN_PASSWORD
  ? crypto.timingSafeEqual(sha(pw), sha(E.ADMIN_PASSWORD))
  : crypto.timingSafeEqual(Buffer.from(hashPw(String(pw || ''), ADMIN_DEFAULT.salt), 'hex'), Buffer.from(ADMIN_DEFAULT.hash, 'hex'));
const STATIC = { '/': ['nova.html', 'text/html; charset=utf-8'], '/index.html': ['nova.html', 'text/html; charset=utf-8'], '/logo.svg': ['logo.svg', 'image/svg+xml'], '/logo.png': ['logo.png', 'image/png'] };

http.createServer(async (req, res) => {
  const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress;
  const url = req.url.split('?')[0];
  if (req.method === 'OPTIONS') { res.writeHead(204, cors()); return res.end(); }
  try {
    if (req.method === 'GET' && STATIC[url]) {
      const f = path.join(E.PAGE_DIR || __dirname, STATIC[url][0]);
      if (!fs.existsSync(f)) return send(res, 404, { error: 'File missing: ' + STATIC[url][0] });
      res.writeHead(200, { 'Content-Type': STATIC[url][1], 'Cache-Control': 'no-cache' }); return res.end(fs.readFileSync(f));
    }
    if (url === '/api/health') return send(res, 200, { ok: true, chat: !!KEY, email: !!E.RESEND_API_KEY });
    if (url === '/api/config') return send(res, 200, { payUrl: E.PAY_URL || '', price: E.PRICE_TEXT || '', limits: LIMITS, windowHours: WINDOW / 36e5, adminEnabled: true });

    if (url === '/api/signup' && req.method === 'POST') {
      if (throttled(ip)) return send(res, 429, { error: 'Too many attempts. Try again later.' });
      const b = await readBody(req), name = cleanName(b.name), pw = String(b.password || '');
      if (name.length < 3) return send(res, 400, { error: 'Username needs 3 or more letters or numbers.' });
      if (pw.length < 8) return send(res, 400, { error: 'Password needs at least 8 characters.' });
      if (db.users[name]) return send(res, 409, { error: 'That username is taken.' });
      const salt = crypto.randomBytes(16).toString('hex');
      db.users[name] = { salt, hash: hashPw(pw, salt), plan: 'free', data: { chats: [], projects: [], mem: [] }, created: Date.now() }; dirty = true;
      return send(res, 200, { name, token: sign({ name, exp: Date.now() + 30 * 864e5 }) });
    }
    if (url === '/api/login' && req.method === 'POST') {
      if (throttled(ip)) return send(res, 429, { error: 'Too many attempts. Try again later.' });
      const b = await readBody(req), name = cleanName(b.name), u = db.users[name];
      const ok = u && crypto.timingSafeEqual(Buffer.from(hashPw(String(b.password || ''), u.salt), 'hex'), Buffer.from(u.hash, 'hex'));
      if (!ok) return send(res, 401, { error: 'Wrong username or password.' });
      return send(res, 200, { name, token: sign({ name, exp: Date.now() + 30 * 864e5 }) });
    }
    if (url === '/api/data') {
      const p = who(req); if (!p || !p.name) return send(res, 401, { error: 'Please sign in again.' });
      if (req.method === 'GET') return send(res, 200, db.users[p.name].data);
      if (req.method === 'PUT') { const b = await readBody(req, 8e6);
        db.users[p.name].data = { chats: (b.chats || []).slice(0, 40), projects: (b.projects || []).slice(0, 30), mem: (b.mem || []).slice(0, 50) }; dirty = true; return send(res, 200, { ok: true }); }
    }
    if (url === '/api/usage') {
      const p = who(req); if (p && p.admin) return send(res, 200, { plan: 'admin', unlimited: true });
      const plan = p ? p.plan : 'guest', q = quota(p ? 'u:' + p.name : 'g:' + ip, LIMITS[plan], false);
      return send(res, 200, { plan, used: q.used, max: q.max, resetAt: q.reset });
    }
    if (url === '/api/feedback' && req.method === 'POST') {
      if (throttled(ip + 'f')) return send(res, 429, { error: 'Too many reports. Try again later.' });
      const b = await readBody(req, 2e5), p = who(req);
      const how = await recordFeedback(`Supernova ${b.kind === 'report' ? 'report: ' + (b.type || '') : 'rating: ' + (b.v || '')}`, { from: p ? p.name || 'admin' : 'guest', ...b });
      return send(res, 200, { ok: true, how });
    }
    if (url === '/api/admin' && req.method === 'POST') {
      if (throttled(ip + 'a')) return send(res, 429, { error: 'Too many attempts. Try again later.' });
      const b = await readBody(req);
      if (!adminOk(b.password)) return send(res, 401, { error: 'Wrong admin password.' });
      return send(res, 200, { token: sign({ admin: true, exp: Date.now() + 12 * 36e5 }) });
    }
    if (url === '/api/admin/feedback') {
      const p = who(req); if (!p || !p.admin) return send(res, 403, { error: 'Admin only.' });
      return send(res, 200, { items: db.feedback.slice(-100).reverse(), users: Object.entries(db.users).map(([n, u]) => ({ name: n, plan: u.plan || 'free' })) });
    }
    if (url === '/api/admin/plan' && req.method === 'POST') {
      const p = who(req); if (!p || !p.admin) return send(res, 403, { error: 'Admin only.' });
      const b = await readBody(req), name = cleanName(b.name);
      if (!db.users[name]) return send(res, 404, { error: 'No such user.' });
      db.users[name].plan = b.plan === 'pro' ? 'pro' : 'free'; dirty = true; return send(res, 200, { ok: true });
    }
    if (url === '/api/chat' && req.method === 'POST') {
      if (!KEY) return send(res, 500, { error: 'The server has no ANTHROPIC_API_KEY set.' });
      const p = who(req);
      if (!(p && p.admin)) { const plan = p ? p.plan : 'guest', q = quota(p ? 'u:' + p.name : 'g:' + ip, LIMITS[plan], true);
        if (!q.ok) return send(res, 429, { error: `You have used all ${q.max} ${plan === 'pro' ? 'Pro' : 'free'} chats. They unlock again in ${dur(q.reset - Date.now())}.${plan === 'pro' ? '' : ' Upgrade for more.'}`, resetAt: q.reset, limit: true }); }
      const b = await readBody(req, 8e6);
      const msgs = (b.messages || []).filter((m) => (m.role === 'user' || m.role === 'assistant') && m.content).slice(-30);
      if (!msgs.length || msgs[0].role !== 'user' || msgs[msgs.length - 1].role !== 'user') return send(res, 400, { error: 'Invalid messages.' });
      const eff = b.effort === 'instant' || b.effort === 'high' ? b.effort : 'medium';
      const ctl = new AbortController(); req.on('close', () => ctl.abort());
      const up = await fetch(UPSTREAM + '/v1/messages', { method: 'POST', signal: ctl.signal,
        headers: { 'x-api-key': KEY, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
        body: JSON.stringify({ model: eff === 'instant' ? MODEL_FAST : eff === 'high' ? MODEL_DEEP : MODEL, max_tokens: eff === 'instant' ? 8000 : eff === 'high' ? 32000 : 16000, stream: true, messages: msgs }) });
      if (!up.ok) { const t = await up.text(); console.error('upstream', up.status, t.slice(0, 300)); return send(res, up.status === 429 ? 429 : 502, { error: up.status === 429 ? 'The AI is busy or out of credits. Try again soon.' : 'The AI service returned an error.' }); }
      res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', ...cors() });
      for await (const chunk of up.body) res.write(chunk);
      return res.end();
    }
    send(res, 404, { error: 'Not found' });
  } catch (e) { if (!res.headersSent) send(res, 500, { error: e.message || 'Server error' }); else res.end(); }
}).listen(PORT, () => console.log(`Supernova on :${PORT}  chat=${KEY ? 'ready' : 'NO API KEY'}  admin=${E.ADMIN_PASSWORD ? 'custom password' : 'default password'}  email=${E.RESEND_API_KEY ? 'on' : 'off'}`));
