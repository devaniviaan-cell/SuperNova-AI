// Supernova server: lets Supernova work outside Claude (GitHub Pages, your own site).
// Zero dependencies. Needs Node 18 or newer.  Run:  node server.js
//
// Environment variables:
//   ANTHROPIC_API_KEY  (required for chat)  your key from console.anthropic.com
//   SECRET             (required in production) long random text used to sign login tokens
//   MODEL              default claude-sonnet-5-5
//   MODEL_DEEP         optional stronger model used when the page asks for deep thinking
//   ALLOWED_ORIGIN     your site, e.g. https://yourname.github.io  (default * = anyone)
//   RESEND_API_KEY     optional; with it, feedback and reports are emailed (resend.com)
//   FEEDBACK_TO        default devaniviaan@gmail.com
//   FEEDBACK_FROM      default "Supernova <onboarding@resend.dev>"
//   DAILY_LIMIT_USER   messages per signed-in user per day (default 100)
//   DAILY_LIMIT_GUEST  messages per guest IP per day (default 10)
//   DATA_FILE          default ./supernova-data.json
//   PORT               default 8787
const http = require('node:http');
const crypto = require('node:crypto');
const fs = require('node:fs');

const E = process.env;
const PORT = +E.PORT || 8787;
const KEY = E.ANTHROPIC_API_KEY || '';
const SECRET = E.SECRET || crypto.randomBytes(32).toString('hex'); // random = tokens reset on restart
const MODEL = E.MODEL || 'claude-sonnet-5-5';
const MODEL_DEEP = E.MODEL_DEEP || MODEL;
const ORIGIN = E.ALLOWED_ORIGIN || '*';
const TO = E.FEEDBACK_TO || 'devaniviaan@gmail.com';
const FROM = E.FEEDBACK_FROM || 'Supernova <onboarding@resend.dev>';
const LIM_USER = +E.DAILY_LIMIT_USER || 100;
const LIM_GUEST = +E.DAILY_LIMIT_GUEST || 10;
const FILE = E.DATA_FILE || './supernova-data.json';
const UPSTREAM = E.ANTHROPIC_BASE || 'https://api.anthropic.com';

let db = { users: {} };
try { db = JSON.parse(fs.readFileSync(FILE, 'utf8')); } catch (e) {}
let dirty = false;
const flush = () => { if (!dirty) return; dirty = false; try { fs.writeFileSync(FILE + '.tmp', JSON.stringify(db)); fs.renameSync(FILE + '.tmp', FILE); } catch (e) { console.error('save failed', e.message); } };
setInterval(flush, 3000).unref();
process.on('SIGINT', () => { flush(); process.exit(0); });

const day = () => new Date().toISOString().slice(0, 10);
const b64 = (s) => Buffer.from(s).toString('base64url');
const sign = (p) => { const body = b64(JSON.stringify(p)); return body + '.' + crypto.createHmac('sha256', SECRET).update(body).digest('base64url'); };
function verify(tok) {
  try {
    const [body, sig] = tok.split('.');
    const good = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
    if (sig.length !== good.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(good))) return null;
    const p = JSON.parse(Buffer.from(body, 'base64url').toString());
    return p.exp > Date.now() ? p : null;
  } catch (e) { return null; }
}
const hash = (pw, salt) => crypto.scryptSync(pw, salt, 64).toString('hex');
const attempts = new Map(); // ip -> [timestamps]
function throttled(ip) {
  const now = Date.now(), a = (attempts.get(ip) || []).filter((t) => now - t < 15 * 60 * 1000);
  a.push(now); attempts.set(ip, a); return a.length > 12;
}
const used = new Map(); // key -> {day,count}
function useQuota(k, max) {
  const u = used.get(k); if (!u || u.day !== day()) { used.set(k, { day: day(), count: 1 }); return true; }
  if (u.count >= max) return false; u.count++; return true;
}

function send(res, code, obj) {
  res.writeHead(code, { 'Content-Type': 'application/json', ...cors() }); res.end(JSON.stringify(obj));
}
const cors = () => ({
  'Access-Control-Allow-Origin': ORIGIN, 'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, OPTIONS',
});
function readBody(req, max = 3e6) {
  return new Promise((ok, no) => {
    let n = 0; const parts = [];
    req.on('data', (c) => { n += c.length; if (n > max) { no(new Error('Request too large')); req.destroy(); } else parts.push(c); });
    req.on('end', () => { try { ok(JSON.parse(Buffer.concat(parts).toString() || '{}')); } catch (e) { no(new Error('Bad JSON')); } });
    req.on('error', no);
  });
}
const who = (req) => { const t = (req.headers.authorization || '').replace(/^Bearer /, ''); const p = t && verify(t); return p && db.users[p.name] ? p : null; };
const cleanName = (n) => String(n || '').trim().toLowerCase().replace(/[^a-z0-9_.-]/g, '').slice(0, 30);

async function emailFeedback(subject, text) {
  if (!E.RESEND_API_KEY) { console.log('[feedback]', subject, text); fs.appendFileSync('feedback.log', `${new Date().toISOString()} ${subject}\n${text}\n\n`); return 'logged'; }
  const r = await fetch('https://api.resend.com/emails', {
    method: 'POST', headers: { Authorization: 'Bearer ' + E.RESEND_API_KEY, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from: FROM, to: [TO], subject, text }),
  });
  if (!r.ok) throw new Error('email failed ' + r.status);
  return 'emailed';
}

const server = http.createServer(async (req, res) => {
  const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress;
  const url = req.url.split('?')[0];
  if (req.method === 'OPTIONS') { res.writeHead(204, cors()); return res.end(); }
  try {
    if (url === '/api/health') return send(res, 200, { ok: true, chat: !!KEY, email: !!E.RESEND_API_KEY });

    if (url === '/api/signup' && req.method === 'POST') {
      if (throttled(ip)) return send(res, 429, { error: 'Too many attempts. Try again later.' });
      const b = await readBody(req), name = cleanName(b.name), pw = String(b.password || '');
      if (name.length < 3) return send(res, 400, { error: 'Username needs 3 or more letters or numbers.' });
      if (pw.length < 8) return send(res, 400, { error: 'Password needs at least 8 characters.' });
      if (db.users[name]) return send(res, 409, { error: 'That username is taken.' });
      const salt = crypto.randomBytes(16).toString('hex');
      db.users[name] = { salt, hash: hash(pw, salt), data: { chats: [], projects: [], mem: [] }, created: Date.now() }; dirty = true;
      return send(res, 200, { name, token: sign({ name, exp: Date.now() + 30 * 864e5 }) });
    }
    if (url === '/api/login' && req.method === 'POST') {
      if (throttled(ip)) return send(res, 429, { error: 'Too many attempts. Try again later.' });
      const b = await readBody(req), name = cleanName(b.name), u = db.users[name];
      const ok = u && crypto.timingSafeEqual(Buffer.from(hash(String(b.password || ''), u.salt), 'hex'), Buffer.from(u.hash, 'hex'));
      if (!ok) return send(res, 401, { error: 'Wrong username or password.' });
      return send(res, 200, { name, token: sign({ name, exp: Date.now() + 30 * 864e5 }) });
    }
    if (url === '/api/data') {
      const p = who(req); if (!p) return send(res, 401, { error: 'Please sign in again.' });
      if (req.method === 'GET') return send(res, 200, db.users[p.name].data);
      if (req.method === 'PUT') {
        const b = await readBody(req, 8e6);
        db.users[p.name].data = { chats: (b.chats || []).slice(0, 40), projects: (b.projects || []).slice(0, 30), mem: (b.mem || []).slice(0, 50) }; dirty = true;
        return send(res, 200, { ok: true });
      }
    }
    if (url === '/api/feedback' && req.method === 'POST') {
      if (throttled(ip + 'f')) return send(res, 429, { error: 'Too many reports. Try again later.' });
      const b = await readBody(req, 2e5), p = who(req);
      const subject = `Supernova ${b.kind === 'report' ? 'report: ' + (b.type || '') : 'rating: ' + (b.v || '')}`;
      const text = JSON.stringify({ from: p ? p.name : 'guest', ...b }, null, 2).slice(0, 20000);
      const how = await emailFeedback(subject, text);
      return send(res, 200, { ok: true, how });
    }
    if (url === '/api/chat' && req.method === 'POST') {
      if (!KEY) return send(res, 500, { error: 'The server has no ANTHROPIC_API_KEY set.' });
      const p = who(req);
      if (!useQuota(p ? 'u:' + p.name : 'g:' + ip, p ? LIM_USER : LIM_GUEST))
        return send(res, 429, { error: p ? 'Daily message limit reached. Come back tomorrow.' : 'Guest limit reached. Create a free account for more messages.' });
      const b = await readBody(req, 8e6);
      const msgs = (b.messages || []).filter((m) => (m.role === 'user' || m.role === 'assistant') && m.content).slice(-30);
      if (!msgs.length || msgs[0].role !== 'user' || msgs[msgs.length - 1].role !== 'user') return send(res, 400, { error: 'Invalid messages.' });
      const ctl = new AbortController(); req.on('close', () => ctl.abort());
      const up = await fetch(UPSTREAM + '/v1/messages', {
        method: 'POST', signal: ctl.signal,
        headers: { 'x-api-key': KEY, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
        body: JSON.stringify({ model: b.tier === 'complex' ? MODEL_DEEP : MODEL, max_tokens: 32000, stream: true, messages: msgs }),
      });
      if (!up.ok) { const t = await up.text(); console.error('upstream', up.status, t.slice(0, 300)); return send(res, up.status === 429 ? 429 : 502, { error: up.status === 429 ? 'The AI is busy or out of credits. Try again soon.' : 'The AI service returned an error.' }); }
      res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', ...cors() });
      for await (const chunk of up.body) res.write(chunk);
      return res.end();
    }
    send(res, 404, { error: 'Not found' });
  } catch (e) {
    if (!res.headersSent) send(res, 500, { error: e.message || 'Server error' }); else res.end();
  }
});
server.listen(PORT, () => console.log(`Supernova server on :${PORT}  chat=${KEY ? 'ready' : 'NO API KEY'}  email=${E.RESEND_API_KEY ? 'on' : 'off (logs to feedback.log)'}`));
