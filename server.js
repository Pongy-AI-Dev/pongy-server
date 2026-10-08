import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import Database from 'better-sqlite3';
import rateLimit from 'express-rate-limit';
import 'dotenv/config';

const app = express();
app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(express.static('.'));

const db = new Database('pongy.db');
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    nickname TEXT DEFAULT '',
    subscription_until INTEGER DEFAULT 0,
    device_id TEXT DEFAULT '',
    created_at INTEGER DEFAULT (strftime('%s','now')*1000)
  );
  CREATE TABLE IF NOT EXISTS chats (
    id TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    title TEXT DEFAULT '',
    messages TEXT DEFAULT '[]',
    updated_at INTEGER,
    pinned INTEGER DEFAULT 0,
    PRIMARY KEY (id, user_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS reset_codes (
    email TEXT PRIMARY KEY,
    code TEXT NOT NULL,
    expires_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS login_attempts (
    device_id TEXT PRIMARY KEY,
    attempts INTEGER DEFAULT 0,
    blocked_until INTEGER DEFAULT 0
  );
  CREATE TABLE IF NOT EXISTS device_registrations (
    device_id TEXT NOT NULL,
    email TEXT NOT NULL,
    created_at INTEGER DEFAULT (strftime('%s','now')*1000),
    PRIMARY KEY (device_id, email)
  );
  CREATE INDEX IF NOT EXISTS idx_chats_user ON chats(user_id);
`);

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const OPENROUTER_KEY = process.env.OPENROUTER_KEY || '';
const RESEND_API_KEY = process.env.RESEND_API_KEY || 're_8fgi4qFe_9T9amqoQZLE27LDNfZNtqyQS';

const FREE_MODELS = [
  'deepseek/deepseek-r1:free',
  'meta-llama/llama-3.3-70b-instruct:free',
  'google/gemini-2.0-flash-exp:free',
  'qwen/qwen2.5-72b-instruct:free',
  'mistralai/mistral-nemo:free'
];

const PLUS_MODELS = [
  'openai/gpt-4o-mini',
  'anthropic/claude-3.5-sonnet',
  'google/gemini-2.5-flash',
  'deepseek/deepseek-chat-v3-0324',
  'x-ai/grok-beta'
];

const authLimit = rateLimit({ windowMs: 15*60*1000, max: 30 });
const chatLimit = rateLimit({ windowMs: 60*1000, max: 30 });
app.use(rateLimit({ windowMs: 60*1000, max: 200 }));

function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'no token' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch (e) { res.status(401).json({ error: 'invalid token' }); }
}
function makeToken(user) {
  return jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '365d' });
}

function sendEmail(to, subject, html) {
  if (!RESEND_API_KEY) {
    console.log('[EMAIL-DEMO] to=' + to + ' subject=' + subject);
    return Promise.resolve();
  }
  return fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + RESEND_API_KEY },
    body: JSON.stringify({ from: 'Pongy AI <onboarding@resend.dev>', to: [to], subject, html })
  }).then(function(r){
    if(!r.ok) return r.text().then(function(t){ console.error('[Resend]', t); });
    return r.json();
  }).then(function(j){ if(j) console.log('[Resend] sent:', j.id); });
}

// ============ AUTH ============
app.post('/api/register', authLimit, (req, res) => {
  const { email, password, deviceId } = req.body || {};
  if (!email || !password || password.length < 6) return res.status(400).json({ error: 'Email and password (min 6) required' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Invalid email format' });
  
  const did = String(deviceId || '').slice(0, 64);
  if (did) {
    const count = db.prepare('SELECT COUNT(DISTINCT email) as c FROM device_registrations WHERE device_id=?').get(did);
    if (count.c >= 3) {
      return res.status(429).json({ error: 'На 1 устройство можно регистрировать не более 3 аккаунтов' });
    }
  }
  
  try {
    const hash = bcrypt.hashSync(password, 10);
    const info = db.prepare('INSERT INTO users (email, password, device_id) VALUES (?, ?, ?)').run(email.toLowerCase(), hash, did);
    const user = { id: info.lastInsertRowid, email: email.toLowerCase() };
    if (did) {
      try { db.prepare('INSERT OR IGNORE INTO device_registrations (device_id, email) VALUES (?, ?)').run(did, user.email); } catch(e){}
    }
    res.json({ token: makeToken(user), user: { id: user.id, email: user.email, nickname: '', subscription_until: 0 } });
  } catch (e) {
    if (String(e).includes('UNIQUE')) return res.status(409).json({ error: 'Email already registered' });
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/login', authLimit, (req, res) => {
  const { email, password, deviceId } = req.body || {};
  const did = String(deviceId || '').slice(0, 64);
  
  if (did) {
    const att = db.prepare('SELECT * FROM login_attempts WHERE device_id=?').get(did);
    if (att && att.blocked_until > Date.now()) {
      const mins = Math.ceil((att.blocked_until - Date.now()) / 60000);
      return res.status(429).json({ error: 'Устройство заблокировано. Попробуйте через ' + mins + ' мин.' });
    }
  }
  
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get((email || '').toLowerCase());
  const ok = user && bcrypt.compareSync(password, user.password);
  
  if (!ok) {
    if (did) {
      const att = db.prepare('SELECT * FROM login_attempts WHERE device_id=?').get(did);
      const attempts = (att ? att.attempts : 0) + 1;
      if (attempts >= 10) {
        const blockedUntil = Date.now() + 30*60*1000;
        db.prepare('INSERT OR REPLACE INTO login_attempts (device_id, attempts, blocked_until) VALUES (?, 0, ?)').run(did, blockedUntil);
        return res.status(429).json({ error: 'Слишком много неверных попыток. Устройство заблокировано на 30 минут.' });
      }
      db.prepare('INSERT OR REPLACE INTO login_attempts (device_id, attempts, blocked_until) VALUES (?, ?, 0)').run(did, attempts);
    }
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  
  if (did) {
    db.prepare('INSERT OR REPLACE INTO login_attempts (device_id, attempts, blocked_until) VALUES (?, 0, 0)').run(did);
  }
  
  res.json({
    token: makeToken(user),
    user: { id: user.id, email: user.email, nickname: user.nickname, subscription_until: user.subscription_until }
  });
});

app.get('/api/me', auth, (req, res) => {
  const user = db.prepare('SELECT id,email,nickname,subscription_until FROM users WHERE id=?').get(req.user.id);
  if (!user) return res.status(404).json({ error: 'Not found' });
  res.json(user);
});

app.put('/api/me', auth, (req, res) => {
  const { nickname } = req.body || {};
  db.prepare('UPDATE users SET nickname=? WHERE id=?').run((nickname || '').slice(0, 32), req.user.id);
  res.json({ ok: true });
});

// ============ PASSWORD RESET ============
app.post('/api/password/send-code', authLimit, async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'Email required' });
  const user = db.prepare('SELECT id FROM users WHERE email=?').get(email.toLowerCase());
  if (!user) return res.json({ ok: true });
  
  const code = String(Math.floor(100000 + Math.random() * 900000));
  const expiresAt = Date.now() + 10 * 60 * 1000;
  db.prepare('INSERT OR REPLACE INTO reset_codes (email, code, expires_at) VALUES (?, ?, ?)').run(email.toLowerCase(), code, expiresAt);
  
  try {
    await sendEmail(email, 'Pongy AI — код сброса пароля',
      '<div style="font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:480px;margin:0 auto;padding:32px 24px;background:#f7f7f9;border-radius:20px">' +
      '<div style="text-align:center;margin-bottom:24px"><div style="width:64px;height:64px;margin:0 auto 16px;border-radius:20px;background:linear-gradient(135deg,#6366f1,#8b5cf6);color:#fff;font-size:32px;font-weight:700;line-height:64px">P</div><h2 style="color:#111;margin:0;font-size:20px">Pongy AI</h2></div>' +
      '<h3 style="color:#111;margin:0 0 12px;font-size:17px">Сброс пароля</h3>' +
      '<p style="color:#666;font-size:14px;margin:0 0 16px;line-height:1.6">Ваш код подтверждения:</p>' +
      '<div style="font-size:34px;font-weight:bold;letter-spacing:8px;color:#6366f1;background:#fff;padding:20px;border-radius:14px;text-align:center;margin:0 0 20px;font-family:Consolas,Monaco,monospace">' + code + '</div>' +
      '<p style="color:#999;font-size:12.5px;margin:0;line-height:1.6">Код действует 10 минут. Если вы не запрашивали сброс — просто проигнорируйте это письмо.</p>' +
      '<p style="color:#999;font-size:11.5px;margin:20px 0 0;text-align:center">Pongy AI · support@pongy.ai</p>' +
      '</div>'
    );
  } catch (e) { console.error('[send-code]', e.message); }
  
  res.json({ ok: true });
});

app.post('/api/password/verify-code', authLimit, (req, res) => {
  const { email, code } = req.body || {};
  const row = db.prepare('SELECT * FROM reset_codes WHERE email=?').get((email || '').toLowerCase());
  if (!row) return res.status(400).json({ error: 'Код не найден' });
  if (row.expires_at < Date.now()) return res.status(400).json({ error: 'Код истёк' });
  if (row.code !== String(code)) return res.status(400).json({ error: 'Неверный код' });
  res.json({ ok: true });
});

app.post('/api/password/reset', authLimit, (req, res) => {
  const { email, code, newPassword } = req.body || {};
  if (!newPassword || newPassword.length < 6) return res.status(400).json({ error: 'Пароль минимум 6 символов' });
  const row = db.prepare('SELECT * FROM reset_codes WHERE email=?').get((email || '').toLowerCase());
  if (!row || row.code !== String(code) || row.expires_at < Date.now()) return res.status(400).json({ error: 'Код недействителен' });
  const hash = bcrypt.hashSync(newPassword, 10);
  db.prepare('UPDATE users SET password=? WHERE email=?').run(hash, email.toLowerCase());
  db.prepare('DELETE FROM reset_codes WHERE email=?').run(email.toLowerCase());
  res.json({ ok: true });
});

// ============ CHATS ============
app.get('/api/chats', auth, (req, res) => {
  const rows = db.prepare('SELECT * FROM chats WHERE user_id=? ORDER BY pinned DESC, updated_at DESC').all(req.user.id);
  res.json(rows.map(r => ({ ...r, messages: JSON.parse(r.messages), pinned: !!r.pinned })));
});
app.put('/api/chats/:id', auth, (req, res) => {
  const { title, messages, pinned } = req.body || {};
  const id = String(req.params.id).slice(0, 64);
  if (!Array.isArray(messages)) return res.status(400).json({ error: 'messages must be array' });
  const upd = Date.now();
  const exists = db.prepare('SELECT 1 FROM chats WHERE id=? AND user_id=?').get(id, req.user.id);
  if (exists) db.prepare('UPDATE chats SET title=?, messages=?, pinned=?, updated_at=? WHERE id=? AND user_id=?').run(title||'', JSON.stringify(messages), pinned?1:0, upd, id, req.user.id);
  else db.prepare('INSERT INTO chats (id, user_id, title, messages, updated_at, pinned) VALUES (?,?,?,?,?,?)').run(id, req.user.id, title||'', JSON.stringify(messages), upd, pinned?1:0);
  res.json({ ok: true });
});
app.delete('/api/chats/:id', auth, (req, res) => {
  db.prepare('DELETE FROM chats WHERE id=? AND user_id=?').run(req.params.id, req.user.id);
  res.json({ ok: true });
});

// ============ AI PROXY ============
app.post('/api/chat', auth, chatLimit, async (req, res) => {
  const { messages, model } = req.body || {};
  if (!Array.isArray(messages) || !messages.length) return res.status(400).json({ error: 'messages required' });
  if (!OPENROUTER_KEY) return res.status(500).json({ error: 'Server not configured' });

  const user = db.prepare('SELECT subscription_until FROM users WHERE id = ?').get(req.user.id);
  const isPlus = user && user.subscription_until && user.subscription_until > Date.now();
  let modelsToTry = isPlus ? [...PLUS_MODELS, ...FREE_MODELS] : [...FREE_MODELS];
  if (model) modelsToTry = [model, ...modelsToTry.filter(m => m !== model)];

  let lastError = null, lastStatus = 500;
  for (const m of modelsToTry) {
    try {
      const r = await fetch('https://openrouter.ai/api/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer ' + OPENROUTER_KEY,
          'HTTP-Referer': 'https://pongy-ai.devs.surf',
          'X-Title': 'Pongy AI'
        },
        body: JSON.stringify({ model: m, stream: true, messages })
      });
      if (r.status === 401) { const txt = await r.text(); return res.status(401).send(txt); }
      if (!r.ok) { lastError = await r.text(); lastStatus = r.status; console.log('[Pongy] fail:', m, r.status); continue; }
      console.log('[Pongy] model:', m, isPlus ? '[Plus]' : '[Free]');
      res.setHeader('Content-Type', 'text/event-stream');
      res.setHeader('Cache-Control', 'no-cache');
      res.setHeader('Connection', 'keep-alive');
      res.setHeader('X-Accel-Buffering', 'no');
      const reader = r.body.getReader();
      const dec = new TextDecoder();
      while (true) { const { done, value } = await reader.read(); if (done) break; res.write(dec.decode(value, { stream: true })); }
      res.end(); return;
    } catch (e) { lastError = e.message; }
  }
  console.error('[Pongy] All models failed');
  res.status(lastStatus).send(lastError || 'All models unavailable');
});

app.get('/', (req, res) => res.sendFile('index.html', { root: '.' }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('✅ Pongy API on :' + PORT));
