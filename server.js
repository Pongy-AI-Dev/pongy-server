import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import Database from 'better-sqlite3';
import rateLimit from 'express-rate-limit';
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import session from 'express-session';
import 'dotenv/config';

const app = express();
app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(express.static('.'));

app.use(session({
  secret: process.env.SESSION_SECRET || 'pongy-session-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 30 * 24 * 60 * 60 * 1000 }
}));
app.use(passport.initialize());
app.use(passport.session());

const db = new Database('pongy.db');
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT,
    nickname TEXT DEFAULT '',
    avatar TEXT DEFAULT '',
    subscription_until INTEGER DEFAULT 0,
    device_id TEXT DEFAULT '',
    google_id TEXT DEFAULT '',
    email_verified INTEGER DEFAULT 0,
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
  CREATE TABLE IF NOT EXISTS verify_codes (
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
const RESEND_API_KEY = process.env.RESEND_API_KEY || '';
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || '';

const FREE_MODELS = [
  'deepseek/deepseek-chat-v3-0324:free',
  'meta-llama/llama-3.3-70b-instruct:free',
  'qwen/qwen-2.5-72b-instruct:free',
  'mistralai/mistral-nemo:free',
  'google/gemma-2-27b-it:free',
  'google/gemma-2-9b-it:free',
  'microsoft/phi-3-medium-128k-instruct:free',
  'meta-llama/llama-3.1-8b-instruct:free',
  'meta-llama/llama-3.2-3b-instruct:free',
  'microsoft/phi-3-mini-128k-instruct:free',
  'mistralai/mistral-7b-instruct:free',
  'qwen/qwen-2.5-7b-instruct:free'
];

const REASONING_MODELS = [
  'deepseek/deepseek-r1:free',
  'deepseek/deepseek-r1-distill-llama-70b:free',
  'qwen/qwq-32b-preview:free',
  ...FREE_MODELS
];

const CODE_MODELS = [
  'deepseek/deepseek-chat-v3-0324:free',
  'qwen/qwen-2.5-coder-32b-instruct:free',
  'meta-llama/llama-3.3-70b-instruct:free',
  ...FREE_MODELS
];

const PLUS_MODELS = [
  'openai/gpt-4o-mini',
  'openai/gpt-4o',
  'anthropic/claude-3.5-sonnet',
  'anthropic/claude-3-haiku',
  'google/gemini-2.5-flash',
  'google/gemini-2.5-pro',
  'deepseek/deepseek-chat-v3-0324',
  'deepseek/deepseek-r1',
  'x-ai/grok-beta',
  'perplexity/sonar-small-chat',
  'meta-llama/llama-3.3-70b-instruct',
  'mistralai/mistral-large'
];

function pickModelsForQuery(text, isPlus) {
  var lower = (text || '').toLowerCase();
  var codeKeywords = ['код', 'code', 'функция', 'function', 'python', 'javascript', 'java', 'html', 'css', 'sql', 'bash', 'баг', 'bug', 'ошибка в коде', 'error', 'напиши программу', 'напиши скрипт', 'react', 'vue', 'node', 'php', 'c++', 'c#', 'compile', 'компил', 'отлад', 'debug', 'regex', 'алгоритм'];
  var mathKeywords = ['математик', 'math', 'решить', 'уравнени', 'формул', 'вычислить', 'логик', 'задач', 'докажи', 'теорем', 'производн', 'интеграл', 'вероятност', 'статистик', 'solve', 'calculate'];
  var isCode = codeKeywords.some(function(k){ return lower.indexOf(k) !== -1; });
  var isMath = mathKeywords.some(function(k){ return lower.indexOf(k) !== -1; });
  var list;
  if (isCode) list = CODE_MODELS.slice();
  else if (isMath) list = REASONING_MODELS.slice();
  else list = FREE_MODELS.slice();
  if (isPlus) list = PLUS_MODELS.concat(list);
  return list;
}

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

// ============ GOOGLE OAUTH ============
if (GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET) {
  passport.use(new GoogleStrategy({
      clientID: GOOGLE_CLIENT_ID,
      clientSecret: GOOGLE_CLIENT_SECRET,
      callbackURL: 'https://pongy-server.onrender.com/auth/google/callback'
    },
    function(accessToken, refreshToken, profile, done) {
      const email = profile.emails && profile.emails[0] && profile.emails[0].value;
      if (!email) return done(new Error('No email'), null);
      let user = db.prepare('SELECT * FROM users WHERE google_id=? OR email=?').get(profile.id, email.toLowerCase());
      if (!user) {
        const info = db.prepare('INSERT INTO users (email, google_id, nickname, avatar, email_verified) VALUES (?, ?, ?, ?, 1)')
          .run(email.toLowerCase(), profile.id, profile.displayName || '', (profile.photos && profile.photos[0] && profile.photos[0].value) || '');
        user = { id: info.lastInsertRowid, email: email.toLowerCase(), nickname: profile.displayName || '', avatar: (profile.photos && profile.photos[0] && profile.photos[0].value) || '', subscription_until: 0, google_id: profile.id };
      } else {
        db.prepare('UPDATE users SET google_id=?, avatar=? WHERE id=?').run(profile.id, (profile.photos && profile.photos[0] && profile.photos[0].value) || '', user.id);
        user.google_id = profile.id;
        user.avatar = (profile.photos && profile.photos[0] && profile.photos[0].value) || '';
      }
      return done(null, user);
    }
  ));
  passport.serializeUser((user, done) => done(null, user.id));
  passport.deserializeUser((id, done) => {
    const user = db.prepare('SELECT * FROM users WHERE id=?').get(id);
    done(null, user);
  });

  app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

  app.get('/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/?google_error=1' }),
    (req, res) => {
      const token = makeToken(req.user);
      res.redirect(`/?google_token=${token}`);
    }
  );
}

// ============ AUTH ============
app.post('/api/register', authLimit, (req, res) => {
  const { email, password, deviceId, code } = req.body || {};
  if (!email || !password || password.length < 6) return res.status(400).json({ error: 'Email и пароль (мин. 6) обязательны' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Неверный формат email' });

  // Проверяем код подтверждения
  const vc = db.prepare('SELECT * FROM verify_codes WHERE email=?').get(email.toLowerCase());
  if (!vc) return res.status(400).json({ error: 'Сначала подтвердите email кодом' });
  if (vc.expires_at < Date.now()) return res.status(400).json({ error: 'Код подтверждения истёк' });
  if (vc.code !== String(code)) return res.status(400).json({ error: 'Неверный код подтверждения' });

  const did = String(deviceId || '').slice(0, 64);
  if (did) {
    const count = db.prepare('SELECT COUNT(DISTINCT email) as c FROM device_registrations WHERE device_id=?').get(did);
    if (count.c >= 3) return res.status(429).json({ error: 'На 1 устройство можно регистрировать не более 3 аккаунтов' });
  }

  try {
    const hash = bcrypt.hashSync(password, 10);
    const info = db.prepare('INSERT INTO users (email, password, device_id, email_verified) VALUES (?, ?, ?, 1)').run(email.toLowerCase(), hash, did);
    const user = { id: info.lastInsertRowid, email: email.toLowerCase() };
    if (did) try { db.prepare('INSERT OR IGNORE INTO device_registrations (device_id, email) VALUES (?, ?)').run(did, user.email); } catch(e){}
    db.prepare('DELETE FROM verify_codes WHERE email=?').run(email.toLowerCase());
    res.json({ token: makeToken(user), user: { id: user.id, email: user.email, nickname: '', subscription_until: 0 } });
  } catch (e) {
    if (String(e).includes('UNIQUE')) return res.status(409).json({ error: 'Email уже зарегистрирован' });
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.post('/api/register/send-code', authLimit, async (req, res) => {
  const { email } = req.body || {};
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Введите корректный email' });
  const existing = db.prepare('SELECT id FROM users WHERE email=?').get(email.toLowerCase());
  if (existing) return res.status(409).json({ error: 'Email уже зарегистрирован' });

  const code = String(Math.floor(100000 + Math.random() * 900000));
  db.prepare('INSERT OR REPLACE INTO verify_codes (email, code, expires_at) VALUES (?, ?, ?)').run(email.toLowerCase(), code, Date.now() + 10*60*1000);

  try {
    await sendEmail(email, 'Pongy AI — код подтверждения',
      '<div style="font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:480px;margin:0 auto;padding:32px 24px;background:#f7f7f9;border-radius:20px">' +
      '<div style="text-align:center;margin-bottom:24px"><div style="width:64px;height:64px;margin:0 auto 16px;border-radius:20px;background:linear-gradient(135deg,#6366f1,#8b5cf6);color:#fff;font-size:32px;font-weight:700;line-height:64px">P</div><h2 style="color:#111;margin:0;font-size:20px">Pongy AI</h2></div>' +
      '<h3 style="color:#111;margin:0 0 12px;font-size:17px">Подтверждение регистрации</h3>' +
      '<p style="color:#666;font-size:14px;margin:0 0 16px">Ваш код:</p>' +
      '<div style="font-size:34px;font-weight:bold;letter-spacing:8px;color:#6366f1;background:#fff;padding:20px;border-radius:14px;text-align:center;margin:0 0 20px;font-family:Consolas,Monaco,monospace">' + code + '</div>' +
      '<p style="color:#999;font-size:12.5px;margin:0">Код действует 10 минут.</p>' +
      '</div>'
    );
  } catch (e) { console.error('[send-code]', e.message); }

  res.json({ ok: true });
});

app.post('/api/register/verify-code', authLimit, (req, res) => {
  const { email, code } = req.body || {};
  const row = db.prepare('SELECT * FROM verify_codes WHERE email=?').get((email || '').toLowerCase());
  if (!row) return res.status(400).json({ error: 'Код не найден' });
  if (row.expires_at < Date.now()) return res.status(400).json({ error: 'Код истёк' });
  if (row.code !== String(code)) return res.status(400).json({ error: 'Неверный код' });
  res.json({ ok: true });
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
  const ok = user && user.password && bcrypt.compareSync(password, user.password);
  if (!ok) {
    if (did) {
      const att = db.prepare('SELECT * FROM login_attempts WHERE device_id=?').get(did);
      const attempts = (att ? att.attempts : 0) + 1;
      if (attempts >= 10) {
        db.prepare('INSERT OR REPLACE INTO login_attempts (device_id, attempts, blocked_until) VALUES (?, 0, ?)').run(did, Date.now() + 30*60*1000);
        return res.status(429).json({ error: 'Слишком много неверных попыток. Устройство заблокировано на 30 минут.' });
      }
      db.prepare('INSERT OR REPLACE INTO login_attempts (device_id, attempts, blocked_until) VALUES (?, ?, 0)').run(did, attempts);
    }
    return res.status(401).json({ error: 'Неверные email или пароль' });
  }
  if (did) db.prepare('INSERT OR REPLACE INTO login_attempts (device_id, attempts, blocked_until) VALUES (?, 0, 0)').run(did);
  res.json({
    token: makeToken(user),
    user: { id: user.id, email: user.email, nickname: user.nickname, avatar: user.avatar || '', subscription_until: user.subscription_until }
  });
});

app.get('/api/me', auth, (req, res) => {
  const user = db.prepare('SELECT id,email,nickname,subscription_until,avatar,email_verified FROM users WHERE id=?').get(req.user.id);
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
  db.prepare('INSERT OR REPLACE INTO reset_codes (email, code, expires_at) VALUES (?, ?, ?)').run(email.toLowerCase(), code, Date.now() + 10*60*1000);
  try {
    await sendEmail(email, 'Pongy AI — код сброса пароля',
      '<div style="font-family:sans-serif;padding:24px;background:#f7f7f9;border-radius:16px;max-width:480px;margin:0 auto"><h2 style="color:#6366f1;margin:0 0 16px">Сброс пароля</h2><p>Ваш код:</p><div style="font-size:34px;font-weight:bold;letter-spacing:8px;color:#6366f1;background:#fff;padding:20px;border-radius:14px;text-align:center;margin:16px 0">' + code + '</div><p style="color:#999;font-size:12.5px">Код действует 10 минут.</p></div>'
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

// ============ SUBSCRIPTION (temporarily disabled) ============
app.post('/api/pay/create', auth, (req, res) => {
  return res.status(503).json({ error: 'В данный момент оплата недоступна. Попробуйте позже.' });
});

// ============ AI PROXY ============
app.post('/api/chat', auth, chatLimit, async (req, res) => {
  const { messages, model } = req.body || {};
  if (!Array.isArray(messages) || !messages.length) return res.status(400).json({ error: 'messages required' });
  if (!OPENROUTER_KEY) return res.status(500).json({ error: 'Server not configured' });

  const user = db.prepare('SELECT subscription_until FROM users WHERE id = ?').get(req.user.id);
  const isPlus = user && user.subscription_until && user.subscription_until > Date.now();
  let lastUserText = '';
  for (let i = messages.length - 1; i >= 0; i--) {
    if (messages[i].role === 'user') { lastUserText = messages[i].content || ''; break; }
  }
  let modelsToTry = pickModelsForQuery(lastUserText, isPlus);
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
      if (!r.ok) { lastError = await r.text(); lastStatus = r.status; console.log('[Pongy] skip:', m, r.status); continue; }
      console.log('[Pongy] ✅ using:', m, isPlus ? '[Plus]' : '[Free]');
      res.setHeader('Content-Type', 'text/event-stream');
      res.setHeader('Cache-Control', 'no-cache');
      res.setHeader('Connection', 'keep-alive');
      res.setHeader('X-Accel-Buffering', 'no');
      res.setHeader('X-Used-Model', m);
      const reader = r.body.getReader();
      const dec = new TextDecoder();
      while (true) { const { done, value } = await reader.read(); if (done) break; res.write(dec.decode(value, { stream: true })); }
      res.end(); return;
    } catch (e) { lastError = e.message; }
  }
  console.error('[Pongy] ❌ all failed');
  res.status(lastStatus).send(lastError || 'All models unavailable');
});

app.get('/', (req, res) => res.sendFile('index.html', { root: '.' }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('✅ Pongy API on :' + PORT));
