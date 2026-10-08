import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import Database from 'better-sqlite3';
import rateLimit from 'express-rate-limit';
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import session from 'express-session';
import FileStore from 'session-file-store';
import dns from 'dns';
import 'dotenv/config';

const app = express();
app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(express.static('.'));

// Сессии — используем /tmp (пишется на Linux, работает на Render)
const FileStoreSession = FileStore(session);
app.use(session({
  store: new FileStoreSession({ path: '/tmp/pongy-sessions', retries: 0, logFn: function(){} }),
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
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://pongy-ai.devs.surf';

const ALLOWED_DOMAINS = ['gmail.com','mail.com','mail.ru','email.com','yandex.ru'];

function isValidEmail(email) {
  if (!email || typeof email !== 'string') return false;
  const t = email.trim().toLowerCase();
  const m = t.match(/^[a-z0-9._%+-]+@([a-z0-9.-]+\.[a-z]{2,})$/i);
  if (!m) return false;
  return ALLOWED_DOMAINS.includes(m[1]);
}

async function checkMxRecord(email) {
  try {
    const records = await dns.promises.resolveMx(email.split('@')[1]);
    return Array.isArray(records) && records.length > 0;
  } catch (e) { return false; }
}

const FREE_MODELS = [
  'deepseek/deepseek-chat-v3-0324:free','meta-llama/llama-3.3-70b-instruct:free',
  'qwen/qwen-2.5-72b-instruct:free','mistralai/mistral-nemo:free',
  'google/gemma-2-27b-it:free','google/gemma-2-9b-it:free',
  'microsoft/phi-3-medium-128k-instruct:free','meta-llama/llama-3.1-8b-instruct:free',
  'meta-llama/llama-3.2-3b-instruct:free','microsoft/phi-3-mini-128k-instruct:free',
  'mistralai/mistral-7b-instruct:free','qwen/qwen-2.5-7b-instruct:free'
];
const REASONING_MODELS = [
  'deepseek/deepseek-r1:free','deepseek/deepseek-r1-distill-llama-70b:free',
  'qwen/qwq-32b-preview:free',...FREE_MODELS
];
const CODE_MODELS = [
  'deepseek/deepseek-chat-v3-0324:free','qwen/qwen-2.5-coder-32b-instruct:free',
  'meta-llama/llama-3.3-70b-instruct:free',...FREE_MODELS
];
const PLUS_MODELS = [
  'openai/gpt-4o-mini','openai/gpt-4o','anthropic/claude-3.5-sonnet',
  'anthropic/claude-3-haiku','google/gemini-2.5-flash','google/gemini-2.5-pro',
  'deepseek/deepseek-chat-v3-0324','deepseek/deepseek-r1','x-ai/grok-beta',
  'perplexity/sonar-small-chat','meta-llama/llama-3.3-70b-instruct','mistralai/mistral-large'
];

function pickModelsForQuery(text, isPlus) {
  var lower = (text || '').toLowerCase();
  var codeKw = ['код','code','функция','function','python','javascript','java','html','css','sql','bash','баг','bug','error','react','vue','node','php','c++','c#','compile','компил','debug','regex','алгоритм'];
  var mathKw = ['математик','math','решить','уравнени','формул','вычислить','логик','задач','докажи','теорем','интеграл','вероятност','solve','calculate'];
  var isCode = codeKw.some(function(k){ return lower.indexOf(k) !== -1; });
  var isMath = mathKw.some(function(k){ return lower.indexOf(k) !== -1; });
  var list = isCode ? CODE_MODELS.slice() : isMath ? REASONING_MODELS.slice() : FREE_MODELS.slice();
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
  if (!RESEND_API_KEY) { console.log('[EMAIL-DEMO] to=' + to); return Promise.resolve(); }
  return fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + RESEND_API_KEY },
    body: JSON.stringify({ from: 'Pongy AI <onboarding@resend.dev>', to: [to], subject, html })
  }).then(r => r.ok ? r.json() : r.text().then(t => console.error('[Resend]', t)))
    .then(j => { if (j && j.id) console.log('[Resend] sent:', j.id); });
}

// ============ GOOGLE OAUTH ============
passport.use(new GoogleStrategy({
  clientID: GOOGLE_CLIENT_ID || 'not-set',
  clientSecret: GOOGLE_CLIENT_SECRET || 'not-set',
  callbackURL: 'https://pongy-server.onrender.com/auth/google/callback'
}, function(accessToken, refreshToken, profile, done) {
  try {
    const email = profile.emails && profile.emails[0] && profile.emails[0].value;
    if (!email) return done(new Error('No email from Google'), null);

    const emailLower = email.toLowerCase();
    const avatar = (profile.photos && profile.photos[0] && profile.photos[0].value) || '';

    // Пробуем найти по google_id или email
    let user = db.prepare('SELECT * FROM users WHERE google_id=? OR email=?').get(profile.id, emailLower);

    if (!user) {
      // Создаём нового
      try {
        const info = db.prepare('INSERT INTO users (email, google_id, nickname, avatar, email_verified) VALUES (?, ?, ?, ?, 1)')
          .run(emailLower, profile.id, profile.displayName || '', avatar);
        user = { id: info.lastInsertRowid, email: emailLower, nickname: profile.displayName || '', avatar: avatar, subscription_until: 0, google_id: profile.id };
      } catch (e) {
        // UNIQUE conflict — пользователь есть, но без google_id
        console.error('[Google] Insert failed:', e.message);
        user = db.prepare('SELECT * FROM users WHERE email=?').get(emailLower);
        if (!user) return done(e, null);
      }
    }

    // Обновляем google_id и avatar если нужно
    if (user && !user.google_id) {
      db.prepare('UPDATE users SET google_id=?, avatar=?, email_verified=1 WHERE id=?').run(profile.id, avatar, user.id);
      user.google_id = profile.id;
      user.avatar = avatar;
    }

    return done(null, user);
  } catch (e) {
    console.error('[Google] Strategy error:', e);
    return done(e, null);
  }
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => {
  try {
    const user = db.prepare('SELECT * FROM users WHERE id=?').get(id);
    done(null, user || null);
  } catch (e) { done(e, null); }
});

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', (req, res, next) => {
  passport.authenticate('google', (err, user, info) => {
    if (err) {
      console.error('[Google] Callback error:', err && err.message);
      return res.redirect(FRONTEND_URL + '/?google_error=' + encodeURIComponent((err && err.message) || 'unknown'));
    }
    if (!user) {
      console.error('[Google] No user:', info);
      return res.redirect(FRONTEND_URL + '/?google_error=nouser');
    }
    try {
      const token = makeToken(user);
      res.redirect(FRONTEND_URL + '/?google_token=' + token);
    } catch (e) {
      console.error('[Google] Token error:', e);
      res.redirect(FRONTEND_URL + '/?google_error=token');
    }
  })(req, res, next);
});

// ============ AUTH ============
app.post('/api/register/send-code', authLimit, async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'Введите email' });
  if (!isValidEmail(email)) return res.status(400).json({ error: 'Разрешены только gmail.com, mail.com, mail.ru, email.com, yandex.ru' });
  const existing = db.prepare('SELECT id FROM users WHERE email=?').get(email.toLowerCase());
  if (existing) return res.status(409).json({ error: 'Этот email уже зарегистрирован' });

  const mxOk = await checkMxRecord(email);
  if (!mxOk) return res.status(400).json({ error: 'Такого почтового ящика не существует' });

  const code = String(Math.floor(100000 + Math.random() * 900000));
  db.prepare('INSERT OR REPLACE INTO verify_codes (email, code, expires_at) VALUES (?, ?, ?)').run(email.toLowerCase(), code, Date.now() + 10*60*1000);

  try {
    await sendEmail(email, 'Pongy AI — код подтверждения',
      '<div style="font-family:sans-serif;padding:32px 24px;background:#f7f7f9;border-radius:20px;max-width:480px;margin:0 auto">' +
      '<div style="text-align:center;margin-bottom:24px"><div style="width:64px;height:64px;margin:0 auto 16px;border-radius:20px;background:linear-gradient(135deg,#6366f1,#8b5cf6);color:#fff;font-size:32px;font-weight:700;line-height:64px">P</div><h2 style="color:#111;margin:0">Pongy AI</h2></div>' +
      '<p style="color:#666;font-size:14px">Ваш код подтверждения:</p>' +
      '<div style="font-size:34px;font-weight:bold;letter-spacing:8px;color:#6366f1;background:#fff;padding:20px;border-radius:14px;text-align:center;margin:16px 0;font-family:Consolas,monospace">' + code + '</div>' +
      '<p style="color:#999;font-size:12.5px">Код действует 10 минут.</p></div>'
    );
  } catch (e) { console.error('[send-code]', e.message); }
  res.json({ ok: true });
});

app.post('/api/register', authLimit, (req, res) => {
  const { email, password, code, deviceId } = req.body || {};
  if (!email || !password || password.length < 6) return res.status(400).json({ error: 'Пароль минимум 6 символов' });
  if (!isValidEmail(email)) return res.status(400).json({ error: 'Недопустимый домен email' });

  const vc = db.prepare('SELECT * FROM verify_codes WHERE email=?').get(email.toLowerCase());
  if (!vc) return res.status(400).json({ error: 'Сначала получите код подтверждения' });
  if (vc.expires_at < Date.now()) return res.status(400).json({ error: 'Код истёк' });
  if (vc.code !== String(code)) return res.status(400).json({ error: 'Неверный код' });

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

app.post('/api/login', authLimit, (req, res) => {
  const { email, password, deviceId } = req.body || {};
  const did = String(deviceId || '').slice(0, 64);
  if (did) {
    const att = db.prepare('SELECT * FROM login_attempts WHERE device_id=?').get(did);
    if (att && att.blocked_until > Date.now()) {
      const mins = Math.ceil((att.blocked_until - Date.now()) / 60000);
      return res.status(429).json({ error: 'Устройство заблокировано. Ещё ' + mins + ' мин.' });
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
        return res.status(429).json({ error: 'Слишком много попыток. Блокировка на 30 минут.' });
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
  try { await sendEmail(email, 'Pongy AI — сброс пароля', '<div style="font-family:sans-serif;padding:24px"><h2>Сброс пароля</h2><p>Код: <b style="font-size:24px;color:#6366f1">' + code + '</b></p></div>'); } catch(e){}
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
  db.prepare('UPDATE users SET password=? WHERE email=?').run(bcrypt.hashSync(newPassword, 10), email.toLowerCase());
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

app.post('/api/pay/create', auth, (req, res) => res.status(503).json({ error: 'В данный момент оплата недоступна. Попробуйте позже.' }));

// ============ AI PROXY ============
app.post('/api/chat', auth, chatLimit, async (req, res) => {
  const { messages, model } = req.body || {};
  if (!Array.isArray(messages) || !messages.length) return res.status(400).json({ error: 'messages required' });
  if (!OPENROUTER_KEY) return res.status(500).json({ error: 'Server not configured' });
  const user = db.prepare('SELECT subscription_until FROM users WHERE id = ?').get(req.user.id);
  const isPlus = user && user.subscription_until && user.subscription_until > Date.now();
  let lastUserText = '';
  for (let i = messages.length - 1; i >= 0; i--) if (messages[i].role === 'user') { lastUserText = messages[i].content || ''; break; }
  let modelsToTry = pickModelsForQuery(lastUserText, isPlus);
  if (model) modelsToTry = [model, ...modelsToTry.filter(m => m !== model)];
  let lastError = null, lastStatus = 500;
  for (const m of modelsToTry) {
    try {
      const r = await fetch('https://openrouter.ai/api/v1/chat/completions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + OPENROUTER_KEY, 'HTTP-Referer': FRONTEND_URL, 'X-Title': 'Pongy AI' },
        body: JSON.stringify({ model: m, stream: true, messages })
      });
      if (r.status === 401) return res.status(401).send(await r.text());
      if (!r.ok) { lastError = await r.text(); lastStatus = r.status; console.log('[Pongy] skip:', m, r.status); continue; }
      console.log('[Pongy] using:', m, isPlus ? '[Plus]' : '[Free]');
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
  res.status(lastStatus).send(lastError || 'All models unavailable');
});

app.get('/', (req, res) => res.sendFile('index.html', { root: '.' }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('✅ Pongy API on :' + PORT));
