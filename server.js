import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { DatabaseSync } from 'node:sqlite';
import rateLimit from 'express-rate-limit';
import 'dotenv/config';

const app = express();
app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(express.static('.'));

const db = new DatabaseSync('pongy.db');
db.exec('PRAGMA journal_mode = WAL;');
db.exec('PRAGMA foreign_keys = ON;');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    nickname TEXT DEFAULT '',
    subscription_until INTEGER DEFAULT 0,
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
  CREATE INDEX IF NOT EXISTS idx_chats_user ON chats(user_id);
`);

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const OPENROUTER_KEY = process.env.OPENROUTER_KEY || '';

const authLimit = rateLimit({ windowMs: 15*60*1000, max: 20, message: { error: 'Too many attempts' } });
const chatLimit = rateLimit({ windowMs: 60*1000, max: 20, message: { error: 'Rate limit exceeded' } });
const globalLimit = rateLimit({ windowMs: 60*1000, max: 120 });

app.use(globalLimit);

function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'no token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    res.status(401).json({ error: 'invalid token' });
  }
}

function makeToken(user) {
  return jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
}

app.post('/api/register', authLimit, (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password || password.length < 6) {
    return res.status(400).json({ error: 'Email and password (min 6) required' });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Invalid email format' });
  }
  try {
    const hash = bcrypt.hashSync(password, 10);
    const info = db.prepare('INSERT INTO users (email, password) VALUES (?, ?)').run(email.toLowerCase(), hash);
    const user = { id: info.lastInsertRowid, email: email.toLowerCase() };
    res.json({ token: makeToken(user), user });
  } catch (e) {
    if (String(e).includes('UNIQUE')) return res.status(409).json({ error: 'Email already registered' });
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/login', authLimit, (req, res) => {
  const { email, password } = req.body || {};
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get((email || '').toLowerCase());
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  res.json({
    token: makeToken(user),
    user: {
      id: user.id,
      email: user.email,
      nickname: user.nickname,
      subscription_until: user.subscription_until
    }
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
  if (exists) {
    db.prepare('UPDATE chats SET title=?, messages=?, pinned=?, updated_at=? WHERE id=? AND user_id=?')
      .run(title || '', JSON.stringify(messages), pinned ? 1 : 0, upd, id, req.user.id);
  } else {
    db.prepare('INSERT INTO chats (id, user_id, title, messages, updated_at, pinned) VALUES (?,?,?,?,?,?)')
      .run(id, req.user.id, title || '', JSON.stringify(messages), upd, pinned ? 1 : 0);
  }
  res.json({ ok: true });
});

app.delete('/api/chats/:id', auth, (req, res) => {
  db.prepare('DELETE FROM chats WHERE id=? AND user_id=?').run(req.params.id, req.user.id);
  res.json({ ok: true });
});

app.post('/api/chat', auth, chatLimit, async (req, res) => {
  const { messages, model } = req.body || {};
  if (!Array.isArray(messages) || !messages.length) {
    return res.status(400).json({ error: 'messages required' });
  }
  if (!OPENROUTER_KEY) return res.status(500).json({ error: 'Server not configured' });

  try {
    const r = await fetch('https://openrouter.ai/api/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${OPENROUTER_KEY}`,
        'HTTP-Referer': 'https://pongy.chat',
        'X-Title': 'Pongy AI'
      },
      body: JSON.stringify({
        model: model || 'deepseek/deepseek-chat-v3-0324:free',
        stream: true,
        messages
      })
    });

    if (!r.ok) {
      const txt = await r.text();
      return res.status(r.status).send(txt);
    }

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');

    const reader = r.body.getReader();
    const dec = new TextDecoder();
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      res.write(dec.decode(value, { stream: true }));
    }
    res.end();
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('✅ Pongy API listening on port ' + PORT));
