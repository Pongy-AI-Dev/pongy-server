# pongy-server
Pongy AI — это новый персональный ИИ-помощник на базе DeepSeek V.4.1 и собственной модели Pongy AI V1.1.
# 🐣 Pongy AI

**Kind personal AI assistant — similar to Verity, yet friendlier.**

Pongy AI is a modern multi-user web application that provides intelligent conversational assistance in 5 languages. It runs as a full-stack solution with a Node.js backend and a lightweight frontend — no build tools required.

🌐 **Live:** [pongy.chat](https://pongy.chat)

---

## ✨ Features

### 💬 Chat experience
- **Real-time streaming** responses — watch the AI type letter by letter
- **Reasoning mode** — extended thinking for complex tasks
- **Search mode** — up-to-date knowledge with source citations
- **Multi-agent system** — Low / Standart / Extra Smart tiers
- **Thinking levels** — Extra / High / Middle / Low
- **Voice input** — Web Speech API in English, Russian, Spanish, German, French
- **Markdown support** — bold, italic, code blocks, lists, links
- **Message actions** — copy, edit, refine, report
- **Session history** — chats saved with timestamps and pinning
- **Chat search** — instant filtering by title

### 🌐 Internationalization
- 5 languages: 🇬🇧 English · 🇷🇺 Русский · 🇪🇸 Español · 🇩🇪 Deutsch · 🇫🇷 Français
- Auto-detection of voice recognition language
- Localized currency and pricing per region

### 🎨 Design
- **Two themes** — light and dark, remembered across sessions
- **Fully responsive** — desktop, tablet, mobile
- **Smooth animations** — thinking orb, streaming cursor, badge pulses
- **Modern UI** — clean typography, rounded corners, subtle shadows
- **Logo** — custom teal-to-violet gradient P

### 🔒 Security
- **CSP (Content Security Policy)** — blocks malicious scripts
- **XSS protection** — all user input escaped
- **JWT authentication** — 30-day tokens
- **bcrypt password hashing** — 10 rounds
- **Rate limiting** — protection from abuse
- **No third-party trackers** — no analytics, no ads
- **API keys stay server-side** — users never see them

### 💾 Multi-user backend
- **Email/password registration**
- **Chats synced across devices**
- **Pinned chats preserved**
- **Per-user isolation** — you only see your own data
- **SQLite** — lightweight, zero-config database

---

## 🏗️ Architecture

┌──────────────┐ HTTPS ┌──────────────┐ HTTPS ┌──────────────┐
│ Frontend │ ──────────▶ │ Backend │ ──────────▶ │ OpenRouter │
│ (Vercel) │ │ (Railway) │ │ (DeepSeek) │
└──────────────┘ └──────┬───────┘ └──────────────┘
│
▼
┌──────────────┐
│ SQLite │
│ users/chats │
└──────────────┘


**Frontend** — single `index.html` (vanilla JS, no build step)
**Backend** — Node.js + Express
**Database** — SQLite (WAL mode)
**AI** — OpenRouter (DeepSeek V3 / R1 free tiers)

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Frontend | Vanilla JavaScript, CSS3, SVG |
| Backend | Node.js 20+, Express 4 |
| Database | better-sqlite3 |
| Auth | JWT + bcryptjs |
| AI | OpenRouter API (streaming) |
| Rate limit | express-rate-limit |
| Deploy | Vercel (front) + Railway (back) |

---

## 🚀 Quick Start

### Prerequisites
- Node.js 20+
- OpenRouter API key — [openrouter.ai/keys](https://openrouter.ai/keys)

### 1. Clone
```bash
git clone https://github.com/YOUR_USERNAME/pongy-server.git
cd pongy-server

For INSTALL:

bash
npm install
_______________

BETA V. 0.1 - NOT FULL...
