# 🛡️ CyberSentinel — AI-Powered SOC Automation Platform

[![Live Demo](https://img.shields.io/badge/Live-Demo-brightgreen)](https://cybersentinel-lbnkgtclm-yashchavan24s-projects.vercel.app)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/Node.js-20+-green.svg)](https://nodejs.org)

**End-to-end cybersecurity automation**: ingest logs/emails/alerts → AI triage (MITRE ATT&CK-mapped rules + statistical heuristics + optional LLM) → severity scoring → automatic dispatch to receivers → full audit trail.

![Dashboard Screenshot](docs/dashboard.png)

---

## 🌟 Live Demo

**Try it now**: https://cybersentinel-lbnkgtclm-yashchavan24s-projects.vercel.app

**Demo credentials**: `analyst` / `Sentinel@2026`

---

## ✨ Features

### 🤖 Hybrid AI Threat Engine
- **14 detection rules** mapped to MITRE ATT&CK techniques (SQLi, XSS, C2 beaconing, phishing, brute-force, etc.)
- **Statistical heuristics**: Shannon entropy analysis, IOC extraction (IPs, domains, URLs, emails, MD5/SHA256 hashes)
- **Pattern recognition**: brand impersonation, high-risk TLDs, process masquerading, Office macro chains
- **Optional LLM enrichment**: OpenAI GPT-4o-mini integration for narrative analysis (set `OPENAI_API_KEY` in `.env`)

### 🔁 Full Automation Loop
- **Auto-analyze on ingest**: every new entry is automatically triaged by the AI engine
- **Severity scoring**: 0–100 threat score with Critical/High/Medium/Low classification
- **Smart dispatch**: High/Critical alerts automatically notify configured receivers (email/SMS/webhook)
- **Status workflow**: new → triaged → investigating → mitigated → closed

### 📊 Real-Time Dashboard
- Severity distribution donut chart
- Event statistics (total, critical, high, open, resolved)
- Events by type breakdown
- Recent events feed with severity badges
- Alert dispatch history

### 📡 Receiver Management
- **Multi-channel support**: email, SMS, webhook (Slack/Discord/Teams)
- **AES-256-GCM encryption**: phone numbers encrypted at rest
- **Critical-only routing**: receivers can opt-in to Critical alerts only
- **Live webhook delivery**: real HTTP POST to your Slack/Discord webhooks
- **Test notifications**: verify receiver connectivity with one click

### 🧾 Audit Trail
- Immutable log of all authentication events (login success/failure, registration)
- Complete mutation tracking (entry create/update/delete, receiver changes, AI analysis runs)
- Timestamp, username, action, detail, and IP address for every event
- Non-repudiation by design

---

## 🔐 Security Controls

| Control | Implementation |
|---------|----------------|
| **Authentication** | JWT tokens (8h expiry), bcrypt cost-12 password hashing |
| **Brute-force protection** | Account lockout after 5 failed attempts (15 min cooldown) + rate limiting (10 login attempts per 15 min per IP) |
| **Security headers** | Helmet middleware (X-Content-Type-Options, X-Frame-Options, etc.) |
| **Input validation** | Zod schema validation on all endpoints, parameterized SQL queries |
| **Data protection** | AES-256-GCM field-level encryption for sensitive receiver data (phone numbers) |
| **CORS** | Smart origin allowlist (localhost + Vercel/Netlify/Render/ngrok preview URLs) |
| **Rate limiting** | Global API rate limit (500 requests per 15 min per IP) |
| **Accountability** | Immutable audit log capturing all auth events and data mutations |

---

## 🏗️ Architecture

### System Overview


### Request Flow: AI Analysis & Auto-Dispatch


### Database Schema


---

## 🚀 Quick Start (Local Development)

### Prerequisites
- **Node.js 20+** (download from https://nodejs.org)
- **Git** (optional, for version control)

### Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/cybersentinel.git
cd cybersentinel

# Install all dependencies (backend + frontend)
npm run install-all

# Configure environment variables
cd backend
cp .env.example .env
# Edit .env and set JWT_SECRET + ENCRYPTION_KEY:
# node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"

# Start both servers
cd ..
npm run dev
cybersentinel/
├── backend/
│   ├── server.js          # Express app + CORS + rate limiting
│   ├── db.js              # SQLite schema + seed data + sql.js wrapper
│   ├── ai-engine.js       # ⭐ Hybrid AI threat engine
│   ├── auth.js            # JWT auth + bcrypt + account lockout
│   ├── routes.js          # API endpoints (entries, receivers, dashboard)
│   ├── notify.js          # Alert dispatch (webhook/email/SMS)
│   ├── security.js        # AES-256-GCM encryption utilities
│   └── .env               # Environment variables (not committed)
├── frontend/
│   ├── src/
│   │   ├── App.jsx        # Router + auth context + layout
│   │   ├── api.js         # Fetch wrapper with JWT handling
│   │   ├── components.jsx # Reusable UI components (Badge, Card, etc.)
│   │   ├── styles.css     # Dark cyber theme
│   │   └── pages/
│   │       ├── Login.jsx
│   │       ├── Dashboard.jsx
│   │       ├── Analyzer.jsx
│   │       ├── Entries.jsx
│   │       ├── Receivers.jsx
│   │       └── Audit.jsx
│   ├── vite.config.js
│   └── index.html
├── package.json           # Root scripts (install-all, dev)
└── README.md              # This file
From: billing@micr0soft-secure.tk
Subject: URGENT: Your account will be suspended in 24 hours

Dear customer, we detected unusual activity on your account.
Click here to verify your password immediately: http://login-micr0soft-verify.tk/account
Failure to confirm will result in permanent deactivation.

203.0.113.42 - - "GET /products?id=41' OR '1'='1 HTTP/1.1" 200
203.0.113.42 - - "GET /products?id=41 UNION SELECT username, password FROM users-- HTTP/1.1" 200
User-Agent: sqlmap/1.8.2

EDR ALERT [WIN-DC01]: process svch0st.exe (PID 5521) spawned from winword.exe macro
SHA256: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
Network: beaconing to update-cdn-metrics.ru every 30 seconds (C2 callback suspected)

INFO 2026-08-14 09:15:22 user=alice action=login status=success src=10.0.4.55 session=normal

Authentication
POST /api/auth/register — Create account
POST /api/auth/login — Get JWT token
GET /api/auth/me — Get current user (requires Bearer token)
Entries
GET /api/entries?severity=&status=&q= — List entries with filters
POST /api/entries — Create entry (auto-analyzes by default)
PATCH /api/entries/:id — Update entry (title, status, source)
DELETE /api/entries/:id — Delete entry
POST /api/entries/:id/analyze — Re-run AI analysis
POST /api/analyze — Quick analyze without saving
Receivers
GET /api/receivers — List all receivers
POST /api/receivers — Create receiver
PATCH /api/receivers/:id — Update receiver (active, critical_only)
DELETE /api/receivers/:id — Delete receiver
POST /api/receivers/:id/test — Send test notification
Dashboard & Audit
GET /api/dashboard — Stats, severity distribution, recent events
GET /api/audit — Audit log (last 100 events)
GET /api/health — Backend health check
🛣️ Roadmap
Real email delivery (nodemailer + SMTP)
Real SMS delivery (Twilio API)
VirusTotal integration for IOC reputation lookup
SIEM connectors (Splunk HEC, Elastic, Datadog)
PostgreSQL migration for production persistence
Role-based access control (RBAC)
Scheduled re-scanning of old entries
Export reports (PDF/CSV)
Docker containerization
Kubernetes Helm chart
🤝 Contributing
Contributions are welcome! Please follow these steps:
Fork the repository
Create a feature branch (git checkout -b feature/amazing-feature)
Commit your changes (git commit -m 'Add amazing feature')
Push to the branch (git push origin feature/amazing-feature)
Open a Pull Request
📄 License
This project is licensed under the MIT License — see the LICENSE file for details.
👤 Author
Yash Chavan
LinkedIn: Your LinkedIn Profile
GitHub: @yashchavan24
🙏 Acknowledgments
MITRE ATT&CK® — Detection rule mappings based on the MITRE ATT&CK framework
sql.js — Pure JavaScript SQLite implementation
React + Vite — Modern frontend tooling
Render + Vercel — Free cloud hosting
⚠️ Disclaimer
This is a portfolio demonstration project showcasing full-stack development and cybersecurity automation concepts. It is not intended for production use in a real SOC environment. For production deployment, consider:
Migrating from SQLite to PostgreSQL
Adding comprehensive logging and monitoring (Datadog, New Relic)
Implementing proper secret management (HashiCorp Vault, AWS Secrets Manager)
Adding comprehensive test coverage (Jest, Cypress)
Conducting a full security audit and penetration test
Built with ❤️ by Yash Chavan | 2026