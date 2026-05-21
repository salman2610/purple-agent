<div align="center">

# 🟣 Purple Agent

### AI SRE Agent — Monitor your servers. Understand what's wrong. Fix it faster.

[![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18+-61DAFB?style=flat-square&logo=react)](https://react.dev)
[![License](https://img.shields.io/badge/License-MIT-purple?style=flat-square)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=flat-square&logo=docker)](docker-compose.yml)

**Purple Agent is an AI-powered server monitoring agent that doesn't just show you graphs — it tells you exactly what's wrong and why.**

[🚀 Quick Start](#-quick-start) · [✨ Features](#-features) · [📸 Screenshots](#-screenshots) · [🧠 How It Works](#-how-it-works) · [🤝 Contributing](#-contributing)

</div>

---

## 🧠 What Makes This Different

Most monitoring tools show you a spike in CPU and leave you to figure it out. Purple Agent's AI engine analyzes your system in real time, correlates events across metrics, and tells you in plain English what's happening — before it becomes an outage.

> *"It's like having a junior sysadmin that never sleeps."*

---

## ✨ Features

### 🤖 AI-Powered Intelligence
- **Smart Insights** — real-time analysis of CPU, memory, disk, and network patterns
- **Predictive Alerts** — predicts CPU peaks and memory pressure before they hit
- **Plain-English Diagnostics** — no more staring at graphs, get actionable recommendations
- **AI Assistant** — chat interface to ask questions about your system

### 📊 Real-Time Monitoring
- CPU, memory, disk usage with live charts
- Running process table with per-process CPU and memory breakdown
- Network activity (bytes sent/received) with historical view
- WebSocket-powered live dashboard — zero page refresh needed

### 🔐 Security & Access Control
- JWT-based authentication with role-based access (admin / user)
- Visitor log tracking — see every IP that hits your backend
- User activity monitor — full audit trail of logins and actions
- Suspicious request detection

### 🚨 Alerts & Incidents
- Configurable alert rules (CPU > 80%, Memory > 90%, Disk > 85%)
- Severity levels: LOW / MEDIUM / HIGH / CRITICAL
- Incident tracking and history
- Active/inactive rule toggling

### 🎛️ Dashboard
- Multiple layout modes (Default, Analytics View, Compact)
- Global server distribution map
- System metrics pie chart
- Business mode / focus mode toggle
- Fully customizable via Dashboard Layouts

### 🧩 Agent Architecture
- Lightweight Python agent deployable as a `systemd` service
- Monitors: system metrics, log files, network connections, file integrity
- Secure JWT-authenticated communication to backend
- Designed for multi-server deployments

---

## 📸 Screenshots

> Dashboard overview with AI Smart Insights and real-time WebSocket feed

| Dashboard | Alerts | Visitor Logs |
|---|---|---|
| AI insights, process table, network chart | Alert rules with severity levels | Real-time IP tracking |

---

## 🚀 Quick Start

### Option 1 — Docker (Recommended)

```bash
git clone https://github.com/salman2610/purple-agent.git
cd purple-agent
docker-compose up -d
```

Frontend: http://localhost:5173  
Backend API: http://localhost:8000  
Default login: `admin` / `admin` *(change immediately)*

---

### Option 2 — Manual Setup

**Backend**
```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

**Frontend**
```bash
cd frontend
npm install
npm run dev
```

**Agent** (on the server you want to monitor)
```bash
cd agent
pip install -r requirements.txt
# Edit config/config.json with your backend URL and token
python -m agent.main
```

---

## ⚙️ Agent Configuration

Edit `config/config.json`:

```json
{
  "server_url": "https://your-backend.example.com/api/agent",
  "agent_id": "server-001",
  "auth_token": "your-jwt-token-here",
  "scan_interval": 60,
  "log_paths": ["/var/log/auth.log", "/var/log/syslog"],
  "integrity_dirs": ["/etc", "/var/www", "/usr/bin"]
}
```

---

## 🧩 Deploy Agent as a Service

```bash
sudo nano /etc/systemd/system/purple-agent.service
```

```ini
[Unit]
Description=Purple Agent Monitoring Service
After=network.target

[Service]
User=root
WorkingDirectory=/path/to/purple-agent
ExecStart=/path/to/purple-agent/venv/bin/python -m agent.main
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable purple-agent
sudo systemctl start purple-agent
sudo systemctl status purple-agent
```

---

## 🏗️ Architecture

```
┌─────────────────┐     WebSocket/REST      ┌──────────────────┐
│   React Frontend │ ◄──────────────────────► │  FastAPI Backend  │
│   (Vite + JS)   │                          │  (Python 3.8+)   │
└─────────────────┘                          └────────┬─────────┘
                                                      │
                                             ┌────────▼─────────┐
                                             │   PostgreSQL DB   │
                                             └────────┬─────────┘
                                                      │
                                             ┌────────▼─────────┐
                                             │  Purple Agent(s)  │
                                             │  (systemd service)│
                                             │  per monitored    │
                                             │  server           │
                                             └──────────────────┘
```

**Stack:** React 18 · FastAPI · PostgreSQL · WebSockets · JWT · PyTorch (LSTM) · Docker

---

## 🗺️ Roadmap

- [ ] One-line agent install script (`curl | bash`)
- [ ] Email & SMS alerts
- [ ] Windows agent support
- [ ] Docker container monitoring
- [ ] Multi-tenant / team support
- [ ] Mobile-responsive UI
- [ ] Stripe billing for hosted version
- [ ] Kubernetes pod monitoring

---

## 🤝 Contributing

Contributions are welcome! Please open an issue before submitting a PR so we can discuss the change.

```bash
git checkout -b feature/your-feature
git commit -m "feat: add your feature"
git push origin feature/your-feature
# Open a Pull Request
```

---

## 🩺 Troubleshooting

**Agent not connecting?**
- Check `config/config.json` — verify `server_url` and `auth_token`
- Ensure backend is reachable from the agent server
- Check logs: `journalctl -u purple-agent -f`

**CORS errors in browser?**
- Add your frontend origin to `ALLOWED_ORIGINS` in `backend/main.py`

**Database warnings?**
- Run `ALTER DATABASE purpleteam_db REFRESH COLLATION VERSION;` in psql

---

## 📜 License

MIT License — use it, fork it, build on it.

---

<div align="center">

Built with 💜 by [salman2610](https://github.com/salman2610)

⭐ **Star this repo if you find it useful** — it helps more people discover it!

</div>
