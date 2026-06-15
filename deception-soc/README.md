# 🎭 Deception-Driven SOC (Security Operations Center)

A complete cybersecurity deception system that **detects** attacker activity, **redirects** them to fake systems (honeypots), **records** every action, uses **AI** to classify attacker behavior, and displays everything on a **real-time analyst dashboard**.

> Instead of blocking attackers — we **trap** them, **study** them, and **learn** from them.

---

## 🏗️ Architecture

```
┌─────────────┐     ┌──────────────────┐     ┌───────────────────┐
│   Attacker   │────▶│  Suricata IDS    │────▶│   Log Watcher     │
│  (Internet)  │     │  (Detection)     │     │  (EVE Parser)     │
└──────┬───────┘     └──────────────────┘     └────────┬──────────┘
       │                                                │
       │  iptables DNAT                          POST /threat/detected
       │  redirect                                      │
       │                                                ▼
       │             ┌──────────────────────────────────────────────┐
       │             │            ORCHESTRATOR (Brain)              │
       │             │  ┌─────────────┐  ┌──────────────────────┐  │
       │             │  │  Decision   │  │  Honeypot Manager    │  │
       └────────────▶│  │  Engine     │  │  (Docker SDK)        │  │
                     │  └─────────────┘  └──────────────────────┘  │
                     │  ┌─────────────────────────────────────────┐ │
                     │  │  Traffic Redirector (iptables)          │ │
                     │  └─────────────────────────────────────────┘ │
                     └──────────────────────┬───────────────────────┘
                                            │
                     ┌──────────────────────┼───────────────────────┐
                     │                      │                       │
              ┌──────▼──────┐    ┌──────────▼──────┐    ┌──────────▼──────┐
              │ SSH Honeypot│    │ HTTP Honeypot   │    │ FTP Honeypot   │
              │ (asyncssh)  │    │ (Flask)         │    │ (pyftpdlib)    │
              │ Fake Shell  │    │ Fake Portal     │    │ Bait Files     │
              └──────┬──────┘    └────────┬────────┘    └────────┬───────┘
                     │                    │                      │
                     └────────────┬───────┘──────────────────────┘
                                  │ POST session logs
                                  ▼
                     ┌────────────────────────┐     ┌────────────────┐
                     │   Central Logger       │────▶│ Elasticsearch  │
                     │   (FastAPI)            │     │ (Data Store)   │
                     └────────────┬───────────┘     └────────────────┘
                                  │
                     ┌────────────▼───────────┐
                     │   AI Module            │
                     │  • Feature Extraction  │
                     │  • K-Means Clustering  │
                     │  • Threat Scoring      │
                     └────────────┬───────────┘
                                  │
                     ┌────────────▼───────────┐
                     │   Dashboard            │
                     │  • React Frontend      │
                     │  • Real-time Updates   │
                     │  • Command Replay      │
                     └────────────────────────┘
```

---

## 🛠️ Technology Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Detection Engine | Suricata IDS | Network traffic analysis |
| Log Watcher | Python, watchdog, aiohttp | EVE log monitoring |
| Orchestrator | Python, FastAPI, Docker SDK | Central decision-making |
| SSH Honeypot | Python, asyncssh | Fake SSH server |
| HTTP Honeypot | Python, Flask | Fake web application |
| FTP Honeypot | Python, pyftpdlib | Fake FTP server |
| Central Logger | Python, FastAPI | Log aggregation |
| Data Store | Elasticsearch 8.11 | Session/command storage |
| AI Module | Python, scikit-learn | Attacker classification |
| Dashboard Backend | Python, FastAPI, aiohttp | API aggregation |
| Dashboard Frontend | React, Vite | Analyst interface |
| Infrastructure | Docker, Docker Compose | Container orchestration |
| Network | iptables | Traffic redirection |

---

## 📋 Prerequisites

- **Docker** >= 24.0
- **Docker Compose** >= 2.0
- **Linux** with iptables (for traffic redirection)
- **Python** >= 3.11 (for running tests)
- At least **4GB RAM** available for containers

---

## 🚀 Quick Start

```bash
# 1. Clone the repository
git clone <repository-url>
cd deception-soc

# 2. Build all images (including honeypots)
make build

# 3. Start the system
make up

# 4. Open the dashboard
# http://localhost:3000
```

### Verify Everything is Running

```bash
make status
```

### Run Attack Simulation

```bash
make test
# Or manually:
python tests/simulate_attacker.py localhost
```

---

## 📦 Component Descriptions

### 1. Detection Engine (Suricata + Log Watcher)
- Monitors network traffic with custom Suricata rules
- Detects: Nmap scans, SSH brute force, HTTP enumeration, SQL injection
- Forwards alerts to the Orchestrator in real-time

### 2. Orchestrator (The Brain)
- Receives threat alerts and makes TRAP/BLOCK/MONITOR decisions
- Deploys honeypot containers dynamically via Docker SDK
- Redirects attacker traffic via iptables DNAT rules
- Tracks all active deception sessions

### 3. Honeypots (Fake Systems)
- **SSH**: Full fake shell with command simulation, fake filesystem, bait credentials
- **HTTP**: Realistic login portal, admin dashboard, API endpoints with fake data
- **FTP**: Fake FTP server with bait files (backups, passwords, SSH keys)

### 4. Central Logger
- Receives session logs from all honeypots
- Stores in Elasticsearch with proper index mappings
- Provides query APIs for the dashboard

### 5. AI Module (20% of project)
- **Feature Extraction**: 15-dimensional behavioral vectors
- **K-Means Clustering**: 5 attacker types (Script Kiddie, Credential Stuffer, Advanced Recon, Data Thief, Malware Dropper)
- **Threat Scoring**: Rule-based 0-100 scoring with severity levels

### 6. Dashboard
- Real-time analyst interface with auto-refresh
- Live session monitoring with session selection
- AI threat scoring with visual indicators
- Command replay in terminal-style view
- Credential statistics

---

## 🔌 API Documentation

### Orchestrator (port 8000)
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/threat/detected` | Receive threat alert |
| GET | `/api/v1/sessions` | List all sessions |
| GET | `/api/v1/sessions/{id}` | Get session details |
| DELETE | `/api/v1/sessions/{ip}` | End a session |
| GET | `/api/v1/attackers` | List attacker profiles |
| GET | `/api/v1/health` | System health |

### Logger (port 9000)
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/session/log` | Store SSH/FTP session |
| POST | `/api/v1/http/log` | Store HTTP session |
| GET | `/api/v1/sessions` | Query sessions |
| GET | `/api/v1/sessions/{ip}` | Sessions by IP |
| GET | `/api/v1/commands/{ip}` | Commands by IP |
| GET | `/api/v1/credentials/top` | Top credentials |
| GET | `/api/v1/stats` | Total counts |

### AI Module (port 8500)
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/ai/classify` | Classify + score session |
| POST | `/api/v1/ai/train` | Train clustering model |
| POST | `/api/v1/ai/score` | Score session only |
| GET | `/api/v1/ai/status` | Model status |

### Dashboard Backend (port 3001)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/dashboard/overview` | Aggregated overview |
| GET | `/api/dashboard/sessions` | All sessions |
| GET | `/api/dashboard/session/{ip}` | Session detail + AI |
| GET | `/api/dashboard/credentials` | Top credentials |
| GET | `/api/dashboard/attackers` | Attacker profiles |

---

## 🧠 How the AI Works

### Feature Extraction (15 dimensions)
```
Session Duration | Commands Count | Unique Commands | Recon Ratio
Exploit Ratio | Persistence Ratio | Lateral Movement Ratio
Data Exfil Ratio | Avg Command Interval | Credentials Count
Unique Usernames | Unique Passwords | Files Accessed
Sensitive Files Ratio | Download Attempts
```

### K-Means Clustering (5 clusters)
| Cluster | Label | Behavior Pattern |
|---------|-------|-----------------|
| 0 | Script Kiddie | Automated tools, minimal interaction |
| 1 | Credential Stuffer | Focused on brute-forcing credentials |
| 2 | Advanced Recon | Careful enumeration, methodical approach |
| 3 | Data Thief | Targets sensitive files and databases |
| 4 | Malware Dropper | Downloads and deploys payloads |

### Threat Scoring (0-100)
| Factor | Max Points | Criteria |
|--------|-----------|----------|
| Duration | 10 | >10min: +10, >2min: +5 |
| Dangerous Commands | 25 | +5 per dangerous command |
| Credential Attempts | 15 | >20: +15, >5: +8 |
| Sensitive Files | 20 | +5 per sensitive file |
| Lateral Movement | 15 | +5 per lateral command |
| Data Exfiltration | 15 | +5 per exfil indicator |

---

## 🔒 Security Considerations

1. **All credentials in honeypots are FAKE** — they contain "FAKE" in values
2. **Honeypot network is ISOLATED** — `internal=true` Docker network, no internet access
3. **Resource limits** — Honeypots are capped at 256MB RAM, 50% CPU
4. **No real secrets** — No production credentials anywhere in the codebase
5. **Containers run with `no-new-privileges`** security option
6. **Sessions auto-expire** after 1 hour maximum
7. **Docker socket access** — Only the orchestrator has Docker API access

---

## 📁 Project Structure

```
deception-soc/
├── docker-compose.yml          # Full deployment configuration
├── .env                        # Environment variables
├── Makefile                    # Build/deploy/test commands
├── README.md                   # This file
├── detection-engine/           # Suricata IDS + Log Watcher
├── orchestrator/               # Central brain (FastAPI)
├── honeypots/
│   ├── ssh-honeypot/           # Fake SSH server
│   ├── http-honeypot/          # Fake web application
│   └── ftp-honeypot/           # Fake FTP server
├── logger/                     # Central logging (Elasticsearch)
├── ai-module/                  # ML clustering + threat scoring
├── dashboard/
│   ├── backend/                # API aggregation proxy
│   └── frontend/               # React analyst dashboard
├── network/                    # iptables rules + topology
└── tests/                      # Unit tests + attack simulator
```

---

## 📜 License

This project is for **educational and research purposes only**. Do not deploy against systems you do not own or have explicit authorization to test.

MIT License — See LICENSE file for details.
