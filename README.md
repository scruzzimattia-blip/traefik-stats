# ⚡ Traefik God Mode Monitor

Security-focused traffic analytics system for Traefik with real-time attack detection, CrowdSec integration, and interactive dashboard.

## 🏗️ Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Traefik   │────▶│   Worker    │────▶│  PostgreSQL │
│  AccessLog │     │ (Parser)    │     │     DB      │
└─────────────┘     └─────────────┘     └─────────────┘
                           │                    │
                           ▼                    ▼
                    ┌─────────────┐     ┌─────────────┐
                    │  CrowdSec  │     │  Streamlit  │
                    │   (Ban)     │     │  Dashboard  │
                    └─────────────┘     └─────────────┘
```

## 🚀 Features

- **Real-time Log Processing** - Parses Traefik access logs with file watcher
- **Attack Detection** - Pattern matching for 30+ attack vectors (SQLi, LFI, path traversal, etc.)
- **Geo Blocking** - Block traffic by country
- **Rate Limiting** - Soft-ban IPs with >20 errors/60s (Redis-backed)
- **CrowdSec Integration** - Auto-ban malicious IPs via LAPI
- **Threat Scoring** - 0-100 risk score per IP based on behavior
- **Login Attempt Tracking** - Detect brute-force on /wp-login, /admin, etc.
- **Interactive Dashboard** - 6 tabs: Dashboard, Security, Traffic, Investigator, Live, System

## 📋 Requirements

- Docker & Docker Compose
- PostgreSQL 15+
- Redis (optional, for rate limiting)
- CrowdSec LAPI (optional)

## 🛠️ Setup

```bash
# Clone and start
cp .env.example .env
# Edit .env with your secrets

docker-compose up -d
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection | `postgresql://user:password@db:5432/traefik_stats` |
| `CROWDSEC_LAPI_URL` | CrowdSec API URL | `http://crowdsec:8080` |
| `CROWDSEC_LAPI_KEY` | CrowdSec API key | - |
| `CROWDSEC_MACHINE_PASSWORD` | CrowdSec machine password | - |
| `ABUSEIPDB_API_KEY` | AbuseIPDB for IP reputation | - |
| `REDIS_URL` | Redis for rate limiting | - |
| `RETENTION_DAYS` | Log retention | `30` |
| `IGNORED_IPS` | IPs to skip (comma-separated) | - |
| `ATTACK_PATTERNS` | Custom patterns (comma-separated) | - |
| `LOG_FORMAT` | `json` for structured logging | - |
| `DISCORD_WEBHOOK` | Discord notification URL | - |

## 📊 Dashboard Tabs

1. **📊 Dashboard** - Overview, metrics, timeline, quick insights
2. **🔒 Security** - Attack stats, geography, paths, CrowdSec management
3. **🌊 Traffic** - Sankey flow, endpoints, bandwidth, browsers
4. **🕵️ Investigator** - IP lookup, CrowdSec status, AbuseIPDB
5. **📺 Live Stream** - Latest 200 requests
6. **🏥 System** - DB stats, threat leaders, login attempts, geo blocking

## 🧪 Testing

```bash
pytest tests/ -v
```

## 🔧 Development

```bash
# Install dependencies
pip install -r requirements-app.txt
pip install -r requirements-worker.txt

# Run tests
pytest tests/ -v

# Run locally
docker-compose up
```

## 📁 Project Structure

```
├── app.py              # Streamlit dashboard
├── worker.py           # Log parser & attack detector
├── models.py           # SQLAlchemy models
├── crowdsec.py         # CrowdSec LAPI client
├── data_service.py     # Dashboard data functions
├── docker-compose.yml  # Full stack
├── Dockerfile          # Streamlit app
├── Dockerfile.worker   # Worker container
└── tests/              # Test suite
```

## 📦 CI/CD

GitHub Actions workflow (`.gitea/workflows/ci.yaml`):
- Runs tests on push/PR
- Builds & pushes Docker images to Gitea container registry on main

## ⚠️ Notes

- Worker reads from `/app/logs/access.log` (mount from Traefik)
- GeoIP databases required at `/app/geoip/city.mmdb` and `/app/geoip/asn.mmdb`
- Rate limiting uses Redis (primary) or falls back to DB
- All new columns auto-migrate on startup

## 📜 License

MIT
