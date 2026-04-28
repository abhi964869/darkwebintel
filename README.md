# Dark Web Threat Intelligence Tool
> A full-stack cybersecurity platform for monitoring, ingesting, and analysing simulated dark web threat data.

---

## Tech Stack
| Layer    | Technology                              |
|----------|-----------------------------------------|
| Backend  | Python 3.11, Flask, Flask-JWT-Extended  |
| Database | MongoDB 7 (Atlas or local)              |
| Frontend | React 18, Vite, Tailwind CSS, Recharts  |
| Ingestor | Python (simulated / Pastebin / Tor)     |

---

## Project Structure
```
dark-web-intel/
├── backend/
│   ├── app.py                   # Flask app factory
│   ├── models.py                # MongoDB schemas
│   ├── ingestor.py              # Threat data ingestion
│   ├── routes/
│   │   ├── auth_routes.py       # Register / Login / JWT
│   │   ├── threat_routes.py     # CRUD + full-text search
│   │   ├── alert_routes.py      # Alerts + keyword management
│   │   └── dashboard_routes.py  # Aggregation stats
│   ├── requirements.txt
│   └── .env.example
└── frontend/
    └── src/
        ├── App.jsx
        ├── api/index.js          # Axios client + interceptors
        └── components/
            ├── Dashboard.jsx
            ├── ThreatList.jsx
            ├── AlertsPanel.jsx
            ├── Keywords.jsx
            ├── Login.jsx
            └── Sidebar.jsx
```

---

## Team Division

### Member 1 — Backend & Security
**Files:** `app.py`, `models.py`, `routes/auth_routes.py`, `routes/threat_routes.py`
- Flask app factory, JWT auth, bcrypt hashing
- Threat CRUD API + full-text search
- MongoDB index design
- Input validation & rate limiting

### Member 2 — Data Ingestion & Intelligence
**Files:** `ingestor.py`, `routes/alert_routes.py`, `routes/dashboard_routes.py`
- Simulated threat generator (realistic data pools)
- Pastebin live scraper
- Keyword matching engine → alert creation
- MongoDB aggregation pipelines for dashboard stats

### Member 3 — Frontend
**Files:** `frontend/src/` (all components + api/)
- React dashboard with stat cards, trend chart, category breakdown
- Threat feed with search, filter, pagination
- Alert management (ack / dismiss)
- Keyword / IOC monitor panel

---

## Setup Instructions

### 1. Prerequisites
```bash
# Install MongoDB (local)
# macOS:  brew tap mongodb/brew && brew install mongodb-community
# Ubuntu: see https://www.mongodb.com/docs/manual/installation/

# Python 3.11+
python --version

# Node 18+
node --version
```

### 2. Backend
```bash
cd backend
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env            # Edit with your values
python app.py                   # Starts at http://localhost:5000
```

### 3. Seed the database
```bash
# Generate 100 simulated threats (no internet needed)
python ingestor.py --mode simulated --count 100

# OR scrape Pastebin public pastes (requires internet)
python ingestor.py --mode pastebin --count 20
```

### 4. Frontend
```bash
cd frontend
npm install
cp .env.example .env.local       # Set VITE_API_URL=http://localhost:5000/api
npm run dev                      # Starts at http://localhost:5173
```

---

## API Reference

| Method | Endpoint                      | Auth | Description               |
|--------|-------------------------------|------|---------------------------|
| POST   | /api/auth/register            | ✗    | Create account            |
| POST   | /api/auth/login               | ✗    | Get JWT token             |
| GET    | /api/threats                  | JWT  | List threats (paginated)  |
| GET    | /api/threats/search?q=…       | JWT  | Full-text search          |
| POST   | /api/threats                  | JWT  | Add threat manually       |
| GET    | /api/alerts                   | JWT  | List your alerts          |
| PATCH  | /api/alerts/<id>/ack          | JWT  | Acknowledge alert         |
| GET    | /api/alerts/keywords          | JWT  | List monitored keywords   |
| POST   | /api/alerts/keywords          | JWT  | Add keyword / IOC         |
| GET    | /api/dashboard/stats          | JWT  | Summary counts            |
| GET    | /api/dashboard/trends         | JWT  | Daily threat trends       |
| GET    | /api/dashboard/categories     | JWT  | Threats by category       |
| GET    | /api/dashboard/top-iocs       | JWT  | Top IOC frequency         |

---

## Development Roadmap

### Phase 1 — Setup (Days 1–2)
- [ ] Member 1: MongoDB up, Flask app running, auth endpoints tested
- [ ] Member 2: Ingestor running, 100 simulated threats in DB
- [ ] Member 3: React + Vite + Tailwind scaffolded, API client wired

### Phase 2 — Core Features (Days 3–6)
- [ ] Member 1: Threat CRUD + search endpoints complete
- [ ] Member 2: Keyword matcher + alert generation + dashboard APIs
- [ ] Member 3: Dashboard charts, threat table, alerts panel

### Phase 3 — Integration & Polish (Days 7–9)
- [ ] End-to-end testing: register → add keyword → ingest → see alert
- [ ] Error handling, loading states, form validation on frontend
- [ ] Member 2: Schedule ingestor (APScheduler) to run every 5 min

### Phase 4 — Testing & Docs (Day 10)
- [ ] Backend unit tests (pytest)
- [ ] Frontend manual test plan
- [ ] README, demo video / screenshots

---

## Security Best Practices Implemented

| Practice                  | Where                                        |
|---------------------------|----------------------------------------------|
| bcrypt password hashing   | `auth_routes.py` — `hash_password()`        |
| JWT with expiry           | `app.py` — `JWT_ACCESS_TOKEN_EXPIRES`       |
| Input validation          | All route handlers — length, format checks  |
| MongoDB injection safe    | PyMongo uses parameterised queries by default|
| CORS restricted origin    | `app.py` — `ALLOWED_ORIGIN` env var         |
| Secrets in `.env`         | `.env.example` — never commit `.env`        |
| Admin-only delete         | `threat_routes.py` — role check             |
| Audit logging model       | `models.py` — `new_audit_log()`             |
| Content length limit      | `app.py` — `MAX_CONTENT_LENGTH = 2 MB`      |
| Vague auth error messages | `auth_routes.py` — "Invalid credentials"    |

---

## Suggested Tools & APIs

| Tool                  | Purpose                         | URL                             |
|-----------------------|---------------------------------|---------------------------------|
| Pastebin Scrape API   | Public paste monitoring         | scrape.pastebin.com             |
| HaveIBeenPwned API    | Check emails in breach DBs      | haveibeenpwned.com/API          |
| AbuseIPDB API         | IP reputation lookup            | abuseipdb.com/api               |
| VirusTotal API        | Hash / URL / IP analysis        | virustotal.com/api              |
| Shodan API            | Exposed service lookup          | shodan.io                       |
| IntelX API            | Dark web index search           | intelx.io                       |
| Tor + Stem            | Real .onion scraping (advanced) | stem.torproject.org             |

---

## Testing Strategy

### Backend (pytest)
```bash
cd backend
pytest tests/ -v
```
Test cases to implement in `tests/`:
- `test_auth.py` — register, login, duplicate email, bad password
- `test_threats.py` — create, list, filter, search, delete (admin check)
- `test_alerts.py` — keyword add, match triggers alert, ack/dismiss
- `test_ingestor.py` — `generate_simulated_threat()` returns valid schema
- `test_dashboard.py` — stats endpoint returns expected keys

### Frontend (manual checklist)
- [ ] Login with wrong password shows error
- [ ] Dashboard stat cards load without crash
- [ ] Threat table pagination works
- [ ] Search returns matching results
- [ ] Adding a keyword shows it in the list
- [ ] Alert badge updates after acknowledging

---

## Environment Variables

| Variable           | Description                        | Default                              |
|--------------------|------------------------------------|--------------------------------------|
| MONGO_URI          | MongoDB connection string          | mongodb://localhost:27017/dark_web_intel |
| JWT_SECRET_KEY     | Random secret for signing tokens   | (required — set a long random string)|
| JWT_EXPIRES_MINUTES| Token lifetime in minutes          | 60                                   |
| ALLOWED_ORIGIN     | CORS allowed frontend URL          | * (lock down in production)          |
| PORT               | Flask listen port                  | 5000                                 |
| FLASK_ENV          | development or production          | development                          |
