# Syshunt — Automated Bug Bounty System

Syshunt automates recon and vulnerability classification so you can focus on manual
analysis and creative exploitation. It runs a full pipeline (subdomain enumeration,
HTTP probe, port scan, web crawl, screenshots, nuclei scanning) and then classifies
findings using heuristics or an AI provider.

> **IMPORTANT:** Only scan targets you are explicitly authorized to test.
> Running scans against systems without written permission is illegal in most jurisdictions.
> Always verify your scope before starting a pipeline.

---

## Requirements

- Docker and Docker Compose
- Python 3.12+ (for local development without Docker)
- Go tools are installed automatically in the worker container

---

## Compose Files

Syshunt ships two Compose files to separate development and VPS deployments:

| File | Purpose | Who should use it |
|------|---------|-------------------|
| `docker-compose.yml` | Base/VPS-safe config — no internal ports exposed to external interfaces | Everyone (always used) |
| `docker-compose.local.yml` | Development overlay — binds Postgres, Redis, Flower, and dashboard to `127.0.0.1` | Local development only |

**On a VPS:** use only `docker-compose.yml` (via `make up-all`). Never deploy
`docker-compose.local.yml` to a public server — it is only for local dev machines.

**On a local machine or notebook:** use `make up-local` (which overlays both files) to
get direct access to all services from your host.

---

## Quick Start — Local / Notebook Mode

Use this when you want to run occasional manual scans on specific targets.

### 1. Configure environment

```bash
cp .env.example .env
# Edit .env:
#   - Set ANTHROPIC_API_KEY (optional, for AI classification)
#   - Leave DASHBOARD_PASSWORD empty for local mode
#   - Adjust OUTPUT_DIR if needed
```

### 2. Start database and Redis

```bash
make up
```

This starts PostgreSQL and Redis via Docker Compose (no port exposure beyond the
Docker network). If you also want Flower and the containerized dashboard, use
`make up-local` instead.

### 3. Run database migrations

```bash
make migrate
```

### 4. Start the worker (in a separate terminal)

```bash
make worker
```

The Celery worker processes pipeline tasks in the background.

### 5. Start the dashboard (in a separate terminal)

```bash
make dashboard
```

Open http://localhost:8501 in your browser.

### 6. Add a target and run recon

1. Go to **Targets** > **Add Target**
2. Enter a domain you are authorized to test
3. Configure scope, depth, and options
4. Click **Start Recon** in the Target List section

### Stop services

```bash
make down
```

---

## Development Mode — All Services with Local Ports

If you want to run all services inside Docker and access Postgres/Redis/Flower
directly from your host (e.g., with `psql`, `redis-cli`, or a browser):

```bash
make up-local
# equivalent to:
# docker compose -f docker-compose.yml -f docker-compose.local.yml up -d
```

This exposes the following ports on `127.0.0.1` only:

| Service | Port |
|---------|------|
| PostgreSQL | 5432 |
| Redis | 6379 |
| Flower | 5555 |
| Dashboard | 8501 |

> **Warning:** `make up-local` is for development on a local machine only.
> Do not run it on a VPS or any server reachable from the internet.

---

## VPS / Continuous Monitoring Mode

Use this when you want the system running 24/7 to monitor bug bounty platforms.

### Security requirements for VPS

- Set `DASHBOARD_PASSWORD` — the dashboard is not protected without it
- PostgreSQL, Redis, and Flower are **not exposed** on external interfaces by default
- The dashboard binds to `127.0.0.1:8501` — it is not directly reachable from outside
- Access the dashboard remotely via one of the methods below

### Accessing the dashboard remotely

**Option A — SSH tunnel (simplest)**

```bash
# From your local machine:
ssh -L 8501:127.0.0.1:8501 user@your-vps-ip
# Then open http://localhost:8501 in your browser
```

**Option B — Tailscale**

Install Tailscale on both your VPS and local machine. Once connected, the VPS's
Tailscale IP can reach the dashboard at `http://<tailscale-ip>:8501`. No tunnel needed.
Make sure the dashboard is reachable only on the Tailscale interface (or keep it
on `127.0.0.1` and use an SSH tunnel via the Tailscale IP).

**Option C — Authenticated reverse proxy (Caddy / nginx + auth)**

Put a reverse proxy with authentication in front of port 8501. Example with Caddy:

```caddyfile
dashboard.yourdomain.com {
    basicauth {
        admin <hashed_password>
    }
    reverse_proxy 127.0.0.1:8501
}
```

### Setup

```bash
cp .env.example .env
# Edit .env:
#   - Set DB_PASSWORD to a strong random password
#   - Set DASHBOARD_PASSWORD to a strong password
#   - Set ANTHROPIC_API_KEY (or another AI provider)
#   - Set OUTPUT_DIR to a persistent volume path (e.g. /data/syshunt)
chmod 600 .env
```

### Start all services (VPS-safe)

```bash
make up-all
```

This starts all services defined in `docker-compose.yml`:
- `db` — PostgreSQL (internal only, not exposed)
- `redis` — Redis (internal only, not exposed)
- `worker` — Celery worker (runs the pipeline)
- `beat` — Celery Beat scheduler
- `flower` — Queue monitor (internal only, access via SSH tunnel)
- `dashboard` — Streamlit dashboard (bound to `127.0.0.1:8501`)

### Run migrations inside the container

```bash
docker compose exec worker alembic upgrade head
```

### Monitor queues (Flower)

Flower runs internally. Access it via SSH tunnel:

```bash
ssh -L 5555:127.0.0.1:5555 user@your-vps-ip
# Then open http://localhost:5555
```

Or use `make up-local` on a development machine to expose it directly.

---

## Makefile Reference

| Command | Description |
|---------|-------------|
| `make up` | Start PostgreSQL and Redis only (notebook mode, no port exposure) |
| `make up-local` | Start all services with local port bindings (development only) |
| `make up-all` | Start all services without exposing internal ports (VPS / production) |
| `make down` | Stop all services |
| `make migrate` | Apply Alembic database migrations |
| `make migrate-new MSG="description"` | Generate a new migration |
| `make worker` | Start Celery worker locally |
| `make dashboard` | Start Streamlit dashboard locally |
| `make beat` | Start Celery Beat scheduler (for platform monitoring) |
| `make flower` | Start Flower queue monitor on port 5555 |
| `make test` | Run all tests with verbose output |
| `make test-cov` | Run tests with coverage report |
| `make lint` | Run ruff linter |
| `make format` | Run black + ruff --fix |
| `make seed` | Insert development seed data |
| `make build` | Build Docker images |
| `make rebuild` | Rebuild Docker images without cache |

---

## Pipeline Overview

```
Target ingested
  -> Subdomain enumeration (subfinder)
       -> DNS filter (dnsx) -- removes NXDOMAIN
            -> HTTP probe (httpx) -- identifies live services
                 -> Port scan (nmap)
                      -> Web crawl (katana + gau)
                           -> Screenshots (gowitness)
                                -> Vulnerability scan (nuclei)
                                     -> AI analysis (heuristic or LLM)
                                          -> Findings ready for review
```

Each stage is a Celery task. Failures in individual items (e.g., one subdomain timing
out) are logged and skipped -- the pipeline continues with remaining items.

---

## AI Classification

Syshunt classifies findings using heuristic scoring by default. When an AI provider
is configured, it upgrades to contextual LLM analysis.

**Providers supported:**
- Anthropic Claude (set `ANTHROPIC_API_KEY`)
- OpenAI-compatible APIs (set `OPENAI_API_KEY` + `OPENAI_BASE_URL`)
- Ollama local models (set `OLLAMA_BASE_URL` + `OLLAMA_MODEL`)

Configure providers in the **Settings** page of the dashboard.

---

## Environment Variables

Key variables from `.env.example`:

```bash
DATABASE_URL=postgresql://user:pass@localhost:5432/bughunter
REDIS_URL=redis://localhost:6379/0

# AI (at least one is required for AI classification)
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...
OPENAI_BASE_URL=https://api.openai.com/v1

# Dashboard
DASHBOARD_PASSWORD=           # Leave empty for local mode; required for VPS

# Pipeline
OUTPUT_DIR=/tmp/syshunt       # Where screenshots and tool outputs are stored
MAX_RECON_DEPTH=2             # How many levels of subdomain recursion
NUCLEI_RATE_LIMIT=150         # Nuclei requests per second
```

See `.env.example` for the full list.

---

## Ethics and Legal Notice

This tool is designed for authorized security testing and bug bounty research only.

- Only run scans against targets explicitly listed in your bug bounty scope
- Respect rate limits and program rules on each platform
- Never use this tool to attack systems without written authorization
- The author assumes no liability for unauthorized use

For responsible disclosure, follow the program policy on HackerOne, Bugcrowd,
Intigriti, or the platform of your choice.
