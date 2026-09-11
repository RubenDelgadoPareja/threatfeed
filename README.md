# ThreatFeed

![Python 3.12](https://img.shields.io/badge/python-3.12-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.141-009688?logo=fastapi&logoColor=white)
![PostgreSQL 18](https://img.shields.io/badge/PostgreSQL-18-4169E1?logo=postgresql&logoColor=white)
![Managed with uv](https://img.shields.io/badge/deps-uv-DE5FE9)
![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)

> A small threat intelligence platform. It ingests public indicator-of-compromise (IoC) feeds,
> normalizes and deduplicates them into PostgreSQL, and answers one question over a REST API:
> **"Is this IP / domain / URL / hash known to be malicious? Who says so, and since when?"**

**Status:** phase 1 (backend) in progress. See the [roadmap](#roadmap).

## Why

Security teams rely on *threat feeds*: continuously updated lists of IoCs published by
organizations such as [abuse.ch](https://abuse.ch/). IPs of botnet command-and-control servers,
URLs currently distributing malware, hashes of known malicious files. Firewalls block them, SIEMs
alert on them, analysts look them up by hand. Consuming the raw feeds is painful, though:

- **Every feed speaks its own dialect.** Different columns, comment lines, casing, trailing dots.
- **They overlap.** The same indicator appears in several feeds. Without deduplication you cannot
  tell how many unique indicators you have, and you lose a valuable signal: independent sources agreeing.
- **Indicators expire.** IP addresses get reassigned. Blocking forever creates false positives,
  so every indicator needs a *first seen* and a *last seen*.
- **Provenance matters.** When something gets blocked, the first question is: who says it is
  malicious, and since when?

ThreatFeed aggregates several feeds into one normalized, deduplicated, queryable store that keeps
provenance and freshness for every indicator. It is strictly defensive: it consumes public data
and organizes it. It does not scan, attack, or analyze malware.

## How it works

```mermaid
flowchart LR
    subgraph feeds["Public feeds (abuse.ch)"]
        U[URLhaus CSV]
        F[Feodo Tracker CSV]
    end

    subgraph ingest["Ingest · python -m threatfeed.ingest &lt;feed&gt;"]
        D[Download] --> P[Parse] --> N[Normalize] --> UP["Upsert<br/>UNIQUE(type, value)"]
    end

    U --> D
    F --> D
    UP --> DB[("PostgreSQL<br/>indicators · ingest_runs")]
    DB --> API["FastAPI<br/>/check · /indicators · /stats · /health"]
    API --> SOC[Analyst / SOC tooling]
```

1. **Ingest.** One ingestor per feed downloads the CSV, parses it (skipping comment lines),
   normalizes each indicator (lowercase, no trailing dots, canonical URLs) and upserts it.
   Every run is recorded in `ingest_runs` with counters and status.
2. **Deduplicate.** An indicator's identity is the pair `(type, value)`, enforced by a unique
   constraint. Re-ingesting never creates duplicates: it updates `last_seen` and appends the new
   source. Ingestion is idempotent, so a crashed or repeated run is always safe to re-run.
3. **Serve.** A FastAPI service answers lookups, lists indicators with pagination and reports
   totals per type and source.

## Data model

**`indicators`**

| Column | Type | Notes |
| --- | --- | --- |
| `id` | uuid | Primary key |
| `type` | enum | `ip`, `domain`, `url`, `hash_sha256`, `hash_md5` |
| `value` | text | Normalized form |
| `first_seen` | timestamptz | First time any feed reported it |
| `last_seen` | timestamptz | Most recent report |
| `sources` | jsonb | Feeds where it appeared, e.g. `["urlhaus", "feodotracker"]` |
| `raw` | jsonb | Original payload, kept for reprocessing |

Unique constraint on `(type, value)`. Deduplication happens in the database with an upsert
(`INSERT ... ON CONFLICT DO UPDATE`), not in application code.

**`ingest_runs`**: `feed`, `started_at`, `finished_at`, `indicators_new`, `indicators_updated`,
`status`, `error`. The audit trail of every ingestion.

## API

| Endpoint | Purpose |
| --- | --- |
| `GET /check/{value}` | Is this indicator known? Returns type, sources, first and last seen |
| `GET /indicators?type=&limit=&offset=` | Paginated listing, optionally filtered by type |
| `GET /stats` | Totals per type and per source |
| `GET /health` | Liveness check |

## Stack

| Layer | Choice | Why |
| --- | --- | --- |
| Web framework | FastAPI | Type-driven validation with Pydantic, OpenAPI for free, async-ready |
| ORM / migrations | SQLAlchemy 2 (sync) + Alembic | Explicit SQL model, versioned schema changes |
| Database | PostgreSQL 18 | `jsonb`, `timestamptz`, native upsert |
| Driver | psycopg 3 | Modern, actively maintained Postgres driver |
| Config | pydantic-settings | Typed settings from environment / `.env`, 12-factor style |
| Tooling | uv · pytest · ruff | Fast, reproducible installs; tests; lint + format in one tool |
| Local env | Docker Compose | One command to bring up the database (and, later, workers) |

## Getting started

Requirements: [uv](https://docs.astral.sh/uv/) and Docker with Compose v2.

```bash
git clone https://github.com/RubenDelgadoPareja/threatfeed.git
cd threatfeed
cp .env.example .env                         # local credentials; dev defaults are fine
docker compose up -d db                      # PostgreSQL with a readiness healthcheck
uv sync                                      # creates .venv and installs everything
uv run alembic upgrade head                  # apply migrations
uv run python -m threatfeed.ingest urlhaus   # first ingestion
uv run uvicorn threatfeed.main:app --reload  # API on http://localhost:8000 (docs at /docs)
```

Development:

```bash
uv run pytest
uv run ruff check . && uv run ruff format --check .
```

## Project layout

```
src/threatfeed/
├── main.py       # FastAPI application
├── config.py     # settings (pydantic-settings, .env)
├── db/           # declarative base, engine/session, Alembic migrations
├── models/       # SQLAlchemy models
├── schemas/      # Pydantic schemas (API in/out)
├── ingest/       # one ingestor per feed
└── api/          # routers
tests/
```

## Roadmap

- [ ] **Phase 1: backend.** Scaffold · models and first migration · URLhaus ingestor ·
  REST API · Feodo Tracker ingestor on a shared `BaseIngestor` · tests.
- [ ] **Phase 2: applied security.** GeoIP / ASN enrichment (MaxMind GeoLite2) · multi-source
  confidence score · `POST /analyze/logs` to match an nginx access log against the indicators,
  parsed as a stream.
- [ ] **Phase 3: distributed.** Celery + Redis scheduled ingestion with parallel workers ·
  retries with exponential backoff · rate limiting · idempotent tasks · Redis cache for `/check`
  with invalidation after each ingestion · full Docker Compose.

## Design decisions

Short version; detailed notes will grow with the project.

- **Deduplicate in the database, not in Python.** A unique constraint plus upsert is atomic and
  race-free even with several workers ingesting at once.
- **Synchronous SQLAlchemy.** FastAPI runs plain `def` endpoints in a threadpool, so sync database
  calls do not block the event loop, and the phase 3 Celery workers are synchronous anyway.
  Async would add complexity without a measurable gain at this scale.
- **Keep the raw payload.** If a parser bug is found, indicators can be reprocessed from `raw`
  without hitting the feeds again.
- **One `.env` for everything.** Docker Compose and the application read the same `POSTGRES_*`
  variables, so there is a single source of truth for local configuration.

## Glossary

| Term | Meaning |
| --- | --- |
| IoC | Indicator of compromise: an observable (IP, domain, URL, file hash) tied to malicious activity |
| Feed | A continuously updated list of IoCs, usually published as CSV or JSON |
| C2 | Command-and-control server from which an attacker issues orders to infected machines |
| Botnet | A set of infected machines controlled by the same C2 |
| False positive | Flagging something legitimate as malicious |
| Normalization | Reducing each indicator to a canonical form so that equal indicators compare equal |

---

Built by [Rubén Delgado Pareja](https://github.com/RubenDelgadoPareja) to go deep on Python
backend engineering, threat intelligence and distributed systems.
