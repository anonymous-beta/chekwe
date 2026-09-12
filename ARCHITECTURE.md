# Architecture

## Layers
- **Frontend** (React + TypeScript + Vite): talks only to the CHEKWE backend.
  Live updates via WebSocket `/ws/events`. SVG charts, no heavy visual libs.
- **Backend** (FastAPI): REST under `/api/v1`, OpenAPI at `/docs`.
  `app/pipeline.py` (ingest/normalize/enrich/correlate) → `app/detection.py`
  (rule registry) → `app/routers/*` → `app/response.py` (policy + adapters)
  → `app/ai.py` (provider abstraction) → `app/audit.py` (append-only).
- **Database**: SQLAlchemy 2.0 models; SQLite for dev, PostgreSQL for
  production via `DATABASE_URL`. JSON columns are used only for raw provider
  payloads and genuinely schemaless data (raw events, thresholds, evidence).
- **Realtime**: `app/ws.py` broadcast manager; ingestion publishes events.

## Extending
- New detection rule: add a function in `app/detection.py` + entry in `RULES`
  and `RULE_METADATA`; it appears in the UI automatically.
- New response action: add an adapter in `app/response.py`, register in
  `ADAPTERS`, create a `ResponsePolicy` row (defaults seeded).
- New AI provider: extend `PROVIDERS` in `app/ai.py` (endpoint + message path).
- New integration type: create an `integrations` row; the webhook adapter and
  the health-check test endpoint pick it up.

## Scaling path (documented, not faked)
Ingestion and detection currently run in-request for reliability and
testability. The pipeline functions are pure DB-bound services, so moving them
to a queue worker (Celery/RQ + Redis, or arq) requires no logic changes —
`ingest_event` and `run_detection` are the worker entry points. WebSocket
fan-out should move to Redis pub/sub beyond one process.

## Migrations
Development uses `Base.metadata.create_all`. For production schema evolution,
adopt Alembic against the same models; the model layer is already
migration-friendly (explicit types, no server-side defaults that mutate).
