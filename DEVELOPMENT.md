# Development

- Backend tests: `cd backend && pytest -v` (SQLite, isolated per test).
- API exploration: http://localhost:8000/docs (OpenAPI).
- Add a rule: `app/detection.py` → function + `RULES` + `RULE_METADATA`.
- Frontend: `npm run dev` with proxy to :8000 configured in vite.config.ts.
- Code style: Python type hints throughout; strict TypeScript.
- End-to-end proof: `backend/tests/test_e2e.py` walks the full chain
  ingest → detect → alert → incident → AI analysis → response → approval →
  execution → audit.
