# Production Deployment

1. Set a strong `SECRET_KEY`, real `DATABASE_URL` (PostgreSQL), `DEMO_MODE=false`.
2. Change all seeded passwords; create named users with least-privilege roles.
3. Run behind TLS-terminating reverse proxy with security headers (see SECURITY.md).
4. `uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 2`
   (for >1 worker, move WS fan-out to Redis pub/sub — see ARCHITECTURE.md).
5. Serve frontend build via nginx (`frontend/Dockerfile` reference config).
6. Configure at least one integration before enabling live (non-dry-run)
   response actions; keep policies on `approval` until confidence is earned.
7. Back up the database and the secret key (losing it invalidates sessions and
   encrypted AI/integration secrets).
