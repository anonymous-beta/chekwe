# Security Notes

- Passwords: bcrypt via passlib. JWT (HS256) bearer tokens, 8h TTL.
- Authorization: enforced server-side in `app/deps.py` (`require()`); the
  frontend role checks are UX only.
- AI keys & integration secrets: Fernet-encrypted (key derived from
  `SECRET_KEY`) before persistence; never returned by any API (masked tail only);
  never stored in browser storage — the browser only ever talks to CHEKWE.
- Audit log: append-only table; no update/delete endpoints exist.
- Injection: SQLAlchemy parameterized queries everywhere; Pydantic validation
  on all inputs; output is rendered as React text nodes (XSS-safe by default).
- Rate limiting: put a reverse proxy (nginx/Traefik) or API gateway in front
  for production rate limits; CORS is restricted to configured origins.
- Headers: terminate TLS at the reverse proxy and set HSTS, X-Content-Type-Options,
  X-Frame-Options: DENY, Referrer-Policy there.
- Demo mode: synthetic events carry `is_synthetic=true` and are labeled in every UI surface.
- Do not run with the default SECRET_KEY or default passwords in production.
