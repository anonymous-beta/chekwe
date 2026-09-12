# Contributing

- Defensive security only. CHEKWE detects, analyzes, and responds — it is not
  an attack toolkit.
- No fake functionality: if a feature isn't complete, expose its interface and
  report `unavailable` honestly.
- Every state-changing endpoint must audit; every new rule must include a test.
- Run `pytest` before opening a PR; keep TypeScript strict.
