<p align="center">
  <img src="CHEKWE_logo.svg" alt="chekwe" width="200" height="auto" />
</p>

# CHEKWE — Security Operations & Defense Platform

**DETECT. UNDERSTAND. RESPOND.**

CHEKWE is a defensive SOC platform: real-time event monitoring, modular intrusion
detection, threat intelligence, incident management, AI-assisted analysis, and a
controlled response framework. Created by **Anonymous-beta**.

## What it does
- **Event pipeline**: ingestion → parsing → normalization → IOC enrichment →
  correlation → detection → severity → alert → incident → AI analysis →
  response → audit. Malformed events are kept and flagged, never discarded.
- **Detection engine**: 10 pluggable rules (brute force, first-seen login,
  impossible travel, suspicious process, IOC match, port scan, rare-port
  egress, DNS anomaly, traffic spike, privilege change) with configurable
  thresholds, enable/disable, per-rule test harness, MITRE ATT&CK mapping.
- **Incident workflow**: new → triaged → investigating → contained →
  remediating → resolved → closed, fully audited.
- **AI layer**: provider-agnostic (OpenAI / Anthropic / Google / any
  OpenAI-compatible endpoint). Analysis is strictly structured into
  OBSERVED / INFERRED / UNKNOWN — the model never invents evidence.
  API keys are stored Fernet-encrypted server-side and never reach the browser.
- **Response framework**: policy-driven (automatic / manual / approval),
  dry-run support, per-action adapters, honest "unavailable" results when an
  integration isn't configured. AI recommends → policy decides → adapter executes → audit records.
- **RBAC**: admin / analyst / viewer, enforced server-side on every endpoint.
- **Demo mode**: clearly labeled SYNTHETIC scenarios for brute force,
  suspicious login, port scan, IOC match, and outbound spike.

## Quick start
```bash
cd backend && python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload        # API on :8000, docs at /docs
cd ../frontend && npm install && npm run dev   # UI on :5173
```
Login:  admin / admin123!  (change immediately). Run pytest in  backend/ . Or:  docker compose up --build .
___
Chekwaa sistemụ gị ugbu a
