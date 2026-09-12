# Installation

## Local (dev)
1. Python 3.11+, Node 18+.
2. Backend:
   ```bash
   cd backend
   python -m venv .venv && source .venv/bin/activate
   pip install -r requirements.txt
   cp ../.env.example ../.env   # or place .env in backend/
   uvicorn app.main:app --reload
   ```
3. Frontend:
```bash
cd frontend
npm install
npm run dev
```
4. Open http://localhost:5173 — login  admin / admin123! .
# Docker
```bash
cp .env.example .env
docker compose up --build
```
