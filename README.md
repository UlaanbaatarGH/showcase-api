# showcase-api

FastAPI backend for the Showcase app. Connects to Supabase Postgres.

## Local dev

```bash
python -m venv .venv
.venv\Scripts\activate            # Windows
pip install -r requirements.txt
cp .env.example .env              # then edit .env with real DATABASE_URL
uvicorn main:app --reload
```

Open http://localhost:8000/api/health → should return `{"status":"ok"}`.
Open http://localhost:8000/api/hello → should return the row from `hello` table.

## Deploy

Render (or any Docker-capable host). Start command:
`uvicorn main:app --host 0.0.0.0 --port $PORT`
