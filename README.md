# Swinra

Swinra is a web MVP for an adult social and dating community focused on reputation, matching, community activity and premium discovery widgets.

The first version is intentionally web-first: a modular FastAPI backend, a React dashboard, Docker Compose for local services, and lightweight Kubernetes/observability templates for later deployment work.

## Stack

- Backend: FastAPI, Pydantic, JWT auth, modular routers.
- Frontend: React, TypeScript, Redux Toolkit, Vite, Recharts.
- Data services: PostgreSQL and Redis in Docker Compose. The MVP API currently uses a demo in-memory repository so the UI and tests can run before persistence is finalized.
- CI/CD: GitHub Actions.
- Infra: Docker, Kubernetes manifests, Prometheus/Grafana starter files.

## Local Development

Copy `.env.example` to `.env` when you want local overrides.

Run with Docker:

```bash
docker compose up --build
```

Local URLs:

- Frontend: http://localhost:5173
- Backend health: http://localhost:8000/health
- Swagger/OpenAPI: http://localhost:8000/docs

Backend only:

```bash
cd backend
python -m venv .venv
. .venv/Scripts/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Frontend only:

```bash
cd frontend
npm install
npm run dev
```

## Brand Switching

Change `APP_BRAND_NAME` and `VITE_APP_BRAND_NAME` to replace Swinra in public API metadata and frontend branding. Internal package names can remain stable until a full rename is required.

## Tests

```bash
cd backend && pytest
cd frontend && npm test
```
