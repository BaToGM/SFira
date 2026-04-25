# Development Guide

## Recommended Flow

1. Start backend with `uvicorn app.main:app --reload` from `backend/`.
2. Start frontend with `npm run dev` from `frontend/`.
3. Open `http://localhost:5173`.
4. Use `http://localhost:8000/docs` to inspect and try the API.

## Quality Gates

- Backend: `ruff check backend` and `pytest` from `backend/`.
- Frontend: `npm test` and `npm run build` from `frontend/`.
- Docker: `docker compose build`.

## Data Persistence Roadmap

The MVP uses `DemoStore` to keep implementation fast and testable. The next persistence iteration should:

- Add SQLAlchemy models and Alembic migrations.
- Create repository classes per domain.
- Move score aggregation into transaction-safe service methods.
- Add Redis caching for search results and rankings.
- Keep API schemas stable while replacing the storage layer.
