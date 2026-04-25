# Deployment Guide

This is the recommended MVP path to put Swinra on a real domain without overbuilding infrastructure too early.

## Recommended Providers

- Frontend: Vercel. It is the simplest fit for a Vite React app, gives preview deployments per PR, automatic HTTPS and easy custom domains.
- Backend: Fly.io. It is a good fit for FastAPI containers, supports regions close to Spain/Europe and can scale from a small app.
- Database: Neon or Supabase PostgreSQL. Neon is very lean for serverless Postgres; Supabase is better if you later want auth/storage/admin tools.
- Redis: Upstash Redis. It is managed, simple, usage-based and enough for cache/rankings/alerts in the MVP.
- Domain/CDN/WAF: Cloudflare. Use it for DNS, SSL, CDN, WAF rules and basic bot protection.

## Environments

Create at least two environments:

- Preview: every PR or staging branch.
- Production: main branch only.

Recommended variables:

```text
APP_BRAND_NAME=Swinra
ENVIRONMENT=production
JWT_SECRET_KEY=<long-random-secret>
DATABASE_URL=<postgres-url>
REDIS_URL=<redis-url>
REPUTATION_MIN_SEARCH_SCORE=3.5
SUPER_SCORE_MULTIPLIER=1.5
PREMIUM_FEATURES_ENABLED=true
VITE_APP_BRAND_NAME=Swinra
VITE_API_BASE_URL=https://api.your-domain.com/api/v1
```

## Frontend On Vercel

1. Import `BaToGM/SFira` in Vercel.
2. Set project root to `frontend`.
3. Build command: `npm run build`.
4. Output directory: `dist`.
5. Add `VITE_APP_BRAND_NAME` and `VITE_API_BASE_URL`.
6. Add the custom domain, for example `app.your-domain.com`.

## Backend On Fly.io

1. Install and authenticate `flyctl`.
2. Create an app from the `backend` folder.
3. Use `backend/Dockerfile`.
4. Set secrets with `fly secrets set`.
5. Deploy the app.
6. Point a domain such as `api.your-domain.com` to Fly.

Example commands:

```bash
cd backend
fly launch --name swinra-api --dockerfile Dockerfile --no-deploy
fly secrets set JWT_SECRET_KEY="<long-random-secret>" DATABASE_URL="<postgres-url>" REDIS_URL="<redis-url>"
fly deploy
```

## Database And Redis

For the current MVP, the backend still uses `DemoStore` in memory. Before production users:

1. Add SQLAlchemy models and Alembic migrations.
2. Replace `DemoStore` with repository classes backed by PostgreSQL.
3. Use Redis for search result cache, rankings and saved-search alerts.
4. Keep demo seed data only for local/dev environments.

## Cloudflare

1. Add the domain to Cloudflare.
2. Point `app.your-domain.com` to Vercel.
3. Point `api.your-domain.com` to Fly.io.
4. Enable HTTPS.
5. Add basic WAF rules for API rate limiting and suspicious traffic.

## Production Readiness Checklist

- Real persistence with PostgreSQL migrations.
- Real auth refresh-token flow and secure cookie strategy.
- Moderation and reporting workflow.
- Legal pages: terms, privacy, cookie policy and adult-only policy.
- Observability: structured logs, error tracking, uptime checks and metrics.
- Backups for PostgreSQL.
- Payment provider integration for premium and credits.
