# API Guide

Swagger is available at `/docs` and OpenAPI JSON at `/api/v1/openapi.json`.

## Demo Credentials

```json
{
  "email": "luna@example.com",
  "password": "SwinraDemo1"
}
```

## Key Endpoints

- `POST /api/v1/auth/register`
- `POST /api/v1/auth/login`
- `GET /api/v1/profiles/me`
- `PATCH /api/v1/profiles/me`
- `GET /api/v1/matching/search?min_score=3.5`
- `POST /api/v1/reputation/ratings`
- `GET /api/v1/reputation/{profile_id}/history`
- `GET /api/v1/community/forum-posts`
- `GET /api/v1/community/monthly-ranking`
- `POST /api/v1/events`
- `POST /api/v1/events/{event_id}/rsvp`
- `GET /api/v1/premium/most-viewed-couples`
- `GET /api/v1/premium/analytics`

Premium endpoints require a bearer token for a premium user.
