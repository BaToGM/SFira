# Swinra Product Roadmap

This roadmap defines what turns the current local MVP into a credible demo for future clients.

## Current Demo Strengths

- App-style landing, dashboard, matching, community and premium sections.
- Profile scoring, badges, reputation chart and minimum score filtering.
- Public profile photos, private album state and verified profile reviews.
- Full profile detail inside matching with trust signals, photos, interests and reviews.
- Simulated connection request, accepted-state chat preview and consent checklist.
- Credits wallet with earn rules, redemption actions and transaction history.
- Premium actions for boost, private album requests, analytics and hotlists.
- Community moderation queue for photos/reviews and trust operations.
- Premium widget for most viewed couples.
- FastAPI backend with typed endpoints and OpenAPI docs.
- React/Vite frontend with Redux state and tests.

## Sellable Local MVP Criteria

- Profiles must feel real: photos, verified state, interests, badges, reviews and privacy controls.
- Matching must support a clear decision loop: see profile, inspect trust signals, request access or start chat.
- Reviews must be constrained: only after a verified interaction, with moderation and owner visibility controls.
- Premium must be visible but not fake: explain why a user would pay, such as private album access workflows, hotlists, analytics and featured placement.
- Demo data must be tasteful, non-explicit and safe to show in a meeting.

## Next Product Features

- Trust Circles: users can share private albums, approximate location and availability only with validated profiles.
- Real connection workflow: request, approve, reject, expire and revoke access.
- Persistent chat: conversation list, message history and post-chat rating flow.
- Real credit ledger: immutable transactions, purchase packs and abuse limits.
- Saved Searches: named searches with alert rules for location, score and interests.
- Moderation console: report triage, audit trail, role permissions and SLA status.

## Production Blockers

- Replace `DemoStore` with PostgreSQL repositories and Alembic migrations.
- Add object storage for uploaded photos and virus/content scanning.
- Add real auth flows, password reset and role-based moderation.
- Add legal pages: terms, privacy, adult-only policy and community rules.
- Add rate limiting, audit logs and report/block flows.
- Add analytics privacy controls before storing behavioral metrics.
