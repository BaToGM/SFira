# Swinra Business Plan

## Honest Assessment

Swinra can be useful if it avoids being "another dating app" and becomes a trust marketplace for private adult communities. The strongest angle is not explicit content; it is reputation, verified interactions, private albums under consent, events and safer discovery.

The main risk is cold-start: a dating/social product has little value without enough profiles in one city. The second risk is moderation: privacy, photos, comments and adult context require strict rules, reporting and active review. The product should launch city-by-city, not everywhere at once.

## Customer Segments

- Private clubs and event organizers that want vetted communities.
- Couples and singles who already use forums/apps but want more privacy and reputation.
- Venue/event partners that need RSVP, waitlists and member reputation.
- Premium users who pay for visibility, advanced filters, private album workflows and analytics.

## Positioning

Swinra should be sold as a private community platform, not as a generic dating app.

Core promise:

> More trust before interacting: verified profiles, reputation after real interactions, private albums by permission and curated events.

## Revenue Model

Suggested consumer pricing:

- Free: profile, limited search, public events, basic reputation.
- Premium: 12.90-17.90 EUR/month. Hotlists, private album requests, saved searches, profile boost, analytics and monthly credits.
- Elite: 29.90-39.90 EUR/month. Higher visibility, event priority, more credits, advanced statistics and concierge moderation.
- Credit packs: 4.99, 9.99, 19.99 EUR for gifts, boosts, super-scores and premium profile skins.

Suggested B2B pricing:

- Private club/event organizer: 99-299 EUR/month for branded community, RSVP, member reputation and event tools.
- Setup/customization fee: 500-2,500 EUR depending on branding, imports, moderation workflows and custom features.

## Go-To-Market

1. Launch in one city first, ideally Madrid or Barcelona.
2. Recruit 2-3 private event organizers as pilot partners.
3. Offer the first 100-300 verified users free premium for feedback.
4. Run curated events and use RSVP/reviews to seed reputation.
5. Convert active users to Premium after the trust loop is proven.

## Maintenance Needs

This cannot be an unattended website. It needs operations:

- Weekly moderation and support.
- Security updates and dependency maintenance.
- Backups, monitoring and incident response.
- Legal/privacy updates.
- Content/photo review workflows.
- Product iteration based on conversion and retention.

Minimum human maintenance after launch: 10-20 hours/month for a small pilot. With active users and events: 30-60 hours/month.

## Infrastructure Cost Estimates

Prototype/local demo:

- 0-30 EUR/month if kept local or on free tiers.

Public pilot:

- Frontend: Vercel Hobby/Pro. Vercel Pro developer seat is listed at $20/month, with included traffic allowances and paid usage beyond limits.
- Backend: Fly.io small shared CPU machine. Fly lists shared-cpu machines around a few dollars/month depending region and RAM; 1GB shared-cpu examples are roughly $5.70-$7.45/month in listed regions.
- Database: Neon Free for prototype, then Launch around typical $15/month for intermittent load with 1GB.
- Redis: Upstash Free for prototype, then pay-as-you-go at $0.20 per 100K commands or fixed 250MB at $10/month.
- DNS/CDN/WAF: Cloudflare Free initially; Cloudflare WAF Pro is listed at $20/month annually or $25/month monthly.

Reasonable early public pilot budget: 50-120 EUR/month for infrastructure, excluding developer time, legal, moderation and paid acquisition.

Production small community:

- Infrastructure: 150-500 EUR/month depending traffic, images, monitoring, backups and WAF.
- Maintenance/development: 1,000-3,000 EUR/month if outsourced part-time.
- Moderation/support: 300-1,500 EUR/month depending volume.

## What To Build Before Selling

- Real PostgreSQL persistence and migrations.
- Real login/register/password reset.
- Photo upload with private album permissions.
- Report/block/moderation queue.
- Saved searches and alerts.
- Credit ledger with transaction history.
- Premium entitlement checks.
- Basic chat or request-to-connect workflow.
- Legal pages and adult-only rules.

## Key Metrics

- Activation: percentage of users with complete profile and at least one photo.
- Trust: verified profiles, reviews per interaction, reports per active user.
- Matching: search-to-connection rate, connection acceptance rate.
- Community: RSVP rate, event attendance, forum participation.
- Revenue: premium conversion, ARPPU, credit purchases, churn.

## Sources For Current Provider Pricing

- Vercel pricing: https://vercel.com/pricing
- Fly.io resource pricing: https://fly.io/docs/about/pricing/
- Neon pricing: https://neon.com/pricing
- Upstash Redis pricing: https://upstash.com/pricing/redis
- Cloudflare WAF pricing: https://www.cloudflare.com/application-services/products/waf/
