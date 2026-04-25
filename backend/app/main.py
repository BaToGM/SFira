from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import get_settings
from app.routers import auth, community, events, matching, premium, profiles, reputation

settings = get_settings()

app = FastAPI(
    title=f"{settings.app_brand_name} API",
    description="Web MVP API for profiles, reputation, matching, community and premium features.",
    version="0.1.0",
    openapi_url=f"{settings.api_prefix}/openapi.json",
    docs_url="/docs",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health", tags=["system"])
def health() -> dict[str, str]:
    return {"status": "ok", "brand": settings.app_brand_name}


for router in [
    auth.router,
    profiles.router,
    matching.router,
    reputation.router,
    community.router,
    events.router,
    premium.router,
]:
    app.include_router(router, prefix=settings.api_prefix)
