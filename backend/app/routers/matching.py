from fastapi import APIRouter, Depends, Query

from app.core.config import Settings, get_settings
from app.schemas import ProfilePublic, SearchFilters, UserType
from app.services.store import store

router = APIRouter(prefix="/matching", tags=["matching"])


@router.get("/search", response_model=list[ProfilePublic])
def search_profiles(
    min_score: float | None = Query(default=None, ge=0, le=5),
    location: str | None = None,
    orientation: str | None = None,
    user_type: UserType | None = None,
    fetishes: list[str] = Query(default=[]),
    settings: Settings = Depends(get_settings),
) -> list[ProfilePublic]:
    filters = SearchFilters(
        min_score=min_score,
        location=location,
        orientation=orientation,
        user_type=user_type,
        fetishes=fetishes,
    )
    return store.search_profiles(filters, settings.reputation_min_search_score)
