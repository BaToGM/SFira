from fastapi import APIRouter, Depends, HTTPException, status

from app.core.config import Settings, get_settings
from app.core.dependencies import get_current_user
from app.schemas import AnalyticsSummary, MostViewedCouple, UserPublic
from app.services.store import store

router = APIRouter(prefix="/premium", tags=["premium"])


@router.get("/most-viewed-couples", response_model=list[MostViewedCouple])
def most_viewed_couples(
    current_user: UserPublic = Depends(get_current_user),
    settings: Settings = Depends(get_settings),
) -> list[MostViewedCouple]:
    if not settings.premium_features_enabled or not current_user.is_premium:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Premium plan required")
    return store.most_viewed_couples()


@router.get("/analytics", response_model=AnalyticsSummary)
def premium_analytics(current_user: UserPublic = Depends(get_current_user)) -> AnalyticsSummary:
    if not current_user.is_premium:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Premium plan required")
    return store.analytics()
