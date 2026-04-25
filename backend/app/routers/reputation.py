from fastapi import APIRouter, Depends, HTTPException, status

from app.core.config import Settings, get_settings
from app.schemas import RatingCreate, RatingPublic, ReputationHistoryPoint
from app.services.store import store

router = APIRouter(prefix="/reputation", tags=["reputation"])


@router.post("/ratings", response_model=RatingPublic, status_code=status.HTTP_201_CREATED)
def rate_interaction(
    payload: RatingCreate,
    settings: Settings = Depends(get_settings),
) -> RatingPublic:
    try:
        return store.add_rating(payload, multiplier=settings.super_score_multiplier)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Profile not found") from exc


@router.get("/{profile_id}/history", response_model=list[ReputationHistoryPoint])
def get_reputation_history(profile_id: str) -> list[ReputationHistoryPoint]:
    return [ReputationHistoryPoint(**point) for point in store.reputation_history(profile_id)]
