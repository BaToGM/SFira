from fastapi import APIRouter, Depends, HTTPException, status

from app.core.dependencies import get_current_user
from app.schemas import ProfilePublic, ProfileReview, ProfileUpdate, UserPublic
from app.services.store import store

router = APIRouter(prefix="/profiles", tags=["profiles"])


@router.get("/me", response_model=ProfilePublic)
def get_my_profile(current_user: UserPublic = Depends(get_current_user)) -> ProfilePublic:
    return store.get_profile_for_user(current_user.id)


@router.patch("/me", response_model=ProfilePublic)
def update_my_profile(
    payload: ProfileUpdate,
    current_user: UserPublic = Depends(get_current_user),
) -> ProfilePublic:
    return store.update_profile(current_user.id, payload)


@router.get("/{profile_id}/reviews", response_model=list[ProfileReview])
def get_profile_reviews(profile_id: str) -> list[ProfileReview]:
    try:
        return store.profile_reviews(profile_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Profile not found") from exc
