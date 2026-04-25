from fastapi import APIRouter, Depends

from app.core.dependencies import get_current_user
from app.schemas import ProfilePublic, ProfileUpdate, UserPublic
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
