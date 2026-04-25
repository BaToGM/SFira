from fastapi import APIRouter, Depends, HTTPException, status

from app.core.dependencies import get_current_user
from app.schemas import EventCreate, EventPublic, UserPublic
from app.services.store import store

router = APIRouter(prefix="/events", tags=["events"])


@router.get("", response_model=list[EventPublic])
def list_events() -> list[EventPublic]:
    return list(store.events.values())


@router.post("", response_model=EventPublic, status_code=status.HTTP_201_CREATED)
def create_event(
    payload: EventCreate,
    current_user: UserPublic = Depends(get_current_user),
) -> EventPublic:
    return store.create_event(current_user.id, payload)


@router.post("/{event_id}/rsvp", response_model=EventPublic)
def rsvp_event(event_id: str) -> EventPublic:
    try:
        return store.rsvp_event(event_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found") from exc
