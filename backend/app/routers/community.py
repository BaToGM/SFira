from fastapi import APIRouter

from app.schemas import ForumPost
from app.services.store import store

router = APIRouter(prefix="/community", tags=["community"])


@router.get("/forum-posts", response_model=list[ForumPost])
def forum_posts() -> list[ForumPost]:
    return sorted(store.forum_posts, key=lambda item: item.points, reverse=True)


@router.get("/monthly-ranking", response_model=list[ForumPost])
def monthly_ranking() -> list[ForumPost]:
    return sorted(store.forum_posts, key=lambda item: item.points + item.replies, reverse=True)
