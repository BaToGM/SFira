from datetime import date, datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, EmailStr, Field


class UserType(StrEnum):
    couple = "couple"
    single = "single"


class VerificationProvider(StrEnum):
    document = "document"
    social = "social"


class Badge(BaseModel):
    code: str
    label: str
    tone: Literal["soft", "hot", "gold", "elite"] = "soft"


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)
    display_name: str = Field(min_length=2, max_length=80)
    user_type: UserType
    birth_date: date


class UserPublic(BaseModel):
    id: str
    email: EmailStr
    display_name: str
    user_type: UserType
    is_premium: bool
    created_at: datetime


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserPublic


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class ProfileUpdate(BaseModel):
    headline: str | None = None
    location: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    orientation: str | None = None
    interests: list[str] = Field(default_factory=list)
    fetishes: list[str] = Field(default_factory=list)
    age_min: int | None = Field(default=None, ge=18, le=99)
    age_max: int | None = Field(default=None, ge=18, le=99)


class ProfilePublic(ProfileUpdate):
    id: str
    user_id: str
    display_name: str
    user_type: UserType
    profile_progress: int
    average_score: float
    reputation_level: str
    badges: list[Badge]
    visits: int
    is_verified: bool
    is_premium: bool


class RatingCreate(BaseModel):
    target_profile_id: str
    interaction_type: Literal["chat", "virtual", "in_person"]
    score: int = Field(ge=1, le=5)
    comment: str | None = Field(default=None, max_length=400)
    is_super_score: bool = False


class RatingPublic(BaseModel):
    id: str
    target_profile_id: str
    score: float
    interaction_type: str
    created_at: datetime


class ReputationHistoryPoint(BaseModel):
    label: str
    average_score: float


class SearchFilters(BaseModel):
    min_score: float | None = None
    location: str | None = None
    orientation: str | None = None
    fetishes: list[str] = Field(default_factory=list)
    user_type: UserType | None = None


class ForumPost(BaseModel):
    id: str
    author: str
    title: str
    topic: str
    points: int
    replies: int
    created_at: datetime


class EventCreate(BaseModel):
    title: str = Field(min_length=3, max_length=120)
    mode: Literal["virtual", "in_person"]
    starts_at: datetime
    location: str | None = None


class EventPublic(EventCreate):
    id: str
    rsvp_count: int
    created_by: str


class MostViewedCouple(BaseModel):
    couple_name: str
    average_score: float
    visits: int
    current_badge: str


class AnalyticsSummary(BaseModel):
    clicks: int
    views: int
    gifts_sent: int
    reputation_percentile: int
