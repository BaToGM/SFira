from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from uuid import uuid4

from app.core.security import hash_password, verify_password
from app.schemas import (
    AnalyticsSummary,
    EventCreate,
    EventPublic,
    ForumPost,
    MostViewedCouple,
    ProfilePublic,
    ProfileUpdate,
    RatingCreate,
    RatingPublic,
    SearchFilters,
    UserCreate,
    UserPublic,
    UserType,
)
from app.services.reputation import assign_badges, calculate_average_score, profile_completion_score, reputation_level


@dataclass
class UserRecord:
    id: str
    email: str
    password_hash: str
    display_name: str
    user_type: UserType
    birth_date: date
    is_premium: bool = False
    is_verified: bool = False
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class ProfileRecord:
    id: str
    user_id: str
    headline: str = ""
    location: str = ""
    latitude: float | None = None
    longitude: float | None = None
    orientation: str = ""
    interests: list[str] = field(default_factory=list)
    fetishes: list[str] = field(default_factory=list)
    age_min: int | None = None
    age_max: int | None = None
    visits: int = 0
    participation_points: int = 0


class DemoStore:
    """In-memory repository for the MVP. Replace with SQLAlchemy repositories when persistence lands."""

    def __init__(self) -> None:
        self.users: dict[str, UserRecord] = {}
        self.profiles: dict[str, ProfileRecord] = {}
        self.ratings: list[RatingPublic] = []
        self.events: dict[str, EventPublic] = {}
        self.forum_posts: list[ForumPost] = []
        self._seed()

    def reset(self) -> None:
        self.users.clear()
        self.profiles.clear()
        self.ratings.clear()
        self.events.clear()
        self.forum_posts.clear()
        self._seed()

    def _seed(self) -> None:
        if self.users:
            return
        seeds = [
            ("luna@example.com", "Luna & Marco", UserType.couple, True, True, 244, 4.9, 24),
            ("iris@example.com", "Iris", UserType.single, False, True, 138, 4.3, 7),
            ("nexo@example.com", "Nexo Duo", UserType.couple, True, False, 318, 4.7, 14),
        ]
        for email, name, user_type, premium, verified, visits, score, count in seeds:
            user = UserRecord(
                id=str(uuid4()),
                email=email,
                password_hash=hash_password("SwinraDemo1"),
                display_name=name,
                user_type=user_type,
                birth_date=date(1992, 1, 1),
                is_premium=premium,
                is_verified=verified,
            )
            profile = ProfileRecord(
                id=str(uuid4()),
                user_id=user.id,
                headline="Conexiones cuidadas, buen humor y planes con quimica.",
                location="Madrid",
                latitude=40.4168,
                longitude=-3.7038,
                orientation="bi-curious",
                interests=["eventos", "cenas", "viajes"],
                fetishes=["roleplay", "lingerie"] if user_type == UserType.couple else ["wellness"],
                age_min=28,
                age_max=48,
                visits=visits,
                participation_points=42,
            )
            self.users[user.id] = user
            self.profiles[profile.id] = profile
            for _ in range(count):
                self.ratings.append(
                    RatingPublic(
                        id=str(uuid4()),
                        target_profile_id=profile.id,
                        score=score,
                        interaction_type="chat",
                        created_at=datetime.now(UTC) - timedelta(days=count),
                    )
                )
        self.forum_posts = [
            ForumPost(
                id=str(uuid4()),
                author="Luna & Marco",
                title="Como preparar una primera quedada comoda",
                topic="Primeros pasos",
                points=88,
                replies=12,
                created_at=datetime.now(UTC) - timedelta(days=2),
            ),
            ForumPost(
                id=str(uuid4()),
                author="Iris",
                title="Ideas para eventos virtuales cuidados",
                topic="Eventos",
                points=52,
                replies=6,
                created_at=datetime.now(UTC) - timedelta(days=1),
            ),
        ]

    def create_user(self, payload: UserCreate) -> UserPublic:
        if any(user.email == payload.email for user in self.users.values()):
            raise ValueError("email_taken")
        age = (date.today() - payload.birth_date).days // 365
        if age < 18:
            raise ValueError("adult_only")
        user = UserRecord(
            id=str(uuid4()),
            email=payload.email,
            password_hash=hash_password(payload.password),
            display_name=payload.display_name,
            user_type=payload.user_type,
            birth_date=payload.birth_date,
        )
        profile = ProfileRecord(id=str(uuid4()), user_id=user.id)
        self.users[user.id] = user
        self.profiles[profile.id] = profile
        return self.to_user_public(user)

    def authenticate(self, email: str, password: str) -> UserPublic | None:
        user = next((item for item in self.users.values() if item.email == email), None)
        if not user or not verify_password(password, user.password_hash):
            return None
        return self.to_user_public(user)

    def to_user_public(self, user: UserRecord) -> UserPublic:
        return UserPublic(
            id=user.id,
            email=user.email,
            display_name=user.display_name,
            user_type=user.user_type,
            is_premium=user.is_premium,
            created_at=user.created_at,
        )

    def get_profile_for_user(self, user_id: str) -> ProfilePublic:
        profile = next(item for item in self.profiles.values() if item.user_id == user_id)
        return self.to_profile_public(profile)

    def update_profile(self, user_id: str, payload: ProfileUpdate) -> ProfilePublic:
        profile = next(item for item in self.profiles.values() if item.user_id == user_id)
        for key, value in payload.model_dump(exclude_unset=True).items():
            setattr(profile, key, value)
        return self.to_profile_public(profile)

    def to_profile_public(self, profile: ProfileRecord) -> ProfilePublic:
        user = self.users[profile.user_id]
        scores = [rating.score for rating in self.ratings if rating.target_profile_id == profile.id]
        average = calculate_average_score(scores)
        rating_count = len(scores)
        completion = profile_completion_score(profile.__dict__)
        return ProfilePublic(
            id=profile.id,
            user_id=user.id,
            display_name=user.display_name,
            user_type=user.user_type,
            headline=profile.headline,
            location=profile.location,
            latitude=profile.latitude,
            longitude=profile.longitude,
            orientation=profile.orientation,
            interests=profile.interests,
            fetishes=profile.fetishes,
            age_min=profile.age_min,
            age_max=profile.age_max,
            profile_progress=completion,
            average_score=average,
            reputation_level=reputation_level(average, rating_count),
            badges=assign_badges(average, rating_count, user.is_premium, profile.participation_points),
            visits=profile.visits,
            is_verified=user.is_verified,
            is_premium=user.is_premium,
        )

    def add_rating(self, payload: RatingCreate, multiplier: float) -> RatingPublic:
        target = self.profiles.get(payload.target_profile_id)
        if not target:
            raise ValueError("profile_not_found")
        score = min(5.0, payload.score * multiplier if payload.is_super_score else float(payload.score))
        rating = RatingPublic(
            id=str(uuid4()),
            target_profile_id=target.id,
            score=round(score, 2),
            interaction_type=payload.interaction_type,
            created_at=datetime.now(UTC),
        )
        self.ratings.append(rating)
        return rating

    def search_profiles(self, filters: SearchFilters, default_min_score: float) -> list[ProfilePublic]:
        min_score = filters.min_score if filters.min_score is not None else default_min_score
        profiles = [self.to_profile_public(profile) for profile in self.profiles.values()]
        results = [profile for profile in profiles if profile.average_score >= min_score]
        if filters.location:
            results = [profile for profile in results if filters.location.lower() in (profile.location or "").lower()]
        if filters.orientation:
            results = [profile for profile in results if profile.orientation == filters.orientation]
        if filters.user_type:
            results = [profile for profile in results if profile.user_type == filters.user_type]
        if filters.fetishes:
            required = set(filters.fetishes)
            results = [profile for profile in results if required.issubset(set(profile.fetishes))]
        return sorted(results, key=lambda item: item.average_score, reverse=True)

    def reputation_history(self, profile_id: str) -> list[dict[str, float | str]]:
        ratings = [rating for rating in self.ratings if rating.target_profile_id == profile_id]
        recent = ratings[-8:]
        return [
            {"label": f"R{i + 1}", "average_score": calculate_average_score([r.score for r in recent[: i + 1]])}
            for i in range(len(recent))
        ]

    def create_event(self, user_id: str, payload: EventCreate) -> EventPublic:
        event = EventPublic(id=str(uuid4()), created_by=user_id, rsvp_count=0, **payload.model_dump())
        self.events[event.id] = event
        return event

    def rsvp_event(self, event_id: str) -> EventPublic:
        event = self.events.get(event_id)
        if not event:
            raise ValueError("event_not_found")
        event.rsvp_count += 1
        return event

    def most_viewed_couples(self) -> list[MostViewedCouple]:
        couples = [
            self.to_profile_public(profile)
            for profile in self.profiles.values()
            if self.users[profile.user_id].user_type == UserType.couple
        ]
        ranked = sorted(couples, key=lambda item: item.visits, reverse=True)
        return [
            MostViewedCouple(
                couple_name=profile.display_name,
                average_score=profile.average_score,
                visits=profile.visits,
                current_badge=profile.badges[-1].label if profile.badges else "Sin badge",
            )
            for profile in ranked[:5]
        ]

    def analytics(self) -> AnalyticsSummary:
        return AnalyticsSummary(clicks=482, views=2360, gifts_sent=37, reputation_percentile=91)


store = DemoStore()
