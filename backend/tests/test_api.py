from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from app.main import app
from app.services.store import store


client = TestClient(app)


def login_demo(email: str = "luna@example.com") -> str:
    response = client.post("/api/v1/auth/login", json={"email": email, "password": "SwinraDemo1"})
    assert response.status_code == 200
    return response.json()["access_token"]


def test_register_and_profile_progress() -> None:
    store.reset()
    response = client.post(
        "/api/v1/auth/register",
        json={
            "email": "new@example.com",
            "password": "SwinraDemo1",
            "display_name": "New Duo",
            "user_type": "couple",
            "birth_date": "1991-04-10",
        },
    )
    assert response.status_code == 201
    token = response.json()["access_token"]

    profile = client.patch(
        "/api/v1/profiles/me",
        headers={"Authorization": f"Bearer {token}"},
        json={"headline": "Hola", "location": "Madrid", "interests": ["events"]},
    )
    assert profile.status_code == 200
    assert profile.json()["profile_progress"] >= 50


def test_matching_uses_min_score_threshold() -> None:
    store.reset()
    response = client.get("/api/v1/matching/search?min_score=4.8")
    assert response.status_code == 200
    assert all(profile["average_score"] >= 4.8 for profile in response.json())


def test_verified_rating_comment_appears_as_profile_review() -> None:
    store.reset()
    target = client.get("/api/v1/matching/search?min_score=4.8").json()[0]
    rating = client.post(
        "/api/v1/reputation/ratings",
        json={
            "target_profile_id": target["id"],
            "interaction_type": "in_person",
            "score": 5,
            "comment": "Comunicacion clara y experiencia muy cuidada.",
        },
    )
    assert rating.status_code == 201

    reviews = client.get(f"/api/v1/profiles/{target['id']}/reviews")
    assert reviews.status_code == 200
    assert reviews.json()[0]["is_verified_interaction"] is True
    assert reviews.json()[0]["comment"] == "Comunicacion clara y experiencia muy cuidada."


def test_premium_most_viewed_requires_premium() -> None:
    store.reset()
    basic_token = login_demo("iris@example.com")
    blocked = client.get(
        "/api/v1/premium/most-viewed-couples",
        headers={"Authorization": f"Bearer {basic_token}"},
    )
    assert blocked.status_code == 403

    premium_token = login_demo("luna@example.com")
    allowed = client.get(
        "/api/v1/premium/most-viewed-couples",
        headers={"Authorization": f"Bearer {premium_token}"},
    )
    assert allowed.status_code == 200
    assert allowed.json()[0]["visits"] >= allowed.json()[-1]["visits"]


def test_event_rsvp_flow() -> None:
    store.reset()
    token = login_demo()
    starts_at = (datetime.now(UTC) + timedelta(days=7)).isoformat()
    created = client.post(
        "/api/v1/events",
        headers={"Authorization": f"Bearer {token}"},
        json={"title": "Velada Swinra", "mode": "virtual", "starts_at": starts_at},
    )
    assert created.status_code == 201
    event_id = created.json()["id"]

    rsvp = client.post(f"/api/v1/events/{event_id}/rsvp")
    assert rsvp.status_code == 200
    assert rsvp.json()["rsvp_count"] == 1
