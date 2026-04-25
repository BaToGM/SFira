from app.schemas import Badge


def calculate_average_score(scores: list[float]) -> float:
    if not scores:
        return 0.0
    return round(sum(scores) / len(scores), 2)


def reputation_level(average_score: float, rating_count: int) -> str:
    if rating_count >= 20 and average_score >= 4.8:
        return "elite"
    if rating_count >= 10 and average_score >= 4.5:
        return "star"
    if rating_count >= 5 and average_score >= 4.0:
        return "trusted"
    if rating_count > 0:
        return "new"
    return "unrated"


def assign_badges(
    average_score: float,
    rating_count: int,
    is_premium: bool,
    participation_points: int = 0,
) -> list[Badge]:
    badges: list[Badge] = []
    if rating_count >= 1 or participation_points >= 20:
        badges.append(Badge(code="explorer", label="Explorador", tone="soft"))
    if rating_count >= 8:
        badges.append(Badge(code="veteran_swinger", label="Veterano Swinger", tone="hot"))
    if rating_count >= 12 and average_score >= 4.6:
        badges.append(Badge(code="fira_star", label="Fira Star", tone="gold"))
    if is_premium:
        badges.append(Badge(code="premium_star", label="Premium Star", tone="gold"))
    if rating_count >= 20 and average_score >= 4.8:
        badges.append(Badge(code="elite_swinger", label="Elite Swinger", tone="elite"))
    return badges


def profile_completion_score(fields: dict[str, object]) -> int:
    weighted_fields = {
        "headline": 15,
        "location": 15,
        "orientation": 15,
        "interests": 20,
        "fetishes": 15,
        "age_min": 10,
        "age_max": 10,
    }
    score = 0
    for field, weight in weighted_fields.items():
        value = fields.get(field)
        if isinstance(value, list):
            score += weight if value else 0
        elif value not in (None, ""):
            score += weight
    return min(score, 100)
