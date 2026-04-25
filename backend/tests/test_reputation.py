from app.services.reputation import assign_badges, calculate_average_score, profile_completion_score, reputation_level


def test_calculate_average_score_rounds_two_decimals() -> None:
    assert calculate_average_score([4.2, 4.8, 5.0]) == 4.67


def test_reputation_level_elite_requires_count_and_score() -> None:
    assert reputation_level(4.9, 20) == "elite"
    assert reputation_level(4.9, 2) == "new"


def test_assign_badges_includes_premium_and_fira_star() -> None:
    badges = assign_badges(4.8, 12, is_premium=True)
    codes = {badge.code for badge in badges}
    assert {"explorer", "veteran_swinger", "fira_star", "premium_star"}.issubset(codes)


def test_profile_completion_score_weights_profile_fields() -> None:
    assert profile_completion_score({"headline": "Hi", "interests": ["events"], "fetishes": []}) == 35
