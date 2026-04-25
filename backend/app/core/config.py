from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_brand_name: str = Field(default="Swinra", alias="APP_BRAND_NAME")
    api_prefix: str = "/api/v1"
    environment: str = Field(default="local", alias="ENVIRONMENT")
    database_url: str = Field(
        default="postgresql+psycopg://swinra:swinra@postgres:5432/swinra",
        alias="DATABASE_URL",
    )
    redis_url: str = Field(default="redis://redis:6379/0", alias="REDIS_URL")
    jwt_secret_key: str = Field(default="change-me-in-production", alias="JWT_SECRET_KEY")
    jwt_algorithm: str = "HS256"
    access_token_minutes: int = 45
    reputation_min_search_score: float = Field(default=3.5, alias="REPUTATION_MIN_SEARCH_SCORE")
    super_score_multiplier: float = Field(default=1.5, alias="SUPER_SCORE_MULTIPLIER")
    premium_features_enabled: bool = Field(default=True, alias="PREMIUM_FEATURES_ENABLED")
    cors_origins: list[str] = Field(default=["http://localhost:5173"], alias="CORS_ORIGINS")

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")


@lru_cache
def get_settings() -> Settings:
    return Settings()
