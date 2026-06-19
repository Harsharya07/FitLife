import os
from pathlib import Path

from pydantic_settings import BaseSettings

ROOT_DIR = Path(__file__).resolve().parent.parent.parent


class Settings(BaseSettings):
    secret_key: str = "fitlife-dev-secret-change-in-production"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    database_url: str = "fitness_site.db"
    cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]
    admin_username: str = "admin"

    # Rate limiting (AI endpoints)
    ai_rate_limit_requests: int = 20
    ai_rate_limit_window_seconds: int = 60

    # LLM — set in .env (project root or backend/)
    llm_provider: str = "gemini"  # gemini | openai
    gemini_api_key: str = ""
    gemini_model: str = "gemini-2.0-flash"
    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"
    openai_base_url: str = "https://api.openai.com/v1"

    class Config:
        env_file = (ROOT_DIR / ".env", Path(__file__).resolve().parent.parent / ".env")
        extra = "ignore"

    @property
    def ai_configured(self) -> bool:
        if self.llm_provider == "openai":
            return bool(self.openai_api_key.strip())
        return bool(self.gemini_api_key.strip())

    @property
    def is_production(self) -> bool:
        return os.getenv("FITLIFE_ENV", "development") == "production"


settings = Settings()

if settings.is_production and settings.secret_key == "fitlife-dev-secret-change-in-production":
    raise RuntimeError("Set SECRET_KEY in production — default dev key is not allowed.")
