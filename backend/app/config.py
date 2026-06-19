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
    llm_provider: str = "groq"  # groq | gemini | openai
    groq_api_key: str = ""
    groq_model: str = "llama-3.3-70b-versatile"
    gemini_api_key: str = ""
    gemini_model: str = "gemini-2.0-flash-lite"
    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"
    openai_base_url: str = "https://api.openai.com/v1"

    class Config:
        env_file = (ROOT_DIR / ".env", Path(__file__).resolve().parent.parent / ".env")
        extra = "ignore"

    @property
    def cors_origin_list(self) -> list[str]:
        extras = [o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()]
        merged: list[str] = []
        seen: set[str] = set()
        for origin in [*self.cors_origins, *extras]:
            if origin not in seen:
                seen.add(origin)
                merged.append(origin)
        return merged

    @property
    def openai_compat_api_key(self) -> str:
        if self.llm_provider == "groq":
            return self.groq_api_key
        return self.openai_api_key

    @property
    def openai_compat_base_url(self) -> str:
        if self.llm_provider == "groq":
            return "https://api.groq.com/openai/v1"
        return self.openai_base_url

    @property
    def openai_compat_model(self) -> str:
        if self.llm_provider == "groq":
            return self.groq_model
        return self.openai_model

    @property
    def ai_model_name(self) -> str:
        if self.llm_provider == "gemini":
            return self.gemini_model
        return self.openai_compat_model

    @property
    def ai_configured(self) -> bool:
        if self.llm_provider == "groq":
            return bool(self.groq_api_key.strip())
        if self.llm_provider == "openai":
            return bool(self.openai_api_key.strip())
        return bool(self.gemini_api_key.strip())

    @property
    def is_production(self) -> bool:
        return os.getenv("FITLIFE_ENV", "development") == "production"


settings = Settings()

if settings.is_production and settings.secret_key == "fitlife-dev-secret-change-in-production":
    raise RuntimeError("Set SECRET_KEY in production — default dev key is not allowed.")
