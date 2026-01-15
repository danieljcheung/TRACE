from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    APP_NAME: str = "TRACE"
    VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True

    HOST: str = "0.0.0.0"
    PORT: int = 8000

    CORS_ORIGINS: list[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5500",
        "http://localhost:5500",
    ]

    RESEND_API_KEY: Optional[str] = None
    EMAIL_FROM: str = "TRACE <noreply@trace.dev>"

    VERIFICATION_CODE_LENGTH: int = 6
    VERIFICATION_CODE_EXPIRY_SECONDS: int = 300  # 5 min
    VERIFICATION_MAX_ATTEMPTS: int = 5
    VERIFICATION_LOCKOUT_SECONDS: int = 900  # 15 min

    RATE_LIMIT_VERIFY_PER_HOUR: int = 10
    RATE_LIMIT_SCAN_COOLDOWN_HOURS: int = 24

    SCAN_TIMEOUT_SECONDS: int = 90

    GITHUB_TOKEN: Optional[str] = None
    HIBP_API_KEY: Optional[str] = None

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()
