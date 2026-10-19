import os
from datetime import timedelta


class Config:
    """Default configuration. Secrets come from environment variables, never from code."""

    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:///secure_api.db")

    # JWT settings (A07: Identification and Authentication Failures)
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY")
    JWT_ALGORITHM = "HS256"
    JWT_EXPIRES = timedelta(minutes=int(os.environ.get("JWT_EXPIRES_MINUTES", "30")))

    # bcrypt work factor: 2^12 rounds
    BCRYPT_ROUNDS = 12

    # Brute-force protection on /auth/* (Flask-Limiter)
    RATELIMIT_ENABLED = True
    RATELIMIT_STORAGE_URI = "memory://"
    RATELIMIT_HEADERS_ENABLED = True
    LOGIN_RATE_LIMIT = "5 per minute"

    # Reject request bodies larger than 16 KB
    MAX_CONTENT_LENGTH = 16 * 1024
