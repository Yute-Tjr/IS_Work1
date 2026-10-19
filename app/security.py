"""Password hashing and JWT helpers."""
from datetime import datetime, timezone

import bcrypt
import jwt
from flask import current_app

# bcrypt only uses the first 72 bytes of a password; longer input is rejected instead
BCRYPT_MAX_BYTES = 72

# Hash compared against when the username does not exist, so a login for an unknown
# user takes as long as one with a wrong password (prevents user enumeration by timing).
_DUMMY_HASH = bcrypt.hashpw(b"dummy-password-for-timing", bcrypt.gensalt()).decode()


def hash_password(password):
    rounds = current_app.config["BCRYPT_ROUNDS"]
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=rounds)).decode()


def verify_password(password, password_hash):
    candidate = password.encode("utf-8")
    if len(candidate) > BCRYPT_MAX_BYTES:
        return False
    return bcrypt.checkpw(candidate, password_hash.encode("utf-8"))


def burn_password_check(password):
    """Run a bcrypt comparison that always fails, to keep response time constant."""
    verify_password(password, _DUMMY_HASH)


def create_access_token(user):
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user.id),
        "username": user.username,
        "iat": now,
        "exp": now + current_app.config["JWT_EXPIRES"],
    }
    return jwt.encode(
        payload,
        current_app.config["JWT_SECRET_KEY"],
        algorithm=current_app.config["JWT_ALGORITHM"],
    )


def decode_access_token(token):
    """Verify signature, expiry and required claims. Raises jwt.InvalidTokenError on failure."""
    return jwt.decode(
        token,
        current_app.config["JWT_SECRET_KEY"],
        # Pin the algorithm: tokens with "alg": "none" or another algorithm are rejected
        algorithms=[current_app.config["JWT_ALGORITHM"]],
        options={"require": ["sub", "iat", "exp"]},
    )
