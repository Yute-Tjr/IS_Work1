"""Authentication endpoints and the JWT middleware that protects /api/*."""
import re

import jwt
from flask import Blueprint, current_app, g, jsonify, request

from .extensions import db, limiter
from .models import User
from .security import (
    BCRYPT_MAX_BYTES,
    burn_password_check,
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")
PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 64


def _login_rate_limit():
    return current_app.config["LOGIN_RATE_LIMIT"]


def _json_body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else None


def _credentials(data):
    username = data.get("username")
    password = data.get("password")
    if not isinstance(username, str) or not isinstance(password, str):
        return None, None
    return username, password


@auth_bp.post("/register")
@limiter.limit(_login_rate_limit)
def register():
    data = _json_body()
    if data is None:
        return jsonify(error="Request body must be a JSON object"), 400
    username, password = _credentials(data)
    if username is None:
        return jsonify(error="'username' and 'password' are required strings"), 400

    if not USERNAME_RE.fullmatch(username):
        return jsonify(error="Username must be 3-32 characters: letters, digits or underscore"), 400
    if not PASSWORD_MIN_LENGTH <= len(password) <= PASSWORD_MAX_LENGTH:
        return jsonify(
            error=f"Password must be {PASSWORD_MIN_LENGTH}-{PASSWORD_MAX_LENGTH} characters"
        ), 400
    if len(password.encode("utf-8")) > BCRYPT_MAX_BYTES:
        return jsonify(error=f"Password must not exceed {BCRYPT_MAX_BYTES} bytes"), 400

    # ORM query: the username is sent as a bound parameter, never concatenated into SQL
    if db.session.execute(db.select(User).filter_by(username=username)).scalar_one_or_none():
        return jsonify(error="Username already taken"), 409

    user = User(username=username, password_hash=hash_password(password))
    db.session.add(user)
    db.session.commit()
    return jsonify(id=user.id, username=user.username), 201


@auth_bp.post("/login")
@limiter.limit(_login_rate_limit)
def login():
    data = _json_body()
    if data is None:
        return jsonify(error="Request body must be a JSON object"), 400
    username, password = _credentials(data)
    if username is None:
        return jsonify(error="'username' and 'password' are required strings"), 400

    user = db.session.execute(db.select(User).filter_by(username=username)).scalar_one_or_none()
    if user is None:
        burn_password_check(password)
        return jsonify(error="Invalid username or password"), 401
    if not verify_password(password, user.password_hash):
        return jsonify(error="Invalid username or password"), 401

    expires_in = int(current_app.config["JWT_EXPIRES"].total_seconds())
    # "Bearer" is the token type name (RFC 6750), not a secret: Bandit B106 false positive
    return jsonify(
        access_token=create_access_token(user),
        token_type="Bearer",  # nosec B106
        expires_in=expires_in,
    )


def _unauthorized(message):
    response = jsonify(error=message)
    response.status_code = 401
    response.headers["WWW-Authenticate"] = 'Bearer realm="api"'
    return response


def require_jwt():
    """Middleware: runs before every request to a protected blueprint.

    Expects "Authorization: Bearer <token>". On success the authenticated user is
    stored in flask.g.current_user; otherwise the request is stopped with 401.
    """
    scheme, _, token = request.headers.get("Authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not token:
        return _unauthorized("Missing or malformed Authorization header")

    try:
        payload = decode_access_token(token)
        user_id = int(payload["sub"])
    except jwt.ExpiredSignatureError:
        return _unauthorized("Token has expired")
    except (jwt.InvalidTokenError, ValueError):
        return _unauthorized("Invalid token")

    user = db.session.get(User, user_id)
    if user is None:
        return _unauthorized("Invalid token")
    g.current_user = user
    return None
