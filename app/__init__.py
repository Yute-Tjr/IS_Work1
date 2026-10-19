"""Secure Notes API: a small Flask REST API built against the OWASP Top 10."""
import secrets

from flask import Flask, jsonify
from werkzeug.exceptions import HTTPException

from .config import Config
from .extensions import db, limiter

MIN_SECRET_LENGTH = 32


def create_app(config_overrides=None):
    app = Flask(__name__)
    app.config.from_object(Config)
    if config_overrides:
        app.config.update(config_overrides)

    _configure_secret(app)

    db.init_app(app)
    limiter.init_app(app)

    from .api import api_bp
    from .auth import auth_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(api_bp)

    _register_index(app)
    _register_security_headers(app)
    _register_error_handlers(app)

    with app.app_context():
        db.create_all()
    return app


def _configure_secret(app):
    secret = app.config.get("JWT_SECRET_KEY")
    if not secret:
        app.config["JWT_SECRET_KEY"] = secrets.token_urlsafe(64)
        app.logger.warning(
            "JWT_SECRET_KEY is not set; using a random key. Issued tokens stop working on restart."
        )
    elif len(secret) < MIN_SECRET_LENGTH:
        raise RuntimeError(f"JWT_SECRET_KEY must be at least {MIN_SECRET_LENGTH} characters long")


def _register_index(app):
    @app.get("/")
    def index():
        return jsonify(
            name="Secure Notes API",
            endpoints=[
                "POST /auth/register",
                "POST /auth/login",
                "GET /api/data",
                "POST /api/data",
                "DELETE /api/data/<id>",
            ],
        )


def _register_security_headers(app):
    @app.after_request
    def set_security_headers(response):
        # The API only serves JSON: forbid MIME sniffing, framing and any active content
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response


def _register_error_handlers(app):
    @app.errorhandler(HTTPException)
    def handle_http_error(error):
        # JSON errors instead of HTML pages; 429 keeps Flask-Limiter's Retry-After header
        response = error.get_response()
        response.data = jsonify(error=error.description).get_data()
        response.content_type = "application/json"
        return response

    @app.errorhandler(Exception)
    def handle_unexpected_error(error):
        # Log the details server-side, but never leak stack traces to the client
        app.logger.exception("Unhandled error: %s", error)
        return jsonify(error="Internal server error"), 500
