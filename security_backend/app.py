"""Application factory: run one service per process, sharing only contracts."""

import json
import math
import os
from datetime import timedelta

from dotenv import load_dotenv
from flask import Flask, g, jsonify, request
from flask_jwt_extended import JWTManager
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError, OperationalError, SQLAlchemyError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.exc import StaleDataError
from werkzeug.exceptions import HTTPException

from .shared.audit import audit_denial, drain_outbox
from .shared.errors import APIError


def create_app(service, overrides=None):
    if service not in ("users", "logs", "playbooks"):
        raise ValueError("Choose users, logs, or playbooks.")
    load_dotenv()
    app = Flask(__name__)
    app.config.update(
        SERVICE_NAME=service, DATABASE_URL=os.getenv("DATABASE_URL", ""),
        API_PREFIX=os.getenv("API_PREFIX", "/api/natalio-hassoun"),
        JWT_SECRET_KEY=os.getenv("JWT_SECRET_KEY", ""),
        JWT_ENCODE_ISSUER=os.getenv("JWT_ENCODE_ISSUER", "security-sprint1-users"),
        JWT_DECODE_ISSUER=os.getenv("JWT_DECODE_ISSUER", "security-sprint1-users"),
        JWT_ENCODE_AUDIENCE=os.getenv("JWT_ENCODE_AUDIENCE", "security-sprint1-services"),
        JWT_DECODE_AUDIENCE=os.getenv("JWT_DECODE_AUDIENCE", "security-sprint1-services"),
        SERVICE_TOKENS=json.loads(os.getenv("SERVICE_TOKENS", "{}")),
        USERS_URL=os.getenv("USERS_URL", "http://127.0.0.1:8001").rstrip("/"),
        LOGS_URL=os.getenv("LOGS_URL", "http://127.0.0.1:8005").rstrip("/"),
        SERVICE_TIMEOUT=float(os.getenv("SERVICE_TIMEOUT", "3")),
        JWT_ACCESS_TOKEN_EXPIRES=timedelta(minutes=30), JWT_ALGORITHM="HS256",
        JWT_DECODE_ALGORITHMS=["HS256"],
        JWT_TOKEN_LOCATION=["headers"], MAX_CONTENT_LENGTH=64 * 1024,
    )
    app.config.update(overrides or {})
    for suffix in ("ISSUER", "AUDIENCE"):
        encode = app.config["JWT_ENCODE_" + suffix]
        decode = app.config["JWT_DECODE_" + suffix]
        if not isinstance(encode, str) or not encode.strip() or encode != decode:
            raise ValueError("JWT encode/decode issuer and audience must be nonempty matching strings.")
    if (not math.isfinite(app.config["SERVICE_TIMEOUT"])
            or not 0 < app.config["SERVICE_TIMEOUT"] <= 5):
        raise ValueError("SERVICE_TIMEOUT must be greater than zero and at most five seconds.")
    secret = app.config["JWT_SECRET_KEY"]
    tokens = app.config["SERVICE_TOKENS"]
    if len(secret) < 32 or "CHANGE_ME" in secret:
        raise ValueError("Set a random JWT_SECRET_KEY of at least 32 characters.")
    if not all(name in tokens for name in ("users", "logs", "playbooks")):
        raise ValueError("SERVICE_TOKENS must include users, logs and playbooks.")
    if (any(not isinstance(value, str) or len(value) < 32 or "CHANGE_ME" in value
            for value in tokens.values()) or len(set(tokens.values())) != len(tokens)
            or secret in tokens.values()):
        raise ValueError("Use distinct random service keys of at least 32 characters, separate from JWT_SECRET_KEY.")
    if not app.config["DATABASE_URL"].startswith("postgresql+psycopg://"):
        raise ValueError("DATABASE_URL must use PostgreSQL with the psycopg driver.")
    prefix = app.config["API_PREFIX"].rstrip("/")
    if not prefix.startswith("/api/") or "natalio-hassoun" not in prefix.split("/"):
        raise ValueError("API_PREFIX must start /api/ and include natalio-hassoun.")
    app.config["API_PREFIX"] = prefix
    engine = create_engine(app.config["DATABASE_URL"], pool_pre_ping=True,
                           connect_args={"connect_timeout": 3})
    app.extensions["engine"] = engine
    app.extensions["session_factory"] = sessionmaker(engine, expire_on_commit=False)
    jwt = JWTManager(app)

    @app.before_request
    def open_session():
        g.db = app.extensions["session_factory"]()
        g.audit_needed = False

    def handle_api_error(error):
        if hasattr(g, "db"):
            g.db.rollback()
        if error.status in (401, 403):
            try:
                audit_denial()
            except SQLAlchemyError:
                return jsonify(status="error", code="AUDIT_STORAGE_UNAVAILABLE",
                               message="The request was rejected; audit storage is unavailable."), 503
        return jsonify(status="error", code=error.code, message=error.message), error.status

    app.register_error_handler(APIError, handle_api_error)

    @jwt.unauthorized_loader
    def missing_token(reason):
        return handle_api_error(APIError(401, "AUTHENTICATION_REQUIRED", "A valid Bearer token is required."))

    @jwt.invalid_token_loader
    def invalid_token(reason):
        return handle_api_error(APIError(401, "INVALID_TOKEN", "The token is invalid."))

    @jwt.expired_token_loader
    def expired_token(header, payload):
        return handle_api_error(APIError(401, "TOKEN_EXPIRED", "The token has expired."))

    @app.errorhandler(IntegrityError)
    def conflict(error):
        return handle_api_error(APIError(409, "CONFLICT", "A unique value conflicts or a referenced record is unavailable."))

    @app.errorhandler(StaleDataError)
    def stale(error):
        return handle_api_error(APIError(409, "CONCURRENT_UPDATE", "The record changed; retrieve it and retry."))

    @app.errorhandler(OperationalError)
    def unavailable(error):
        return handle_api_error(APIError(503, "DATABASE_UNAVAILABLE", "The database is unavailable."))

    @app.errorhandler(HTTPException)
    def http_error(error):
        return handle_api_error(APIError(error.code, error.name.upper().replace(" ", "_"), error.description))

    @app.errorhandler(Exception)
    def unexpected(error):
        # Deliberately avoid logging exception strings that could include SQL parameters.
        app.logger.error("Unhandled exception type: %s", type(error).__name__)
        return handle_api_error(APIError(500, "INTERNAL_ERROR", "An unexpected error occurred."))

    @app.after_request
    def deliver_audit(response):
        if hasattr(g, "db"):
            g.db.close()
        if getattr(g, "audit_needed", False):
            try:
                # Keep request latency bounded even when a backlog exists.
                # Explicit flush commands process larger batches after commit.
                pending = drain_outbox(limit=10)
                delivery = {"status": "pending" if pending else "delivered", "pending_events": pending}
            except SQLAlchemyError:
                delivery = {"status": "pending", "message": "Retry audit delivery with flush-audit."}
            if response.is_json:
                value = response.get_json()
                value["audit_delivery"] = delivery
                response.set_data(app.json.dumps(value))
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.teardown_request
    def close_session(error):
        if hasattr(g, "db"):
            g.db.close()

    @app.get(prefix + "/health")
    def health():
        from sqlalchemy import text
        g.db.execute(text("SELECT 1"))
        return jsonify(status="success", data={"service": service})

    from . import logs, playbooks, users
    app.register_blueprint({"users": users.bp, "logs": logs.bp, "playbooks": playbooks.bp}[service],
                           url_prefix=prefix)
    return app


def success(data, status=200, commit=False):
    if commit:
        g.db.commit()
        g.audit_needed = True
    return jsonify(status="success", data=data), status
