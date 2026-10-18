"""Strict, bounded JSON validation; SQLAlchemy binds query parameters."""

import re
from datetime import datetime, timezone

from email_validator import EmailNotValidError, validate_email
from flask import request

from .errors import invalid


def body(allowed, required=()):
    if not request.is_json:
        invalid("A JSON object is required.")
    value = request.get_json(silent=True)
    if not isinstance(value, dict) or not value:
        invalid("A non-empty JSON object is required.")
    unknown = set(value) - set(allowed)
    if unknown:
        invalid("Unexpected fields: " + ", ".join(sorted(unknown)))
    for key in required:
        if key not in value:
            invalid(f"{key} is required.")
    return value


def text(value, name, maximum=255):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        invalid(f"{name} must be non-empty text of at most {maximum} characters.")
    if any(ord(c) < 32 and c not in "\n\t" for c in value):
        invalid(f"{name} contains unsupported control characters.")
    return value.strip()


def choice(value, name, allowed):
    if not isinstance(value, str) or value not in allowed:
        invalid(f"{name} must be one of: {', '.join(allowed)}.")
    return value


def positive_id(value, name="id", nullable=False):
    if nullable and value is None:
        return None
    if type(value) is not int or value < 1 or value > 2147483647:
        invalid(f"{name} must be a positive integer.")
    return value


def email(value):
    try:
        return validate_email(text(value, "email", 254), check_deliverability=False).normalized.lower()
    except EmailNotValidError:
        invalid("email must have a valid format.")


def username(value):
    value = text(value, "username", 64).lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{2,63}", value):
        invalid("username must be 3-64 letters, numbers, dots, underscores or hyphens; start with a letter or number.")
    return value


def password(value):
    if (not isinstance(value, str) or not 12 <= len(value) <= 128
            or not re.search(r"[a-z]", value) or not re.search(r"[A-Z]", value)
            or not re.search(r"[0-9]", value) or not re.search(r"[^a-zA-Z0-9\s]", value)):
        invalid("password must be 12-128 characters with uppercase, lowercase, number and symbol.")
    return value


def utcnow():
    return datetime.now(timezone.utc)


def iso(value):
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z") if value else None


def timestamp(value, name):
    try:
        parsed = datetime.fromisoformat(text(value, name, 40).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError()
        return parsed.astimezone(timezone.utc)
    except ValueError:
        invalid(f"{name} must be an ISO 8601 timestamp with a timezone.")
