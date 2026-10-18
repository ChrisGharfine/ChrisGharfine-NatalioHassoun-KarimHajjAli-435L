"""Append-only logs, service-authenticated ingestion and stable deduplication."""

import hashlib
import json
import re
import uuid
from datetime import date, datetime, time, timedelta, timezone

from flask import Blueprint, g, request
from sqlalchemy import select

from .app import success
from .models import Log, LogReceipt
from .shared import validation as v
from .shared.audit import record_event
from .shared.auth import protected, service_auth
from .shared.clients import call_users
from .shared.constants import ADMIN, ANALYST, AUDITOR, LOG_SEVERITIES
from .shared.errors import APIError, missing

bp = Blueprint("logs", __name__)
FIELDS = ("user_id", "action", "description", "severity", "related_service")


def validate_payload(data):
    payload = {"user_id": v.positive_id(data["user_id"], "user_id", nullable=True),
               "action": v.text(data["action"], "action", 100),
               "description": v.text(data["description"], "description", 2000),
               "severity": v.choice(data["severity"], "severity", LOG_SEVERITIES),
               "related_service": v.text(data["related_service"], "related_service", 64)}
    if not re.fullmatch(r"[a-z][a-z0-9_]*", payload["action"]):
        v.invalid("action must use lowercase letters, digits and underscores.")
    # Free text still needs caller discipline. Reject obvious accidental secret payloads.
    if re.search(r"(?i)(bearer\s+|password\s*[:=]|access_token\s*[:=]|eyJ[A-Za-z0-9_-]+\.)", payload["description"]):
        v.invalid("description must not contain credentials or tokens.")
    return payload


def insert_event(session, payload, source, event_id):
    fingerprint = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    receipt = session.get(LogReceipt, event_id)
    if receipt:
        if receipt.source_service != source or receipt.payload_hash != fingerprint:
            raise APIError(409, "IDEMPOTENCY_CONFLICT", "The event ID was already used for a different event.")
        return session.get(Log, receipt.log_id) if receipt.log_id else None, False
    log = Log(**payload, source_service=source, event_id=event_id)
    session.add(log)
    session.flush()
    session.add(LogReceipt(event_id=event_id, source_service=source,
                           payload_hash=fingerprint, log_id=log.id))
    return log, True


@bp.post("/internal/logs")
def ingest():
    source = service_auth()
    payload = validate_payload(v.body(FIELDS, FIELDS))
    try:
        event_id = str(uuid.UUID(request.headers.get("Idempotency-Key", "")))
    except ValueError:
        v.invalid("Idempotency-Key must be a UUID; retain it for retries.")
    if payload["related_service"] != source:
        v.invalid("related_service must match the authenticated source service.")
    # Short-circuit exact retries before calling Users (including after log deletion).
    receipt = g.db.get(LogReceipt, event_id)
    if receipt is None and payload["user_id"] is not None:
        call_users(f"/internal/users/{payload['user_id']}")
    log, created = insert_event(g.db, payload, source, event_id)
    g.db.commit()
    return success({"event_id": event_id, "log": log.public() if log else None,
                    "duplicate": not created}, 201 if created else 200)


@bp.post("/logs")
@protected(ADMIN)
def create_log():
    payload = validate_payload(v.body(FIELDS, FIELDS))
    if payload["user_id"] != g.actor["id"]:
        raise APIError(403, "FORBIDDEN", "Manual records must identify the authenticated administrator as actor.")
    log, _ = insert_event(g.db, payload, "logs", str(uuid.uuid4()))
    return success(log.public(), 201, commit=True)


@bp.get("/logs")
@protected(ADMIN, AUDITOR)
def list_logs():
    return success([log.public() for log in g.db.scalars(select(Log).order_by(Log.id))])


@bp.get("/logs/<int:log_id>")
@protected(ADMIN, AUDITOR, ANALYST)
def retrieve_log(log_id):
    log = g.db.get(Log, log_id)
    if not log:
        missing("Log")
    return success(log.public())


@bp.get("/logs/search")
@protected(ADMIN, AUDITOR, ANALYST)
def search_logs():
    allowed = {"user_id", "date", "action", "severity", "related_service"}
    if set(request.args) - allowed:
        v.invalid("Unsupported search parameter.")
    query = select(Log)
    for key in ("action", "severity", "related_service"):
        if key in request.args:
            value = v.text(request.args[key], key, 100)
            if key == "severity":
                v.choice(value, key, LOG_SEVERITIES)
            query = query.where(getattr(Log, key) == value)
    if "user_id" in request.args:
        try:
            user_id = int(request.args["user_id"])
        except ValueError:
            v.invalid("user_id must be a positive integer.")
        query = query.where(Log.user_id == v.positive_id(user_id, "user_id"))
    if "date" in request.args:
        try:
            day = date.fromisoformat(request.args["date"])
            start = datetime.combine(day, time.min, timezone.utc)
            end = start + timedelta(days=1)
        except (ValueError, OverflowError):
            v.invalid("date must be YYYY-MM-DD in UTC.")
        query = query.where(Log.timestamp >= start, Log.timestamp < end)
    return success([log.public() for log in g.db.scalars(query.order_by(Log.id))])


@bp.get("/logs/user/<int:user_id>")
@protected(ADMIN, AUDITOR)
def logs_by_user(user_id):
    return success([log.public() for log in g.db.scalars(select(Log).where(Log.user_id == user_id).order_by(Log.id))])


@bp.delete("/logs/<int:log_id>")
@protected(ADMIN)
def delete_log(log_id):
    log = g.db.get(Log, log_id)
    if not log:
        missing("Log")
    g.db.delete(log)
    record_event(g.db, "log_deleted", f"Administrator deleted log {log_id}.", g.actor["id"])
    return success({"id": log_id, "deleted": True}, commit=True)
