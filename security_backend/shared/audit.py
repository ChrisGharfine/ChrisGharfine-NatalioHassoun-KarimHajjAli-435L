"""Atomic local outbox + idempotent delivery prevents silent audit loss."""

import uuid

from flask import current_app, g, request
from sqlalchemy import select

from ..models import PlaybooksOutbox, UsersOutbox
from .clients import log_event
from .errors import APIError
from .validation import utcnow


def outbox_type():
    return UsersOutbox if current_app.config["SERVICE_NAME"] == "users" else PlaybooksOutbox


def record_event(session, action, description, user_id=None, severity="Information"):
    payload = {"user_id": user_id, "action": action, "description": description,
               "severity": severity, "related_service": current_app.config["SERVICE_NAME"]}
    if current_app.config["SERVICE_NAME"] == "logs":
        from ..logs import insert_event
        insert_event(session, payload, "logs", str(uuid.uuid4()))
    else:
        session.add(outbox_type()(id=str(uuid.uuid4()), payload=payload))


def drain_outbox(limit=100):
    if current_app.config["SERVICE_NAME"] == "logs":
        return 0
    model = outbox_type()
    factory = current_app.extensions["session_factory"]
    with factory() as session:
        rows = session.scalars(select(model).where(model.delivered_at.is_(None))
                               .order_by(model.created_at).limit(limit).with_for_update(skip_locked=True)).all()
        for row in rows:
            row.attempts += 1
            try:
                log_event(row.payload, row.id)
                row.delivered_at = utcnow()
                row.last_error = None
            except APIError as exc:
                row.last_error = exc.code
                break
        session.commit()
        return len(session.scalars(select(model.id).where(model.delivered_at.is_(None))).all())


def audit_denial(message="Protected request rejected."):
    """Separate transaction: a failed request must still leave an audit event."""
    factory = current_app.extensions["session_factory"]
    with factory() as session:
        route = request.url_rule.rule if request.url_rule else "unmatched route"
        record_event(session, "unauthorized_access", f"{request.method} {route}: {message}",
                     user_id=getattr(g, "actor", {}).get("id"), severity="Warning")
        session.commit()
    g.audit_needed = True
