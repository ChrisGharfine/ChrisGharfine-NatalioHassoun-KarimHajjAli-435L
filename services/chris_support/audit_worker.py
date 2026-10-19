"""Deliver durable audit events. Run separately from HTTP worker processes."""

import argparse
import json
import time
from datetime import timedelta
from uuid import UUID

import httpx
from sqlalchemy import func, select
from sqlalchemy.orm import sessionmaker

from .audit import AuditOutbox, OWNED_SERVICES, validate_payload, wire_payload
from .config import Settings
from .database import make_engine, utcnow

MAX_RECEIPT_BYTES = 65_536


def valid_receipt(body, status_code: int, event_id: str) -> bool:
    """Require a persisted receipt, including exact retries after log deletion."""
    if not isinstance(body, dict) or body.get("status") != "success":
        return False
    data = body.get("data")
    if not isinstance(data, dict) or not isinstance(data.get("event_id"), str):
        return False
    try:
        if UUID(data["event_id"]) != UUID(event_id):
            return False
    except (ValueError, TypeError, AttributeError):
        return False
    duplicate = data.get("duplicate")
    if type(duplicate) is not bool or duplicate != (status_code == 200):
        return False
    if status_code not in {200, 201} or "log" not in data:
        return False
    log = data["log"]
    if log is None:
        return status_code == 200 and duplicate
    return isinstance(log, dict) and type(log.get("id")) is int and log["id"] > 0


def _pending():
    return (
        AuditOutbox.delivered_at.is_(None), AuditOutbox.failed_at.is_(None),
        AuditOutbox.next_attempt_at <= utcnow(),
    )


def _freeze_payloads(session_factory, batch_size):
    # Commit before contacting Logs: a remote acceptance followed by a local
    # rollback/restart must still retry this exact normalized payload.
    with session_factory.begin() as session:
        records = session.scalars(
            select(AuditOutbox).where(*_pending(), AuditOutbox.transport_payload.is_(None))
            .order_by(AuditOutbox.created_at, AuditOutbox.id).limit(batch_size)
            .with_for_update(skip_locked=True)
        ).all()
        for record in records:
            try:
                UUID(record.id)
                record.transport_payload = wire_payload(
                    user_id=record.user_id, action=record.action,
                    description=record.description, severity=record.severity,
                    service=record.related_service,
                )
            except (ValueError, TypeError, AttributeError):
                record.failed_at = utcnow()
                record.last_error = "INVALID_LOCAL_PAYLOAD: operator review required"


def _post_event(client, settings, record, key):
    with client.stream(
        "POST", settings.audit_url + "/internal/logs",
        headers={
            "X-Service-Name": record.related_service, "X-Service-Key": key,
            "Idempotency-Key": record.id,
        }, json=record.transport_payload, timeout=settings.http_timeout_seconds,
        follow_redirects=False,
    ) as response:
        media_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if media_type != "application/json" and not media_type.endswith("+json"):
            return response.status_code, None
        content = bytearray()
        for chunk in response.iter_bytes():
            if len(content) + len(chunk) > MAX_RECEIPT_BYTES:
                return response.status_code, None
            content.extend(chunk)
        try:
            return response.status_code, json.loads(content)
        except (ValueError, UnicodeError, RecursionError):
            return response.status_code, None


def _failure_code(body):
    # Persist only local summaries, never an untrusted raw response body.
    if not isinstance(body, dict):
        return None
    if isinstance(body.get("error"), dict):
        return body["error"].get("code")
    return body.get("code")


def deliver_batch(session_factory, client, settings, *, batch_size=50) -> int:
    if type(batch_size) is not int or not 1 <= batch_size <= 1000:
        raise ValueError("batch_size must be between 1 and 1000")
    _freeze_payloads(session_factory, batch_size)
    delivered = 0
    with session_factory.begin() as session:
        records = session.scalars(
            select(AuditOutbox).where(*_pending(), AuditOutbox.transport_payload.is_not(None))
            .order_by(AuditOutbox.created_at, AuditOutbox.id)
            .limit(batch_size).with_for_update(skip_locked=True)
        ).all()
        for record in records:
            record.attempts += 1
            try:
                UUID(record.id)
                validate_payload(record.transport_payload)
                if record.transport_payload["related_service"] != record.related_service:
                    raise ValueError("Frozen service differs from original service")
            except (ValueError, TypeError, AttributeError):
                record.failed_at = utcnow()
                record.last_error = "INVALID_LOCAL_PAYLOAD: operator review required"
                continue
            try:
                key = settings.service_key(record.related_service)
            except ValueError:
                record.failed_at = utcnow()
                record.last_error = "SERVICE_CREDENTIAL_MISSING: configure key and explicitly retry"
                continue
            try:
                status, acknowledgment = _post_event(client, settings, record, key)
                if valid_receipt(acknowledgment, status, record.id):
                    record.delivered_at = utcnow()
                    record.last_error = None
                    delivered += 1
                    continue
                code = _failure_code(acknowledgment)
                if status == 409 and code == "IDEMPOTENCY_CONFLICT":
                    record.failed_at = utcnow()
                    record.last_error = "IDEMPOTENCY_CONFLICT: permanent; operator review required"
                elif 400 <= status < 500 and status not in {408, 409, 429}:
                    record.failed_at = utcnow()
                    record.last_error = f"HTTP_{status}: input/credentials rejected; explicitly retry after correction"
                else:
                    record.last_error = f"Audit acknowledgment rejected (HTTP {status})"
            except (httpx.HTTPError, ValueError, TypeError, AttributeError):
                record.last_error = "Audit request failed or acknowledgment was invalid"
            record.next_attempt_at = utcnow() + timedelta(seconds=min(300, 2 ** min(record.attempts, 9)))
    return delivered


def requeue_failed(session_factory, service: str) -> int:
    """Explicitly retry corrected input/credential errors, preserving the event."""
    if service not in OWNED_SERVICES:
        raise ValueError("A Chris-owned service is required")
    count = 0
    with session_factory.begin() as session:
        records = session.scalars(select(AuditOutbox).where(
            AuditOutbox.related_service == service, AuditOutbox.delivered_at.is_(None),
            AuditOutbox.failed_at.is_not(None),
        ).with_for_update(skip_locked=True)).all()
        for record in records:
            # A UUID bound to a different accepted event cannot be repaired by
            # retrying or silently changing that event's payload.
            if (record.last_error or "").startswith(("IDEMPOTENCY_CONFLICT", "INVALID_LOCAL_PAYLOAD")):
                continue
            record.failed_at = None
            record.last_error = None
            record.next_attempt_at = utcnow()
            count += 1
    return count


def queue_counts(session_factory):
    with session_factory() as session:
        pending = session.scalar(select(func.count()).select_from(AuditOutbox).where(
            AuditOutbox.delivered_at.is_(None), AuditOutbox.failed_at.is_(None),
        ))
        failed = session.scalar(select(func.count()).select_from(AuditOutbox).where(
            AuditOutbox.delivered_at.is_(None), AuditOutbox.failed_at.is_not(None),
        ))
    return pending, failed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--retry-failed", action="store_true",
                        help="Explicitly requeue corrected credential/input failures; preserves UUID and payload")
    parser.add_argument("--service", choices=sorted(OWNED_SERVICES),
                        help="Required with --retry-failed; never retries payload/idempotency conflicts")
    args = parser.parse_args()
    if args.retry_failed and not args.service:
        parser.error("--retry-failed requires --service")
    settings = Settings()
    engine = make_engine(settings.database_url)
    factory = sessionmaker(bind=engine)
    try:
        if args.retry_failed:
            print(f"Requeued {requeue_failed(factory, args.service)} corrected {args.service} events", flush=True)
        with httpx.Client(trust_env=False) as client:
            while True:
                count = deliver_batch(factory, client, settings)
                pending, failed = queue_counts(factory)
                print(f"Delivered {count} audit events; pending={pending}; failed={failed}", flush=True)
                if args.once:
                    return 1 if pending or failed else 0
                time.sleep(2)
    finally:
        engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
