"""Deliver durable audit events. Run separately from HTTP worker processes."""

import argparse
import time
from datetime import timedelta

import httpx
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from .audit import AuditOutbox
from .config import Settings
from .database import make_engine, utcnow


def deliver_batch(session_factory, client, settings, *, batch_size=50) -> int:
    token = settings.audit_service_token
    if token is None or not token.get_secret_value().strip():
        raise ValueError("CHRIS_AUDIT_SERVICE_TOKEN is required for audit delivery")
    delivered = 0
    with session_factory.begin() as session:
        records = session.scalars(
            select(AuditOutbox).where(
                AuditOutbox.delivered_at.is_(None), AuditOutbox.next_attempt_at <= utcnow(),
            ).order_by(AuditOutbox.created_at, AuditOutbox.id)
            .limit(batch_size).with_for_update(skip_locked=True)
        ).all()
        for record in records:
            record.attempts += 1
            try:
                response = client.post(
                    settings.audit_url + "/logs",
                    headers={
                        "Authorization": f"Bearer {token.get_secret_value()}",
                        "Idempotency-Key": record.id,
                    },
                    json={
                        "event_id": record.id, "user_id": record.user_id,
                        "action": record.action, "description": record.description,
                        "severity": record.severity, "related_service": record.related_service,
                        "timestamp": record.created_at.isoformat(),
                    }, timeout=settings.http_timeout_seconds, follow_redirects=False,
                )
                acknowledgment = response.json() if response.status_code in {200, 201} else {}
                if (response.status_code in {200, 201}
                        and type(acknowledgment.get("id")) is int and acknowledgment["id"] > 0):
                    record.delivered_at = utcnow()
                    record.last_error = None
                    delivered += 1
                    continue
                record.last_error = f"Audit acknowledgment rejected (HTTP {response.status_code})"
            except (httpx.HTTPError, ValueError, TypeError, AttributeError):
                record.last_error = "Audit request failed or acknowledgment was invalid"
            record.next_attempt_at = utcnow() + timedelta(seconds=min(300, 2 ** min(record.attempts, 9)))
    return delivered


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    settings = Settings()
    engine = make_engine(settings.database_url)
    try:
        with httpx.Client(trust_env=False) as client:
            while True:
                count = deliver_batch(sessionmaker(bind=engine), client, settings)
                print(f"Delivered {count} audit events", flush=True)
                if args.once:
                    break
                time.sleep(2)
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
