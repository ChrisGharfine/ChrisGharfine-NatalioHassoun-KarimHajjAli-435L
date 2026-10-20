"""Durable notification delivery from Incidents and Vulnerabilities.

Section 7 of team-integration-v1.0.0 is explicit that a trigger owner
"delivers it using its own service key over HTTP, even for Karim's
services" and that ``services.notifications_db`` must not be imported from
another service. So although all three services are mine, Incidents and
Vulnerabilities talk to Notifications the same way Chris's services would.

Same transactional-outbox shape as the audit outbox: the trigger queues the
work inside the business transaction, and the worker posts it afterwards.
A pending notification never rolls back the assignment that caused it.

:author: Karim Hajj Ali
"""

import uuid
from datetime import datetime, timedelta, timezone

import requests

import config
import db
from outbox.receipts import valid_receipt

#: Notification types this process is allowed to raise, per caller. The
#: Notifications service enforces the same table on the receiving side.
ALLOWED_TYPES = {
    config.SERVICE_INCIDENTS: ("Incident Assignment",),
    config.SERVICE_VULNERABILITIES: ("Vulnerability Alert",),
}


def queue_notification(source_service, recipient_user_id, title, message,
                       notification_type, severity_level, actor_user_id=None,
                       cursor=None, event_id=None):
    """Store notification work for later delivery over HTTP.

    :param source_service: ``incidents`` or ``vulnerabilities``.
    :type source_service: str
    :param recipient_user_id: Who should receive the notification.
    :type recipient_user_id: int
    :param title: Short headline.
    :type title: str
    :param message: Body text.
    :type message: str
    :param notification_type: One of the types allowed for this caller.
    :type notification_type: str
    :param severity_level: ``Low``, ``Medium``, ``High`` or ``Critical``.
    :type severity_level: str
    :param actor_user_id: The authenticated actor who caused this, or
        ``None``, defaults to None.
    :type actor_user_id: int, optional
    :param cursor: An open cursor to enlist in, defaults to None.
    :type cursor: psycopg.Cursor, optional
    :param event_id: Override the generated UUID, defaults to None.
    :type event_id: str, optional
    :raises ValueError: If this caller may not raise this type.
    :return: The event UUID.
    :rtype: str
    """
    allowed = ALLOWED_TYPES.get(source_service, ())
    if notification_type not in allowed:
        raise ValueError(
            "Service '%s' may not raise '%s' notifications"
            % (source_service, notification_type))

    new_id = event_id or str(uuid.uuid4())
    sql = ("INSERT INTO karim_notification_outbox "
           "(event_id, source_service, recipient_user_id, actor_user_id, "
           " title, message, notification_type, severity_level) "
           "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)")
    params = (new_id, source_service, recipient_user_id, actor_user_id,
              title, message, notification_type, severity_level)

    if cursor is not None:
        cursor.execute(sql, params)
    else:
        db.execute(sql, params)
    return new_id


def pending_count():
    """Count notification work still waiting to be delivered.

    :return: ``{"pending": int, "permanent_error": int, "delivered": int}``.
    :rtype: dict
    """
    row = db.query_one(
        "SELECT "
        " count(*) FILTER (WHERE delivered_at IS NULL "
        "                  AND permanent_error = FALSE) AS pending,"
        " count(*) FILTER (WHERE permanent_error) AS permanent_error,"
        " count(*) FILTER (WHERE delivered_at IS NOT NULL) AS delivered "
        "FROM karim_notification_outbox")
    return dict(row)


def claim_batch(limit=None):
    """Fetch notification work due for an attempt.

    :param limit: Maximum rows, defaults to the configured batch size.
    :type limit: int, optional
    :return: Outbox rows.
    :rtype: list
    """
    return db.query_all(
        "SELECT * FROM karim_notification_outbox "
        "WHERE delivered_at IS NULL AND permanent_error = FALSE "
        "  AND next_attempt_at <= now() "
        "ORDER BY created_at "
        "LIMIT %s",
        (limit or config.OUTBOX_BATCH_SIZE,))


def mark_delivered(event_id):
    """Record that Notifications accepted this work.

    :param event_id: The event UUID.
    :type event_id: str
    :return: ``None``
    :rtype: NoneType
    """
    db.execute(
        "UPDATE karim_notification_outbox "
        "SET delivered_at = %s, last_error = NULL WHERE event_id = %s",
        (datetime.now(timezone.utc), event_id))


def mark_retryable(event_id, attempts, reason):
    """Schedule another attempt after a temporary failure.

    :param event_id: The event UUID.
    :type event_id: str
    :param attempts: Attempts made so far.
    :type attempts: int
    :param reason: Sanitised failure reason.
    :type reason: str
    :return: ``None``
    :rtype: NoneType
    """
    delay = min(2 ** min(attempts + 1, 16), config.OUTBOX_MAX_BACKOFF_SECONDS)
    db.execute(
        "UPDATE karim_notification_outbox "
        "SET attempts = attempts + 1, next_attempt_at = %s, last_error = %s "
        "WHERE event_id = %s",
        (datetime.now(timezone.utc) + timedelta(seconds=delay),
         reason[:500], event_id))


def mark_permanent(event_id, reason):
    """Stop retrying work that can never succeed.

    Section 7 keeps invalid-recipient and idempotency conflicts visible for
    intervention rather than retrying them forever.

    :param event_id: The event UUID.
    :type event_id: str
    :param reason: Sanitised failure reason.
    :type reason: str
    :return: ``None``
    :rtype: NoneType
    """
    db.execute(
        "UPDATE karim_notification_outbox "
        "SET attempts = attempts + 1, permanent_error = TRUE, last_error = %s "
        "WHERE event_id = %s", (reason[:500], event_id))


def _post_notification(row):
    """Send one queued notification to the Notifications service.

    :param row: An outbox row.
    :type row: dict
    :return: ``("delivered"|"retry"|"permanent", reason)``.
    :rtype: tuple
    """
    url = "%s/internal/notifications" % \
        config.NOTIFICATIONS_BASE_URL.rstrip("/")
    source = row["source_service"]

    try:
        key = config.my_service_key(source)
    except RuntimeError as failure:
        return "retry", "service key unavailable: %s" % failure

    payload = {
        "user_id": row["recipient_user_id"],
        "actor_user_id": row["actor_user_id"],
        "title": row["title"],
        "message": row["message"],
        "notification_type": row["notification_type"],
        "severity_level": row["severity_level"],
    }

    try:
        response = requests.post(
            url,
            json=payload,
            headers={
                "X-Service-Name": source,
                "X-Service-Key": key,
                "Idempotency-Key": str(row["event_id"]),
            },
            timeout=config.HTTP_TIMEOUT_SECONDS,
            allow_redirects=False,
        )
    except requests.Timeout:
        return "retry", "timeout"
    except requests.RequestException:
        return "retry", "connection error"

    if response.status_code in (200, 201):
        try:
            body = response.json()
        except ValueError:
            return "retry", "non-JSON acknowledgement"
        return (("delivered", "") if valid_receipt(body, response.status_code, row["event_id"],
                                                  "notification", "notification_id")
                else ("retry", "invalid notification receipt"))

    if response.status_code == 404:
        return "permanent", "recipient does not exist"

    if response.status_code == 409:
        code = ""
        try:
            body = response.json()
            if isinstance(body, dict):
                code = body.get("code") or ""
        except ValueError:
            pass
        if code == "RECIPIENT_UNAVAILABLE":
            return "permanent", "recipient is inactive or deleted"
        if code == "IDEMPOTENCY_CONFLICT":
            return "permanent", "idempotency conflict for this event id"
        return "retry", "conflict, retrying same event id"

    if response.status_code == 400:
        return "permanent", "notification payload was rejected as invalid"

    if response.status_code in (401, 403):
        return "retry", "service credentials rejected (status %d)" % \
            response.status_code

    return "retry", "unexpected status %d" % response.status_code


def deliver_pending(limit=None):
    """Attempt delivery for one batch of queued notifications.

    :param limit: Maximum events to attempt, defaults to the batch size.
    :type limit: int, optional
    :return: ``{"attempted", "delivered", "retry", "permanent"}``.
    :rtype: dict
    """
    counters = {"attempted": 0, "delivered": 0, "retry": 0, "permanent": 0}

    for row in claim_batch(limit):
        counters["attempted"] += 1
        outcome, reason = _post_notification(row)

        if outcome == "delivered":
            mark_delivered(row["event_id"])
            counters["delivered"] += 1
        elif outcome == "permanent":
            mark_permanent(row["event_id"], reason)
            counters["permanent"] += 1
        else:
            mark_retryable(row["event_id"], row["attempts"], reason)
            counters["retry"] += 1

    return counters
