"""Durable audit events, queued locally and delivered to Natalio's Logs.

Section 6 of team-integration-v1.0.0. The Sprint I version wrote straight
into a ``logs`` table and swallowed failures. Neither is allowed now: Logs
belongs to Natalio and is reached over HTTP, and a failed delivery has to
survive a restart rather than disappear.

The shape is a transactional outbox:

* :func:`queue_audit_event` inserts a row. Called inside the same
  transaction as the business change, so the two commit together.
* :func:`deliver_pending` posts queued rows to Logs and marks them
  delivered. Run by the worker or an explicit flush, never inline in a
  request.

Each event keeps one stable UUID for its whole life, so a retry is
recognised by Logs as the same event rather than creating a duplicate.

:author: Karim Hajj Ali
"""

import uuid
from datetime import datetime, timedelta, timezone

import requests

import config
import db
from outbox.receipts import valid_receipt

#: Transport action codes fixed by section 6. Natalio's Logs validates
#: against ``[a-z][a-z0-9_]*``, so the Sprint I human labels like
#: "Incident created" would be rejected outright.
ACTION_INCIDENT_CREATED = "incident_created"
ACTION_INCIDENT_ASSIGNED = "incident_assigned"
ACTION_INCIDENT_STATUS_UPDATED = "incident_status_updated"
ACTION_INVESTIGATION_NOTE_ADDED = "investigation_note_added"
ACTION_VULNERABILITY_CREATED = "vulnerability_created"
ACTION_VULNERABILITY_UPDATED = "vulnerability_updated"
ACTION_VULNERABILITY_DELETED = "vulnerability_deleted"
ACTION_NOTIFICATION_CREATED = "notification_created"
ACTION_NOTIFICATION_DELETED = "notification_deleted"
ACTION_UNAUTHORIZED_ACCESS = "unauthorized_access"


def queue_audit_event(source_service, user_id, action, description, severity,
                      related_service, cursor=None, event_id=None):
    """Store one audit event for later delivery.

    Pass ``cursor`` to enlist in a transaction that is already open, which
    is how a business mutation and its audit event commit atomically. Omit
    it and the event gets its own transaction, which is what a denied
    request wants.

    :param source_service: Which of my services produced the event.
    :type source_service: str
    :param user_id: The authenticated actor, or ``None`` when unknown.
    :type user_id: int or NoneType
    :param action: One of the transport action codes above.
    :type action: str
    :param description: Short description. Never a raw body or credential.
    :type description: str
    :param severity: ``Information``, ``Warning``, ``Error`` or ``Critical``.
    :type severity: str
    :param related_service: The service name the event belongs to.
    :type related_service: str
    :param cursor: An open cursor to reuse, defaults to None.
    :type cursor: psycopg.Cursor, optional
    :param event_id: Override the generated UUID, defaults to None.
    :type event_id: str, optional
    :return: The event UUID.
    :rtype: str
    """
    new_id = event_id or str(uuid.uuid4())
    params = (new_id, source_service, user_id, action, description[:2000],
              severity, related_service)
    sql = ("INSERT INTO karim_audit_outbox (event_id, source_service, "
           "user_id, action, description, severity, related_service) "
           "VALUES (%s, %s, %s, %s, %s, %s, %s)")

    if cursor is not None:
        cursor.execute(sql, params)
    else:
        db.execute(sql, params)
    return new_id


def pending_count():
    """Count events still waiting to be delivered.

    :return: ``{"pending": int, "permanent_error": int, "delivered": int}``.
    :rtype: dict
    """
    row = db.query_one(
        "SELECT "
        " count(*) FILTER (WHERE delivered_at IS NULL "
        "                  AND permanent_error = FALSE) AS pending,"
        " count(*) FILTER (WHERE permanent_error) AS permanent_error,"
        " count(*) FILTER (WHERE delivered_at IS NOT NULL) AS delivered "
        "FROM karim_audit_outbox")
    return dict(row)


def claim_batch(limit=None):
    """Fetch events that are due for a delivery attempt.

    :param limit: Maximum rows to claim, defaults to the configured batch.
    :type limit: int, optional
    :return: Outbox rows.
    :rtype: list
    """
    return db.query_all(
        "SELECT * FROM karim_audit_outbox "
        "WHERE delivered_at IS NULL AND permanent_error = FALSE "
        "  AND next_attempt_at <= now() "
        "ORDER BY created_at "
        "LIMIT %s",
        (limit or config.OUTBOX_BATCH_SIZE,))


def _backoff_seconds(attempts):
    """Return the delay before the next attempt.

    Exponential, capped by configuration at 300 seconds per section 6.

    :param attempts: How many attempts have already been made.
    :type attempts: int
    :return: Delay in seconds.
    :rtype: int
    """
    return min(2 ** min(attempts, 16), config.OUTBOX_MAX_BACKOFF_SECONDS)


def mark_delivered(event_id):
    """Record that Logs accepted an event.

    :param event_id: The event UUID.
    :type event_id: str
    :return: ``None``
    :rtype: NoneType
    """
    db.execute(
        "UPDATE karim_audit_outbox SET delivered_at = %s, last_error = NULL "
        "WHERE event_id = %s", (datetime.now(timezone.utc), event_id))


def mark_retryable(event_id, attempts, reason):
    """Schedule another attempt after a temporary failure.

    :param event_id: The event UUID.
    :type event_id: str
    :param attempts: Attempts made so far, before this one is counted.
    :type attempts: int
    :param reason: Sanitised failure reason, never a response body.
    :type reason: str
    :return: ``None``
    :rtype: NoneType
    """
    delay = _backoff_seconds(attempts + 1)
    db.execute(
        "UPDATE karim_audit_outbox "
        "SET attempts = attempts + 1, next_attempt_at = %s, last_error = %s "
        "WHERE event_id = %s",
        (datetime.now(timezone.utc) + timedelta(seconds=delay),
         reason[:500], event_id))


def mark_permanent(event_id, reason):
    """Stop retrying an event that can never succeed as queued.

    Used for an idempotency conflict, which section 6 says is a permanent
    delivery failure requiring correction rather than an endless loop. The
    original payload is kept for diagnosis.

    :param event_id: The event UUID.
    :type event_id: str
    :param reason: Sanitised failure reason.
    :type reason: str
    :return: ``None``
    :rtype: NoneType
    """
    db.execute(
        "UPDATE karim_audit_outbox "
        "SET attempts = attempts + 1, permanent_error = TRUE, last_error = %s "
        "WHERE event_id = %s", (reason[:500], event_id))


def _post_event(row):
    """Send one event to Logs and interpret the reply.

    :param row: An outbox row.
    :type row: dict
    :return: ``("delivered"|"retry"|"permanent", reason)``.
    :rtype: tuple
    """
    url = "%s/internal/logs" % config.LOGS_BASE_URL.rstrip("/")
    source = row["source_service"]

    try:
        key = config.my_service_key(source)
    except RuntimeError as failure:
        return "retry", "service key unavailable: %s" % failure

    payload = {
        "user_id": row["user_id"],
        "action": row["action"],
        "description": row["description"],
        "severity": row["severity"],
        "related_service": row["related_service"],
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
        return _validate_receipt(response, row)

    if response.status_code == 409:
        code = _error_code(response)
        if code == "IDEMPOTENCY_CONFLICT":
            return ("permanent",
                    "idempotency conflict: this UUID was already used with a "
                    "different payload")
        # Natalio's generic 409 can also mean a concurrent identical request.
        # That is retryable with the same UUID.
        return "retry", "conflict, retrying same event id"

    if response.status_code in (401, 403):
        return "retry", "service credentials rejected (status %d)" % \
            response.status_code

    return "retry", "unexpected status %d" % response.status_code


def _error_code(response):
    """Pull an error code out of a response without logging its body.

    :param response: The HTTP response.
    :type response: requests.Response
    :return: The code, or ``""`` if absent.
    :rtype: str
    """
    try:
        body = response.json()
    except ValueError:
        return ""
    if not isinstance(body, dict):
        return ""
    for key in ("code", "error_code"):
        if isinstance(body.get(key), str):
            return body[key]
    error = body.get("error")
    if isinstance(error, dict) and isinstance(error.get("code"), str):
        return error["code"]
    return ""


def _validate_receipt(response, row):
    """Check that Logs really persisted this event under this UUID.

    Section 6 says a delivery only counts once a valid receipt comes back,
    including the deletion case where the log row is gone but the receipt
    still stands.

    :param response: The HTTP response from Logs.
    :type response: requests.Response
    :param row: The outbox row that was sent.
    :type row: dict
    :return: ``("delivered"|"retry", reason)``.
    :rtype: tuple
    """
    try:
        body = response.json()
    except ValueError:
        return "retry", "non-JSON acknowledgement"

    return (("delivered", "") if valid_receipt(body, response.status_code, row["event_id"], "log", "id")
            else ("retry", "invalid audit receipt"))


def deliver_pending(limit=None):
    """Attempt delivery for one batch of pending events.

    :param limit: Maximum events to attempt, defaults to the batch size.
    :type limit: int, optional
    :return: ``{"attempted", "delivered", "retry", "permanent"}``.
    :rtype: dict
    """
    counters = {"attempted": 0, "delivered": 0, "retry": 0, "permanent": 0}

    for row in claim_batch(limit):
        counters["attempted"] += 1
        outcome, reason = _post_event(row)

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
