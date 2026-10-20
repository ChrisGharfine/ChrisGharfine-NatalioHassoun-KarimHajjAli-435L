"""Database layer for Service 8 -- Notification and Alert Management.

Ported to PostgreSQL for team-integration-v1.0.0, and extended with the
idempotency receipts section 7 requires.

The Sprint I ``send_notification()`` helper is deliberately **gone**.
Section 7 says the trigger owner "delivers it using its own service key
over HTTP" and that ``services.notifications_db`` must not be imported from
another service. Incidents and Vulnerabilities now queue work in
:mod:`outbox.notification_outbox` instead.

:author: Karim Hajj Ali
"""

import hashlib
import json

import db
from serialization import jsonify_row, jsonify_rows, utc_now

_NOTIFICATION_COLUMNS = """
    notification_id, user_id, title, message, notification_type,
    severity_level, status, creation_date, read_date
"""


def payload_digest(payload):
    """Return a stable digest of an internal-delivery payload.

    Used to tell an identical retry from a different payload reusing the
    same idempotency key, which section 7 answers with ``409``.

    :param payload: The delivery payload.
    :type payload: dict
    :return: Hex SHA-256 digest.
    :rtype: str
    """
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Receipts
# ---------------------------------------------------------------------------

def get_receipt(event_id):
    """Fetch the receipt for an idempotency key, if one exists.

    :param event_id: The ``Idempotency-Key`` UUID.
    :type event_id: str
    :return: The receipt row, or ``None``.
    :rtype: dict or NoneType
    """
    return db.query_one(
        "SELECT event_id, source_service, payload_digest, notification_id "
        "FROM karim_notification_receipts WHERE event_id = %s", (event_id,))


def create_notification_with_receipt(event_id, source_service, digest, row):
    """Create a notification, its receipt and its audit event atomically.

    Section 7 requires all three to happen in one transaction so a retry
    can never find a notification without a receipt, or the other way
    round.

    :param event_id: The idempotency key for this delivery.
    :type event_id: str
    :param source_service: The authenticated calling service.
    :type source_service: str
    :param digest: Digest of the payload, stored on the receipt.
    :type digest: str
    :param row: Column values from :meth:`models.Notification.to_row`.
    :type row: dict
    :return: The stored notification.
    :rtype: dict
    """
    from outbox.audit_outbox import ACTION_NOTIFICATION_CREATED, \
        queue_audit_event

    with db.transaction() as cur:
        cur.execute(
            "INSERT INTO notifications (user_id, title, message, "
            "notification_type, severity_level, status, creation_date) "
            "VALUES (%s, %s, %s, %s, %s, 'Unread', %s) "
            "RETURNING " + _NOTIFICATION_COLUMNS,
            (row["user_id"], row["title"], row["message"],
             row["notification_type"], row["severity_level"], utc_now()))
        notification = jsonify_row(cur.fetchone())

        cur.execute(
            "INSERT INTO karim_notification_receipts "
            "(event_id, source_service, payload_digest, notification_id) "
            "VALUES (%s, %s, %s, %s)",
            (event_id, source_service, digest,
             notification["notification_id"]))

        queue_audit_event(
            source_service="notifications",
            user_id=row.get("actor_user_id"),
            action=ACTION_NOTIFICATION_CREATED,
            description="Notification %s (%s) created for user %s by %s"
                        % (notification["notification_id"],
                           notification["notification_type"],
                           notification["user_id"], source_service),
            severity="Information",
            related_service="notifications",
            cursor=cur)

    return notification


# ---------------------------------------------------------------------------
# Public reads and writes
# ---------------------------------------------------------------------------

def insert_notification(cursor, row):
    """Insert a notification inside an open transaction.

    Used by the public administrator endpoint. Internal deliveries go
    through :func:`create_notification_with_receipt` instead, because they
    also need a receipt.

    :param cursor: An open cursor inside the business transaction.
    :type cursor: psycopg.Cursor
    :param row: Column values from :meth:`models.Notification.to_row`.
    :type row: dict
    :return: The stored notification.
    :rtype: dict
    """
    cursor.execute(
        "INSERT INTO notifications (user_id, title, message, "
        "notification_type, severity_level, status, creation_date) "
        "VALUES (%s, %s, %s, %s, %s, 'Unread', %s) "
        "RETURNING " + _NOTIFICATION_COLUMNS,
        (row["user_id"], row["title"], row["message"],
         row["notification_type"], row["severity_level"], utc_now()))
    return jsonify_row(cursor.fetchone())


def get_notification_by_id(notification_id):
    """Fetch one notification.

    :param notification_id: The notification to fetch.
    :type notification_id: int
    :return: The notification, or ``None``.
    :rtype: dict or NoneType
    """
    return jsonify_row(db.query_one(
        "SELECT " + _NOTIFICATION_COLUMNS +
        " FROM notifications WHERE notification_id = %s", (notification_id,)))


def get_notifications_by_user(user_id):
    """Fetch one user's notifications, newest first.

    :param user_id: The recipient.
    :type user_id: int
    :return: Their notifications, empty if none.
    :rtype: list
    """
    return jsonify_rows(db.query_all(
        "SELECT " + _NOTIFICATION_COLUMNS + " FROM notifications "
        "WHERE user_id = %s "
        "ORDER BY creation_date DESC, notification_id DESC", (user_id,)))


def mark_notification_read(notification_id, actor_user_id):
    """Mark a notification read, preserving an existing read date.

    :param notification_id: The notification to mark.
    :type notification_id: int
    :param actor_user_id: Current authenticated user who changed the notification.
    :type actor_user_id: int
    :return: The updated notification, or ``None``.
    :rtype: dict or NoneType
    """
    from outbox.audit_outbox import queue_audit_event
    with db.transaction() as cur:
        cur.execute("SELECT " + _NOTIFICATION_COLUMNS +
                    " FROM notifications WHERE notification_id=%s FOR UPDATE", (notification_id,))
        existing = cur.fetchone()
        if existing is None:
            return None
        if existing["status"] == "Read":
            return jsonify_row(existing)
        cur.execute("UPDATE notifications SET status='Read', read_date=%s WHERE notification_id=%s RETURNING "
                    + _NOTIFICATION_COLUMNS, (utc_now(), notification_id))
        changed = cur.fetchone()
        queue_audit_event(source_service="notifications", user_id=actor_user_id,
                          action="notification_marked_read", description="Notification %s marked as read" % notification_id,
                          severity="Information", related_service="notifications", cursor=cur)
        return jsonify_row(changed)


def search_notifications(user_id=None, notification_type=None, severity=None,
                         status=None):
    """Search notifications by up to four criteria, combined with AND.

    :param user_id: Restrict to one recipient, defaults to None.
    :type user_id: int, optional
    :param notification_type: Restrict to one type, defaults to None.
    :type notification_type: str, optional
    :param severity: Restrict to one severity, defaults to None.
    :type severity: str, optional
    :param status: ``Unread`` or ``Read``, defaults to None.
    :type status: str, optional
    :return: Matching notifications, newest first.
    :rtype: list
    """
    sql = "SELECT " + _NOTIFICATION_COLUMNS + " FROM notifications WHERE TRUE"
    params = []

    if user_id is not None:
        sql += " AND user_id = %s"
        params.append(user_id)
    if notification_type:
        sql += " AND notification_type = %s"
        params.append(notification_type)
    if severity:
        sql += " AND severity_level = %s"
        params.append(severity)
    if status:
        sql += " AND status = %s"
        params.append(status)

    sql += " ORDER BY creation_date DESC, notification_id DESC"
    return jsonify_rows(db.query_all(sql, tuple(params)))


def delete_notification(cursor, notification_id):
    """Delete one notification inside an open transaction.

    The receipt row survives: its ``notification_id`` becomes ``NULL`` via
    ``ON DELETE SET NULL``, so an identical retry still returns
    ``duplicate=true`` with ``notification=null`` rather than recreating
    the notification.

    :param cursor: An open cursor inside the business transaction.
    :type cursor: psycopg.Cursor
    :param notification_id: The notification to delete.
    :type notification_id: int
    :return: ``True`` if a row was removed.
    :rtype: bool
    """
    cursor.execute("DELETE FROM notifications WHERE notification_id = %s",
                   (notification_id,))
    return cursor.rowcount > 0
