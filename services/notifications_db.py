"""Database layer for Service 8 -- Notification and Alert Management.

All SQL for the ``notifications`` table lives here. The API layer calls these
functions and never writes SQL itself, which keeps the routes readable and
means the queries can be tested without starting Flask.

Every value that comes from a request is bound as a ``?`` parameter, so there
is no way for user input to be read as SQL.

:author: Karim Hajj Ali
"""

from datetime import datetime

from database import connect_to_db, row_to_dict, rows_to_list
from models import Notification


def send_notification(user_id, title, message, notification_type, severity):
    """Build, validate and store a notification in one step.

    This is the entry point the other two services use when something they
    did should alert a user -- an incident being assigned, or a serious
    vulnerability being logged against an asset. Going through the
    :class:`models.Notification` class rather than inserting directly means
    an automatically generated notification is held to exactly the same
    validation rules as one posted by an administrator.

    It deliberately swallows failures: a notification that cannot be
    delivered must not roll back the incident assignment that caused it.

    :param user_id: ``user_id`` of the recipient.
    :type user_id: int
    :param title: Short headline.
    :type title: str
    :param message: Body text.
    :type message: str
    :param notification_type: One of :data:`constants.NOTIFICATION_TYPES`.
    :type notification_type: str
    :param severity: One of :data:`constants.SEVERITIES`.
    :type severity: str
    :return: The stored notification, or ``None`` if it could not be stored.
    :rtype: dict or NoneType
    """
    try:
        notification = Notification(
            user_id, title, message, notification_type, severity)
        notification.validate()
        return insert_notification(notification.to_row()) or None
    except Exception as error:
        print("Could not generate notification: %s" % error)
        return None


def insert_notification(row):
    """Insert one notification and return it as stored.

    :param row: Column values, as produced by
        :meth:`models.Notification.to_row`.
    :type row: dict
    :return: The stored notification, or ``{}`` if the insert failed.
    :rtype: dict
    """
    conn = connect_to_db()
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO notifications (user_id, title, message, "
            "notification_type, severity_level, status, creation_date) "
            "VALUES (?, ?, ?, ?, ?, 'Unread', ?)",
            (row["user_id"], row["title"], row["message"],
             row["notification_type"], row["severity_level"],
             datetime.now().isoformat(timespec="seconds")))
        conn.commit()
        new_id = cur.lastrowid
    except Exception:
        conn.rollback()
        return {}
    finally:
        conn.close()
    return get_notification_by_id(new_id)


def get_notification_by_id(notification_id):
    """Fetch a single notification.

    :param notification_id: The notification to fetch.
    :type notification_id: int
    :return: The notification, or ``None`` if no such row exists.
    :rtype: dict or NoneType
    """
    conn = connect_to_db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM notifications WHERE notification_id = ?",
                    (notification_id,))
        return row_to_dict(cur.fetchone())
    finally:
        conn.close()


def get_notifications_by_user(user_id):
    """Fetch every notification belonging to one user, newest first.

    :param user_id: The recipient to fetch notifications for.
    :type user_id: int
    :return: The user's notifications, empty if they have none.
    :rtype: list
    """
    conn = connect_to_db()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM notifications WHERE user_id = ? "
            "ORDER BY creation_date DESC, notification_id DESC",
            (user_id,))
        return rows_to_list(cur.fetchall())
    finally:
        conn.close()


def mark_notification_read(notification_id):
    """Mark a notification as read and stamp the read date.

    Marking an already-read notification again leaves the original read date
    alone, so the timestamp keeps meaning "when it was first opened".

    :param notification_id: The notification to update.
    :type notification_id: int
    :return: The updated notification, or ``None`` if it does not exist.
    :rtype: dict or NoneType
    """
    conn = connect_to_db()
    try:
        conn.execute(
            "UPDATE notifications SET status = 'Read', read_date = ? "
            "WHERE notification_id = ? AND status = 'Unread'",
            (datetime.now().isoformat(timespec="seconds"), notification_id))
        conn.commit()
    except Exception:
        conn.rollback()
        return None
    finally:
        conn.close()
    return get_notification_by_id(notification_id)


def search_notifications(user_id=None, notification_type=None,
                         severity=None, status=None):
    """Search notifications by any combination of four criteria.

    Filters are combined with ``AND``. Passing nothing returns everything,
    which is what an administrator browsing the service would expect.

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
    query = "SELECT * FROM notifications WHERE 1 = 1"
    params = []

    if user_id is not None:
        query += " AND user_id = ?"
        params.append(user_id)
    if notification_type:
        query += " AND notification_type = ?"
        params.append(notification_type)
    if severity:
        query += " AND severity_level = ?"
        params.append(severity)
    if status:
        query += " AND status = ?"
        params.append(status)

    query += " ORDER BY creation_date DESC, notification_id DESC"

    conn = connect_to_db()
    try:
        cur = conn.cursor()
        cur.execute(query, tuple(params))
        return rows_to_list(cur.fetchall())
    finally:
        conn.close()


def delete_notification(notification_id):
    """Delete one notification.

    :param notification_id: The notification to delete.
    :type notification_id: int
    :return: ``True`` if a row was actually removed.
    :rtype: bool
    """
    conn = connect_to_db()
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM notifications WHERE notification_id = ?",
                    (notification_id,))
        conn.commit()
        return cur.rowcount > 0
    except Exception:
        conn.rollback()
        return False
    finally:
        conn.close()
