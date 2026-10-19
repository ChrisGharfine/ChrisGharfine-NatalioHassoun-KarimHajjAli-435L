"""Audit logging client.

.. note::

   The **Security Audit Logging Service (Service 5)** itself is another team
   member's work. This module is the thin client my three services call so
   that their activity shows up in the audit trail from day one.

   There is one function, :func:`write_log`, and it writes straight into the
   ``logs`` table. When Service 5 is finished, the body of that function
   becomes an HTTP ``POST /logs`` call to it and nothing else in my services
   has to change -- that is the whole reason the write goes through one
   function instead of being inlined everywhere.

Logging never raises. If the audit write fails, the operation that triggered
it still succeeds and the failure is printed to the console. Losing a log
line is bad, but failing a legitimate incident update because the logging
table was locked would be worse.

:author: Karim Hajj Ali
"""

from datetime import datetime

from database import connect_to_db


def write_log(user_id, action, description, severity, service):
    """Record one entry in the security audit log.

    :param user_id: ``user_id`` of whoever performed the action. May be
        ``None`` for events with no signed-in user.
    :type user_id: int or NoneType
    :param action: Short name of what happened, e.g. ``"Incident created"``.
    :type action: str
    :param description: Fuller sentence describing the event.
    :type description: str
    :param severity: One of :data:`constants.LOG_SEVERITIES`.
    :type severity: str
    :param service: Which service generated the entry.
    :type service: str
    :return: The ``log_id`` that was written, or ``None`` if the write failed.
    :rtype: int or NoneType
    """
    conn = connect_to_db()
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO logs (user_id, action_performed, description, "
            "timestamp, severity_level, related_service) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (user_id, action, description,
             datetime.now().isoformat(timespec="seconds"), severity, service))
        conn.commit()
        return cur.lastrowid
    except Exception as error:
        conn.rollback()
        print("Audit log write failed: %s" % error)
        return None
    finally:
        conn.close()
