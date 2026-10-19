"""Database layer for Service 3 -- Incident Management.

Covers both the ``incidents`` table and the ``investigation_notes`` table
that hangs off it, since a note has no meaning outside the incident it
belongs to.

Reads join against ``users`` and ``assets`` so the API can return the
reporter's and analyst's names instead of bare ids. The join is a ``LEFT
JOIN`` on purpose: an incident that has not been assigned yet, or that was
reported without naming an asset, still has to come back.

:author: Karim Hajj Ali
"""

from datetime import datetime

from database import connect_to_db, row_to_dict, rows_to_list

#: Selects an incident together with the readable names behind its ids.
_INCIDENT_SELECT = """
    SELECT i.*,
           reporter.full_name AS reporter_name,
           analyst.full_name  AS assigned_analyst_name,
           a.asset_name       AS affected_asset_name
      FROM incidents i
      LEFT JOIN users  reporter ON reporter.user_id = i.reporter_id
      LEFT JOIN users  analyst  ON analyst.user_id  = i.assigned_analyst_id
      LEFT JOIN assets a        ON a.asset_id       = i.asset_id
"""


def insert_incident(row):
    """Insert a new incident. It always starts at status ``Open``.

    :param row: Column values, as produced by :meth:`models.Incident.to_row`.
    :type row: dict
    :return: The stored incident, or ``{}`` if the insert failed.
    :rtype: dict
    """
    conn = connect_to_db()
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO incidents (title, description, category, severity, "
            "reporter_id, asset_id, status, creation_date) "
            "VALUES (?, ?, ?, ?, ?, ?, 'Open', ?)",
            (row["title"], row["description"], row["category"],
             row["severity"], row["reporter_id"], row["asset_id"],
             datetime.now().isoformat(timespec="seconds")))
        conn.commit()
        new_id = cur.lastrowid
    except Exception:
        conn.rollback()
        return {}
    finally:
        conn.close()
    return get_incident_by_id(new_id)


def get_incidents(reporter_id=None, analyst_id=None):
    """Fetch incidents, newest first.

    :param reporter_id: Only incidents reported by this user, defaults to None.
    :type reporter_id: int, optional
    :param analyst_id: Only incidents assigned to this analyst, defaults to
        None.
    :type analyst_id: int, optional
    :return: Matching incidents.
    :rtype: list
    """
    query = _INCIDENT_SELECT + " WHERE 1 = 1"
    params = []

    if reporter_id is not None:
        query += " AND i.reporter_id = ?"
        params.append(reporter_id)
    if analyst_id is not None:
        query += " AND i.assigned_analyst_id = ?"
        params.append(analyst_id)

    query += " ORDER BY i.creation_date DESC, i.incident_id DESC"

    conn = connect_to_db()
    try:
        cur = conn.cursor()
        cur.execute(query, tuple(params))
        return rows_to_list(cur.fetchall())
    finally:
        conn.close()


def get_incident_by_id(incident_id):
    """Fetch one incident, without its investigation notes.

    :param incident_id: The incident to fetch.
    :type incident_id: int
    :return: The incident, or ``None`` if no such row exists.
    :rtype: dict or NoneType
    """
    conn = connect_to_db()
    try:
        cur = conn.cursor()
        cur.execute(_INCIDENT_SELECT + " WHERE i.incident_id = ?",
                    (incident_id,))
        return row_to_dict(cur.fetchone())
    finally:
        conn.close()


def get_incident_with_notes(incident_id):
    """Fetch one incident together with all of its investigation notes.

    This is what ``GET /incidents/{id}`` returns, so a single call gives the
    analyst the whole picture.

    :param incident_id: The incident to fetch.
    :type incident_id: int
    :return: The incident with an added ``investigation_notes`` list, or
        ``None`` if no such incident exists.
    :rtype: dict or NoneType
    """
    incident = get_incident_by_id(incident_id)
    if incident is None:
        return None
    incident["investigation_notes"] = get_notes_for_incident(incident_id)
    return incident


def assign_incident(incident_id, analyst_id):
    """Assign an incident to a security analyst.

    :param incident_id: The incident to assign.
    :type incident_id: int
    :param analyst_id: ``user_id`` of the analyst taking it on.
    :type analyst_id: int
    :return: The updated incident, or ``None`` if the update failed.
    :rtype: dict or NoneType
    """
    conn = connect_to_db()
    try:
        conn.execute(
            "UPDATE incidents SET assigned_analyst_id = ? "
            "WHERE incident_id = ?",
            (analyst_id, incident_id))
        conn.commit()
    except Exception:
        conn.rollback()
        return None
    finally:
        conn.close()
    return get_incident_by_id(incident_id)


def update_incident_status(incident_id, new_status):
    """Move an incident to a new status.

    The caller is expected to have already checked the transition with
    :class:`models.IncidentWorkflow`. Reaching ``Resolved`` stamps the
    resolution date.

    :param incident_id: The incident to update.
    :type incident_id: int
    :param new_status: The status to move to.
    :type new_status: str
    :return: The updated incident, or ``None`` if the update failed.
    :rtype: dict or NoneType
    """
    conn = connect_to_db()
    try:
        if new_status == "Resolved":
            conn.execute(
                "UPDATE incidents SET status = ?, resolution_date = ? "
                "WHERE incident_id = ?",
                (new_status, datetime.now().isoformat(timespec="seconds"),
                 incident_id))
        else:
            conn.execute(
                "UPDATE incidents SET status = ? WHERE incident_id = ?",
                (new_status, incident_id))
        conn.commit()
    except Exception:
        conn.rollback()
        return None
    finally:
        conn.close()
    return get_incident_by_id(incident_id)


# ---------------------------------------------------------------------------
# Investigation notes
# ---------------------------------------------------------------------------

def insert_note(incident_id, analyst_id, note_content):
    """Attach an investigation note to an incident.

    :param incident_id: The incident the note belongs to.
    :type incident_id: int
    :param analyst_id: ``user_id`` of whoever wrote it.
    :type analyst_id: int
    :param note_content: The note text.
    :type note_content: str
    :return: The stored note, or ``{}`` if the insert failed.
    :rtype: dict
    """
    conn = connect_to_db()
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO investigation_notes (incident_id, analyst_id, "
            "note_content, creation_timestamp) VALUES (?, ?, ?, ?)",
            (incident_id, analyst_id, note_content,
             datetime.now().isoformat(timespec="seconds")))
        conn.commit()
        new_id = cur.lastrowid
    except Exception:
        conn.rollback()
        return {}
    finally:
        conn.close()

    conn = connect_to_db()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT n.*, u.full_name AS analyst_name "
            "FROM investigation_notes n "
            "LEFT JOIN users u ON u.user_id = n.analyst_id "
            "WHERE n.note_id = ?", (new_id,))
        return row_to_dict(cur.fetchone()) or {}
    finally:
        conn.close()


def get_notes_for_incident(incident_id):
    """Fetch every investigation note on an incident, oldest first.

    Oldest first because the notes read as a running investigation log.

    :param incident_id: The incident whose notes to fetch.
    :type incident_id: int
    :return: The notes, empty if there are none yet.
    :rtype: list
    """
    conn = connect_to_db()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT n.*, u.full_name AS analyst_name "
            "FROM investigation_notes n "
            "LEFT JOIN users u ON u.user_id = n.analyst_id "
            "WHERE n.incident_id = ? "
            "ORDER BY n.creation_timestamp ASC, n.note_id ASC",
            (incident_id,))
        return rows_to_list(cur.fetchall())
    finally:
        conn.close()


def user_has_role(user_id, role):
    """Check that a user exists and currently holds a given role.

    Used before assigning an incident, because the spec requires the target
    to actually be a Security Analyst.

    :param user_id: The user to check.
    :type user_id: int
    :param role: The role they must hold.
    :type role: str
    :return: ``True`` if the user exists and has that role.
    :rtype: bool
    """
    conn = connect_to_db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT role FROM users WHERE user_id = ?", (user_id,))
        row = cur.fetchone()
        return row is not None and row["role"] == role
    finally:
        conn.close()
