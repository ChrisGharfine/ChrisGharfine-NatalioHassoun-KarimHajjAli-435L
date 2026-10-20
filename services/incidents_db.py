"""Database layer for Service 3 -- Incident Management.

Ported from SQLite to PostgreSQL for team-integration-v1.0.0. Three changes
beyond the dialect:

* The ``LEFT JOIN`` onto ``users`` and ``assets`` is gone. Those tables
  belong to Natalio and Chris, and section 3 allows a foreign key to them
  but not a query of them. The ``reporter_name``,
  ``assigned_analyst_name`` and ``affected_asset_name`` fields that join
  produced are therefore no longer returned.
* Timestamps are ``TIMESTAMPTZ`` and always written as aware UTC values.
* Writes that must be atomic with an outbox event take a cursor from the
  caller instead of opening their own connection.

:author: Karim Hajj Ali
"""

import db
from serialization import jsonify_row, jsonify_rows, utc_now

#: Only my own columns. No cross-owner joins.
_INCIDENT_COLUMNS = """
    incident_id, title, description, category, severity,
    reporter_id, asset_id, assigned_analyst_id, status,
    creation_date, resolution_date
"""


def insert_incident(cursor, row):
    """Insert a new incident using an existing transaction.

    The cursor is supplied by the caller so the incident and its audit
    outbox event commit together.

    :param cursor: An open cursor inside the business transaction.
    :type cursor: psycopg.Cursor
    :param row: Column values from :meth:`models.Incident.to_row`.
    :type row: dict
    :return: The stored incident.
    :rtype: dict
    """
    cursor.execute(
        "INSERT INTO incidents (title, description, category, severity, "
        "reporter_id, asset_id, status, creation_date) "
        "VALUES (%s, %s, %s, %s, %s, %s, 'Open', %s) "
        "RETURNING " + _INCIDENT_COLUMNS,
        (row["title"], row["description"], row["category"], row["severity"],
         row["reporter_id"], row["asset_id"], utc_now()))
    return jsonify_row(cursor.fetchone())


def get_incidents(reporter_id=None, analyst_id=None):
    """Fetch incidents, newest first.

    :param reporter_id: Only incidents reported by this user, defaults to None.
    :type reporter_id: int, optional
    :param analyst_id: Only incidents assigned to this analyst, defaults to None.
    :type analyst_id: int, optional
    :return: Matching incidents.
    :rtype: list
    """
    sql = "SELECT " + _INCIDENT_COLUMNS + " FROM incidents WHERE TRUE"
    params = []

    if reporter_id is not None:
        sql += " AND reporter_id = %s"
        params.append(reporter_id)
    if analyst_id is not None:
        sql += " AND assigned_analyst_id = %s"
        params.append(analyst_id)

    sql += " ORDER BY creation_date DESC, incident_id DESC"
    return jsonify_rows(db.query_all(sql, tuple(params)))


def get_incident_by_id(incident_id):
    """Fetch one incident without its notes.

    :param incident_id: The incident to fetch.
    :type incident_id: int
    :return: The incident, or ``None``.
    :rtype: dict or NoneType
    """
    return jsonify_row(db.query_one(
        "SELECT " + _INCIDENT_COLUMNS +
        " FROM incidents WHERE incident_id = %s", (incident_id,)))


def get_incident_with_notes(incident_id):
    """Fetch one incident together with its investigation notes.

    :param incident_id: The incident to fetch.
    :type incident_id: int
    :return: The incident with an ``investigation_notes`` list, or ``None``.
    :rtype: dict or NoneType
    """
    incident = get_incident_by_id(incident_id)
    if incident is None:
        return None
    incident["investigation_notes"] = get_notes_for_incident(incident_id)
    return incident


def assign_incident(cursor, incident_id, analyst_id):
    """Assign an incident to an analyst inside an open transaction.

    :param cursor: An open cursor inside the business transaction.
    :type cursor: psycopg.Cursor
    :param incident_id: The incident to assign.
    :type incident_id: int
    :param analyst_id: The analyst taking it on.
    :type analyst_id: int
    :return: The updated incident, or ``None`` if it vanished.
    :rtype: dict or NoneType
    """
    cursor.execute(
        "UPDATE incidents SET assigned_analyst_id = %s "
        "WHERE incident_id = %s RETURNING " + _INCIDENT_COLUMNS,
        (analyst_id, incident_id))
    return jsonify_row(cursor.fetchone())


def update_incident_status(cursor, incident_id, new_status):
    """Move an incident to a new status inside an open transaction.

    The caller checks the transition first with
    :class:`models.IncidentWorkflow`. Reaching ``Resolved`` stamps the
    resolution date.

    :param cursor: An open cursor inside the business transaction.
    :type cursor: psycopg.Cursor
    :param incident_id: The incident to update.
    :type incident_id: int
    :param new_status: The status to move to.
    :type new_status: str
    :return: The updated incident, or ``None``.
    :rtype: dict or NoneType
    """
    if new_status == "Resolved":
        cursor.execute(
            "UPDATE incidents SET status = %s, resolution_date = %s "
            "WHERE incident_id = %s RETURNING " + _INCIDENT_COLUMNS,
            (new_status, utc_now(), incident_id))
    else:
        cursor.execute(
            "UPDATE incidents SET status = %s "
            "WHERE incident_id = %s RETURNING " + _INCIDENT_COLUMNS,
            (new_status, incident_id))
    return jsonify_row(cursor.fetchone())


# ---------------------------------------------------------------------------
# Investigation notes
# ---------------------------------------------------------------------------

def insert_note(cursor, incident_id, analyst_id, note_content):
    """Attach an investigation note inside an open transaction.

    :param cursor: An open cursor inside the business transaction.
    :type cursor: psycopg.Cursor
    :param incident_id: The incident the note belongs to.
    :type incident_id: int
    :param analyst_id: Who wrote it.
    :type analyst_id: int
    :param note_content: The note text.
    :type note_content: str
    :return: The stored note.
    :rtype: dict
    """
    cursor.execute(
        "INSERT INTO investigation_notes (incident_id, analyst_id, "
        "note_content, creation_timestamp) VALUES (%s, %s, %s, %s) "
        "RETURNING note_id, incident_id, analyst_id, note_content, "
        "creation_timestamp",
        (incident_id, analyst_id, note_content, utc_now()))
    return jsonify_row(cursor.fetchone())


def get_notes_for_incident(incident_id):
    """Fetch an incident's notes, oldest first.

    :param incident_id: The incident whose notes to fetch.
    :type incident_id: int
    :return: The notes.
    :rtype: list
    """
    return jsonify_rows(db.query_all(
        "SELECT note_id, incident_id, analyst_id, note_content, "
        "creation_timestamp FROM investigation_notes "
        "WHERE incident_id = %s "
        "ORDER BY creation_timestamp ASC, note_id ASC", (incident_id,)))
