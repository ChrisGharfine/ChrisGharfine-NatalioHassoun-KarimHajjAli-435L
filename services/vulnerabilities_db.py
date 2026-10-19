"""Database layer for Service 7 -- Vulnerability Management.

Ported to PostgreSQL for team-integration-v1.0.0. As with incidents, the
join onto ``assets`` is gone: the asset belongs to Chris, so the asset's
name, criticality and owner now come from
:func:`clients.assets_client.lookup_asset` at the one point they are
actually needed, which is deciding who to alert when a serious
vulnerability is registered.

:author: Karim Hajj Ali
"""

import db
from serialization import jsonify_row, jsonify_rows, utc_now

#: Only my own columns. No cross-owner joins.
_VULNERABILITY_COLUMNS = """
    vulnerability_id, title, description, cve_identifier, cvss_score,
    severity_level, asset_id, discovery_source, status,
    creation_date, resolution_date
"""


def insert_vulnerability(cursor, row):
    """Insert a vulnerability inside an open transaction.

    :param cursor: An open cursor inside the business transaction.
    :type cursor: psycopg.Cursor
    :param row: Column values from :meth:`models.Vulnerability.to_row`.
    :type row: dict
    :return: The stored vulnerability.
    :rtype: dict
    """
    cursor.execute(
        "INSERT INTO vulnerabilities (title, description, cve_identifier, "
        "cvss_score, severity_level, asset_id, discovery_source, status, "
        "creation_date) VALUES (%s, %s, %s, %s, %s, %s, %s, 'Open', %s) "
        "RETURNING " + _VULNERABILITY_COLUMNS,
        (row["title"], row["description"], row["cve_identifier"],
         row["cvss_score"], row["severity_level"], row["asset_id"],
         row["discovery_source"], utc_now()))
    return jsonify_row(cursor.fetchone())


def get_vulnerabilities():
    """Fetch every vulnerability, newest first.

    :return: All stored vulnerabilities.
    :rtype: list
    """
    return jsonify_rows(db.query_all(
        "SELECT " + _VULNERABILITY_COLUMNS + " FROM vulnerabilities "
        "ORDER BY creation_date DESC, vulnerability_id DESC"))


def get_vulnerability_by_id(vulnerability_id):
    """Fetch one vulnerability.

    :param vulnerability_id: The vulnerability to fetch.
    :type vulnerability_id: int
    :return: The vulnerability, or ``None``.
    :rtype: dict or NoneType
    """
    return jsonify_row(db.query_one(
        "SELECT " + _VULNERABILITY_COLUMNS +
        " FROM vulnerabilities WHERE vulnerability_id = %s",
        (vulnerability_id,)))


def update_vulnerability(cursor, vulnerability_id, fields):
    """Update supplied vulnerability fields inside an open transaction.

    Column names are matched against a fixed whitelist before reaching the
    statement, so nothing from a request body can steer the SQL. Values are
    bound as parameters.

    :param cursor: An open cursor inside the business transaction.
    :type cursor: psycopg.Cursor
    :param vulnerability_id: The vulnerability to update.
    :type vulnerability_id: int
    :param fields: Column name to new value.
    :type fields: dict
    :return: The updated vulnerability, or ``None``.
    :rtype: dict or NoneType
    """
    allowed = ("description", "severity_level", "status", "cvss_score",
               "cve_identifier", "discovery_source", "resolution_date")

    assignments = []
    params = []
    for column in allowed:
        if column in fields:
            assignments.append("%s = %%s" % column)
            params.append(fields[column])

    if not assignments:
        return get_vulnerability_by_id(vulnerability_id)

    params.append(vulnerability_id)
    cursor.execute(
        "UPDATE vulnerabilities SET %s WHERE vulnerability_id = %%s "
        "RETURNING %s" % (", ".join(assignments), _VULNERABILITY_COLUMNS),
        tuple(params))
    return jsonify_row(cursor.fetchone())


def search_vulnerabilities(cve=None, severity=None, asset_id=None,
                           status=None):
    """Search by CVE, severity, asset and status, combined with AND.

    The CVE filter matches partially and case-insensitively.

    :param cve: Whole or partial CVE identifier, defaults to None.
    :type cve: str, optional
    :param severity: Restrict to one severity, defaults to None.
    :type severity: str, optional
    :param asset_id: Restrict to one asset, defaults to None.
    :type asset_id: int, optional
    :param status: Restrict to one lifecycle status, defaults to None.
    :type status: str, optional
    :return: Matching vulnerabilities, newest first.
    :rtype: list
    """
    sql = "SELECT " + _VULNERABILITY_COLUMNS + " FROM vulnerabilities WHERE TRUE"
    params = []

    if cve:
        sql += " AND cve_identifier ILIKE %s"
        params.append("%" + cve + "%")
    if severity:
        sql += " AND severity_level = %s"
        params.append(severity)
    if asset_id is not None:
        sql += " AND asset_id = %s"
        params.append(asset_id)
    if status:
        sql += " AND status = %s"
        params.append(status)

    sql += " ORDER BY creation_date DESC, vulnerability_id DESC"
    return jsonify_rows(db.query_all(sql, tuple(params)))


def delete_vulnerability(cursor, vulnerability_id):
    """Delete one vulnerability inside an open transaction.

    :param cursor: An open cursor inside the business transaction.
    :type cursor: psycopg.Cursor
    :param vulnerability_id: The vulnerability to delete.
    :type vulnerability_id: int
    :return: ``True`` if a row was removed.
    :rtype: bool
    """
    cursor.execute(
        "DELETE FROM vulnerabilities WHERE vulnerability_id = %s",
        (vulnerability_id,))
    return cursor.rowcount > 0
