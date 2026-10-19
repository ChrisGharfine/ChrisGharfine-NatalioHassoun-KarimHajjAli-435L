"""Database layer for Service 7 -- Vulnerability Management.

Reads join against ``assets`` so a vulnerability comes back with the name of
the machine it affects rather than just an id, which is what makes the
search results readable.

:author: Karim Hajj Ali
"""

from datetime import datetime

from database import connect_to_db, row_to_dict, rows_to_list

#: Selects a vulnerability along with the asset it was found on.
_VULNERABILITY_SELECT = """
    SELECT v.*,
           a.asset_name        AS affected_asset_name,
           a.criticality_level AS affected_asset_criticality,
           a.owner_id          AS affected_asset_owner_id
      FROM vulnerabilities v
      LEFT JOIN assets a ON a.asset_id = v.asset_id
"""


def insert_vulnerability(row):
    """Insert a new vulnerability. It always starts at status ``Open``.

    :param row: Column values, as produced by
        :meth:`models.Vulnerability.to_row`.
    :type row: dict
    :return: The stored vulnerability, or ``{}`` if the insert failed.
    :rtype: dict
    """
    conn = connect_to_db()
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO vulnerabilities (title, description, "
            "cve_identifier, cvss_score, severity_level, asset_id, "
            "discovery_source, status, creation_date) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, 'Open', ?)",
            (row["title"], row["description"], row["cve_identifier"],
             row["cvss_score"], row["severity_level"], row["asset_id"],
             row["discovery_source"],
             datetime.now().isoformat(timespec="seconds")))
        conn.commit()
        new_id = cur.lastrowid
    except Exception:
        conn.rollback()
        return {}
    finally:
        conn.close()
    return get_vulnerability_by_id(new_id)


def get_vulnerabilities():
    """Fetch every vulnerability, newest first.

    :return: All stored vulnerabilities.
    :rtype: list
    """
    conn = connect_to_db()
    try:
        cur = conn.cursor()
        cur.execute(_VULNERABILITY_SELECT +
                    " ORDER BY v.creation_date DESC, v.vulnerability_id DESC")
        return rows_to_list(cur.fetchall())
    finally:
        conn.close()


def get_vulnerability_by_id(vulnerability_id):
    """Fetch one vulnerability.

    :param vulnerability_id: The vulnerability to fetch.
    :type vulnerability_id: int
    :return: The vulnerability, or ``None`` if no such row exists.
    :rtype: dict or NoneType
    """
    conn = connect_to_db()
    try:
        cur = conn.cursor()
        cur.execute(_VULNERABILITY_SELECT + " WHERE v.vulnerability_id = ?",
                    (vulnerability_id,))
        return row_to_dict(cur.fetchone())
    finally:
        conn.close()


def update_vulnerability(vulnerability_id, fields):
    """Update whichever vulnerability fields were supplied.

    Only the columns present in ``fields`` are touched, so a caller changing
    just the CVSS score does not have to resend the description. Column
    names are matched against a fixed whitelist before being put into the
    SQL, so nothing from the request body can reach the statement itself.

    :param vulnerability_id: The vulnerability to update.
    :type vulnerability_id: int
    :param fields: Column name to new value.
    :type fields: dict
    :return: The updated vulnerability, or ``None`` if the update failed.
    :rtype: dict or NoneType
    """
    allowed = ("description", "severity_level", "status", "cvss_score",
               "cve_identifier", "discovery_source", "resolution_date")

    assignments = []
    params = []
    for column, value in fields.items():
        if column in allowed:
            assignments.append("%s = ?" % column)
            params.append(value)

    if not assignments:
        return get_vulnerability_by_id(vulnerability_id)

    params.append(vulnerability_id)

    conn = connect_to_db()
    try:
        conn.execute(
            "UPDATE vulnerabilities SET %s WHERE vulnerability_id = ?"
            % ", ".join(assignments), tuple(params))
        conn.commit()
    except Exception:
        conn.rollback()
        return None
    finally:
        conn.close()
    return get_vulnerability_by_id(vulnerability_id)


def search_vulnerabilities(cve=None, severity=None, asset_id=None,
                           status=None):
    """Search vulnerabilities by CVE, severity, asset and status.

    The CVE filter is a partial, case-insensitive match, so searching for
    ``2024`` finds every CVE issued that year. The other three are exact.

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
    query = _VULNERABILITY_SELECT + " WHERE 1 = 1"
    params = []

    if cve:
        query += " AND v.cve_identifier LIKE ?"
        params.append("%" + cve + "%")
    if severity:
        query += " AND v.severity_level = ?"
        params.append(severity)
    if asset_id is not None:
        query += " AND v.asset_id = ?"
        params.append(asset_id)
    if status:
        query += " AND v.status = ?"
        params.append(status)

    query += " ORDER BY v.creation_date DESC, v.vulnerability_id DESC"

    conn = connect_to_db()
    try:
        cur = conn.cursor()
        cur.execute(query, tuple(params))
        return rows_to_list(cur.fetchall())
    finally:
        conn.close()


def delete_vulnerability(vulnerability_id):
    """Delete one vulnerability record.

    :param vulnerability_id: The vulnerability to delete.
    :type vulnerability_id: int
    :return: ``True`` if a row was actually removed.
    :rtype: bool
    """
    conn = connect_to_db()
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM vulnerabilities WHERE vulnerability_id = ?",
                    (vulnerability_id,))
        conn.commit()
        return cur.rowcount > 0
    except Exception:
        conn.rollback()
        return False
    finally:
        conn.close()
