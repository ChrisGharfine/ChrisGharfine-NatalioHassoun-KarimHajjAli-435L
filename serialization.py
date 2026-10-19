"""Turning database rows into JSON-ready dictionaries.

Two things need converting before a row can be handed to ``jsonify``:

* ``TIMESTAMPTZ`` values come back as aware ``datetime`` objects. Section 8
  requires timezone-aware ISO 8601 on the wire representing UTC, so they are
  normalised to UTC and serialised with an explicit offset.
* ``NUMERIC`` values come back as ``Decimal``, which is not JSON
  serialisable. The only one I store is the CVSS score, which is a number
  with one decimal place.

:author: Karim Hajj Ali
"""

from datetime import datetime, timezone
from decimal import Decimal


def to_utc_iso(value):
    """Render a datetime as timezone-aware ISO 8601 in UTC.

    A naive datetime would be ambiguous, so one is rejected rather than
    guessed at. Section 3 is explicit that naive values must be converted
    using their real original timezone, never relabelled as UTC.

    :param value: The value to render.
    :type value: datetime.datetime or NoneType
    :raises ValueError: If the datetime has no timezone.
    :return: ISO 8601 with an offset, or ``None``.
    :rtype: str or NoneType
    """
    if value is None:
        return None
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError(
            "refusing to serialise a naive datetime: its real timezone is "
            "unknown and assuming UTC would silently shift the time")
    return value.astimezone(timezone.utc).isoformat()


def utc_now():
    """Return the current time as an aware UTC datetime.

    :return: Now, in UTC.
    :rtype: datetime.datetime
    """
    return datetime.now(timezone.utc)


def jsonify_row(row):
    """Convert one database row into JSON-ready values.

    :param row: A row from psycopg's dict row factory.
    :type row: dict or NoneType
    :return: The same mapping with datetimes and decimals converted.
    :rtype: dict or NoneType
    """
    if row is None:
        return None

    output = {}
    for key, value in row.items():
        if isinstance(value, datetime):
            output[key] = to_utc_iso(value)
        elif isinstance(value, Decimal):
            output[key] = float(value)
        else:
            output[key] = value
    return output


def jsonify_rows(rows):
    """Convert a list of database rows.

    :param rows: Rows from a query.
    :type rows: list
    :return: One converted dictionary per row.
    :rtype: list
    """
    return [jsonify_row(row) for row in rows]
