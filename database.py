"""Database access helpers shared by every service.

Same approach as Lab 5: plain ``sqlite3``, one connection per operation,
parameterised queries only. The two things added on top of the lab are
``PRAGMA foreign_keys = ON`` (SQLite ignores foreign keys unless you ask for
them, which would silently let an incident point at a user that does not
exist) and ``row_factory`` being set before the cursor is created so rows
come back as dictionaries ready for ``jsonify``.

:author: Karim Hajj Ali
"""

import os
import sqlite3

#: The database file sits next to the code, exactly as in Lab 5.
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "database.db")

#: Path to the schema that :func:`create_db_tables` executes.
SCHEMA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "schema.sql")


def connect_to_db():
    """Open a connection to the SQLite database.

    Foreign key enforcement is switched on for every connection, and rows are
    returned as :class:`sqlite3.Row` so they can be turned into dictionaries.

    :return: An open connection.
    :rtype: sqlite3.Connection
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def create_db_tables():
    """Create every table in :data:`SCHEMA_PATH` if it does not exist yet.

    Safe to run repeatedly -- the schema uses ``CREATE TABLE IF NOT EXISTS``.

    :return: ``None``
    :rtype: NoneType
    """
    conn = connect_to_db()
    try:
        with open(SCHEMA_PATH, "r", encoding="utf-8") as schema_file:
            conn.executescript(schema_file.read())
        conn.commit()
        print("Database ready at %s" % DB_PATH)
    except sqlite3.Error as error:
        conn.rollback()
        print("Could not create the tables: %s" % error)
    finally:
        conn.close()


def rows_to_list(rows):
    """Turn a list of :class:`sqlite3.Row` objects into plain dictionaries.

    :param rows: Rows straight out of ``cursor.fetchall()``.
    :type rows: list
    :return: One dictionary per row.
    :rtype: list
    """
    return [dict(row) for row in rows]


def row_to_dict(row):
    """Turn a single :class:`sqlite3.Row` into a dictionary.

    :param row: A row from ``cursor.fetchone()``, possibly ``None``.
    :type row: sqlite3.Row or NoneType
    :return: The row as a dictionary, or ``None`` if there was no row.
    :rtype: dict or NoneType
    """
    return dict(row) if row is not None else None


def record_exists(table, id_column, record_id):
    """Check that a row with the given id exists.

    Used before inserting a foreign key so the API can answer with a clear
    ``404`` instead of letting SQLite raise an integrity error.

    The ``table`` and ``id_column`` arguments are never taken from user input
    -- they are always literals written in this codebase -- which is why they
    can be formatted into the SQL string. Everything that *does* come from the
    request is bound as a parameter.

    :param table: Table name to look in.
    :type table: str
    :param id_column: Primary key column name.
    :type id_column: str
    :param record_id: The id to look for.
    :type record_id: int
    :return: ``True`` if a matching row exists.
    :rtype: bool
    """
    conn = connect_to_db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM %s WHERE %s = ?" % (table, id_column),
                    (record_id,))
        return cur.fetchone() is not None
    finally:
        conn.close()


if __name__ == "__main__":
    create_db_tables()
