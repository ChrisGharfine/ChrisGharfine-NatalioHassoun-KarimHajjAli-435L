"""PostgreSQL access for Karim's three services.

Replaces the SQLite layer from Sprint I. Differences worth knowing:

* ``psycopg`` 3 with ``dict_row`` gives dictionaries straight out of the
  cursor, which is what the old ``sqlite3.Row`` conversion was doing.
* Placeholders are ``%s`` rather than ``?``. Every value from a request is
  still bound, never formatted into the statement.
* Foreign keys are enforced by PostgreSQL itself, so there is no equivalent
  of the ``PRAGMA foreign_keys = ON`` the SQLite version needed.
* ``transaction()`` gives an explicit unit of work, which section 6 of the
  integration spec requires: a business mutation and its audit outbox event
  have to commit together or not at all.

:author: Karim Hajj Ali
"""

from contextlib import contextmanager

import psycopg
from psycopg.rows import dict_row

import config


@contextmanager
def connect():
    """Open a connection that commits on success and rolls back on error.

    :return: A context manager yielding an open connection.
    :rtype: contextlib.AbstractContextManager
    """
    conn = psycopg.connect(config.database_url(), row_factory=dict_row)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@contextmanager
def transaction():
    """Open a connection and yield a cursor inside one transaction.

    Everything done with the cursor commits together. This is the unit of
    work used wherever a business change and its outbox event must be
    atomic.

    :return: A context manager yielding a cursor.
    :rtype: contextlib.AbstractContextManager
    """
    with connect() as conn:
        with conn.cursor() as cur:
            yield cur


def query_all(sql, params=()):
    """Run a SELECT and return every row.

    :param sql: SQL with ``%s`` placeholders.
    :type sql: str
    :param params: Values to bind.
    :type params: tuple
    :return: One dictionary per row.
    :rtype: list
    """
    with transaction() as cur:
        cur.execute(sql, params)
        return cur.fetchall()


def query_one(sql, params=()):
    """Run a SELECT and return the first row.

    :param sql: SQL with ``%s`` placeholders.
    :type sql: str
    :param params: Values to bind.
    :type params: tuple
    :return: The row, or ``None`` if there was none.
    :rtype: dict or NoneType
    """
    with transaction() as cur:
        cur.execute(sql, params)
        return cur.fetchone()


def execute(sql, params=()):
    """Run a statement that changes rows and return how many it touched.

    :param sql: SQL with ``%s`` placeholders.
    :type sql: str
    :param params: Values to bind.
    :type params: tuple
    :return: Affected row count.
    :rtype: int
    """
    with transaction() as cur:
        cur.execute(sql, params)
        return cur.rowcount


def table_exists(table_name):
    """Check whether a table is present in the current schema.

    :param table_name: Unqualified table name.
    :type table_name: str
    :return: ``True`` if it exists.
    :rtype: bool
    """
    row = query_one(
        "SELECT to_regclass(%s) IS NOT NULL AS present", (table_name,))
    return bool(row and row["present"])


def ping():
    """Check that the database answers.

    :return: ``True`` if a trivial query succeeds.
    :rtype: bool
    """
    try:
        return query_one("SELECT 1 AS ok")["ok"] == 1
    except Exception:
        return False
