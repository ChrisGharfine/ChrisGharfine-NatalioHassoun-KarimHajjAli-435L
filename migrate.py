"""Apply Karim's owned migrations.

Deliberately small and explicit rather than Alembic. Section 3 of
team-integration-v1.0.0 forbids any metadata-wide ``create_all`` that could
create placeholder tables for another owner, and a hand-written runner over
plain SQL files makes it obvious that only my four business tables and my
three delivery tables are ever touched.

History lives in ``karim_schema_versions``, which is mine. Natalio has
``student1_schema_versions`` and Chris has ``chris_alembic_version``; the
three never collide.

Run it with::

    python migrate.py            apply anything outstanding
    python migrate.py --status   show what is applied without changing it

:author: Karim Hajj Ali
"""

import hashlib
import os
import sys
from datetime import datetime, timezone

import db

MIGRATIONS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "migrations")

#: Tables another owner creates. Section 3 puts their migrations before mine,
#: and my foreign keys cannot be created until they exist.
REQUIRED_UPSTREAM_TABLES = {
    "users": "Natalio (Service 1)",
    "assets": "Chris (Service 2)",
}

VERSION_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS karim_schema_versions (
    version     TEXT        PRIMARY KEY,
    checksum    TEXT        NOT NULL,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
)
"""


def available_migrations():
    """List the migration files on disk, in order.

    :return: ``(version, absolute path)`` tuples sorted by version.
    :rtype: list
    """
    if not os.path.isdir(MIGRATIONS_DIR):
        return []
    names = sorted(name for name in os.listdir(MIGRATIONS_DIR)
                   if name.endswith(".sql"))
    return [(name[:-4], os.path.join(MIGRATIONS_DIR, name)) for name in names]


def checksum(path):
    """Return a stable digest of a migration file.

    Stored alongside the version so an already-applied migration that was
    later edited is reported rather than silently ignored.

    :param path: Path to the ``.sql`` file.
    :type path: str
    :return: Hex SHA-256 digest.
    :rtype: str
    """
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def applied_versions():
    """Return the migrations already recorded as applied.

    :return: Mapping of version to stored checksum.
    :rtype: dict
    """
    rows = db.query_all(
        "SELECT version, checksum FROM karim_schema_versions ORDER BY version")
    return {row["version"]: row["checksum"] for row in rows}


def check_upstream_tables():
    """Verify the tables my foreign keys point at already exist.

    :raises RuntimeError: If ``users`` or ``assets`` is missing.
    :return: ``None``
    :rtype: NoneType
    """
    missing = [(name, owner) for name, owner in REQUIRED_UPSTREAM_TABLES.items()
               if not db.table_exists(name)]
    if not missing:
        return

    lines = ["Cannot apply my migrations: required upstream tables are "
             "missing from this database."]
    for name, owner in missing:
        lines.append("  - %-8s owned by %s" % (name, owner))
    lines.append("")
    lines.append("Section 3 of team-integration-v1.0.0 applies Natalio's "
                 "migrations first, then Chris's, then mine. I must not "
                 "create another owner's tables.")
    lines.append("")
    lines.append("For solo development without the teammates' services, run:")
    lines.append("    python devtools/bootstrap_dev_dependencies.py")
    lines.append("which creates minimal stand-ins. Never run that against "
                 "the real integration database.")
    raise RuntimeError("\n".join(lines))


def apply_migration(version, path):
    """Apply one migration file and record it, in a single transaction.

    :param version: Version identifier, the file name without ``.sql``.
    :type version: str
    :param path: Path to the file.
    :type path: str
    :return: ``None``
    :rtype: NoneType
    """
    with open(path, "r", encoding="utf-8") as handle:
        sql = handle.read()

    with db.transaction() as cur:
        cur.execute(sql)
        cur.execute(
            "INSERT INTO karim_schema_versions (version, checksum, applied_at)"
            " VALUES (%s, %s, %s)",
            (version, checksum(path), datetime.now(timezone.utc)))


def show_status():
    """Print which migrations are applied and which are outstanding.

    :return: Number of outstanding migrations.
    :rtype: int
    """
    db.execute(VERSION_TABLE_SQL)
    applied = applied_versions()
    outstanding = 0

    print("%-28s %-10s %s" % ("migration", "state", "note"))
    print("-" * 70)
    for version, path in available_migrations():
        current = checksum(path)
        if version not in applied:
            print("%-28s %-10s" % (version, "pending"))
            outstanding += 1
        elif applied[version] != current:
            print("%-28s %-10s %s" % (version, "APPLIED",
                                      "file changed since it was applied"))
        else:
            print("%-28s %-10s" % (version, "applied"))
    print("-" * 70)
    return outstanding


def main(argv):
    """Entry point.

    :param argv: Command line arguments without the program name.
    :type argv: list
    :return: Process exit code.
    :rtype: int
    """
    if "--status" in argv:
        outstanding = show_status()
        print("%d outstanding" % outstanding)
        return 0

    try:
        check_upstream_tables()
    except RuntimeError as error:
        print(error)
        return 2

    db.execute(VERSION_TABLE_SQL)
    applied = applied_versions()

    pending = [(version, path) for version, path in available_migrations()
               if version not in applied]

    if not pending:
        print("Nothing to apply. %d migration(s) already recorded."
              % len(applied))
        return 0

    for version, path in pending:
        print("applying %s ..." % version, end=" ")
        apply_migration(version, path)
        print("done")

    print("\nApplied %d migration(s)." % len(pending))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
