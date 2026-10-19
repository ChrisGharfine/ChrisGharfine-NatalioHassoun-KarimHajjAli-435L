"""Create the database and fill it with enough data to demonstrate things.

Services 3, 7 and 8 all point at users and assets, which belong to other
team members' services. Until those exist there would be nothing to attach
an incident to, so this script inserts a small, realistic set of users and
assets to work against.

It is destructive -- it clears the tables it owns before inserting -- so
screenshots taken after running it always show the same starting point.

Run it with::

    python seed.py

:author: Karim Hajj Ali
"""

from datetime import datetime

from auth import hash_password
from database import connect_to_db, create_db_tables

#: One account per role, so every permission case can be demonstrated.
#: Passwords are only this simple because this is seed data for a demo.
USERS = [
    ("Karim Hajj Ali", "karim.admin", "karim.admin@aub.edu.lb",
     "Admin#2026", "Information Security", "Security Administrator"),
    ("Rana Khoury", "rana.analyst", "rana.analyst@aub.edu.lb",
     "Analyst#2026", "Security Operations", "Security Analyst"),
    ("Omar Saleh", "omar.analyst", "omar.analyst@aub.edu.lb",
     "Analyst#2026", "Security Operations", "Security Analyst"),
    ("Lina Haddad", "lina.employee", "lina.employee@aub.edu.lb",
     "Employee#2026", "Finance", "Regular Employee"),
    ("Samir Fares", "samir.auditor", "samir.auditor@aub.edu.lb",
     "Auditor#2026", "Internal Audit", "Auditor"),
]

#: A spread of asset types and criticality levels, so searches return
#: something interesting.
ASSETS = [
    ("Primary Domain Controller", "Server", "10.0.1.10", "Windows Server 2022",
     1, "Information Security", "Data Centre A", "Critical", "Active"),
    ("Finance File Server", "Server", "10.0.1.25", "Ubuntu 22.04",
     4, "Finance", "Data Centre A", "High", "Active"),
    ("HR Workstation 14", "Workstation", "10.0.4.114", "Windows 11",
     4, "Human Resources", "Building B", "Medium", "Active"),
    ("Customer Records Database", "Database", "10.0.2.50", "Oracle Linux 9",
     1, "Information Security", "Data Centre B", "Critical", "Active"),
    ("Branch Office Router", "Network Device", "192.168.20.1", "Cisco IOS",
     2, "IT Operations", "Branch Office", "High", "Under Maintenance"),
    ("Payroll Web Application", "Application", "10.0.3.80", "Debian 12",
     4, "Finance", "Cloud Region EU", "High", "Active"),
]


def clear_tables():
    """Empty every table, in an order the foreign keys allow.

    Children are deleted before parents, otherwise SQLite refuses the delete
    now that foreign key enforcement is switched on.

    :return: ``None``
    :rtype: NoneType
    """
    conn = connect_to_db()
    try:
        for table in ("investigation_notes", "notifications",
                      "vulnerabilities", "incidents", "logs",
                      "response_actions", "playbooks", "threats",
                      "assets", "users"):
            conn.execute("DELETE FROM %s" % table)
            # Reset the autoincrement counters so ids start at 1 again and
            # the ids in the report screenshots stay predictable.
            conn.execute("DELETE FROM sqlite_sequence WHERE name = ?",
                         (table,))
        conn.commit()
        print("Existing data cleared")
    except Exception as error:
        conn.rollback()
        print("Could not clear the tables: %s" % error)
    finally:
        conn.close()


def seed_users():
    """Insert one user per role, with properly hashed passwords.

    :return: ``None``
    :rtype: NoneType
    """
    conn = connect_to_db()
    try:
        now = datetime.now().isoformat(timespec="seconds")
        for full_name, username, email, password, department, role in USERS:
            conn.execute(
                "INSERT INTO users (full_name, username, email, "
                "password_hash, department, role, account_status, "
                "created_date) VALUES (?, ?, ?, ?, ?, ?, 'Active', ?)",
                (full_name, username, email, hash_password(password),
                 department, role, now))
        conn.commit()
        print("Inserted %d users" % len(USERS))
    except Exception as error:
        conn.rollback()
        print("Could not insert the users: %s" % error)
    finally:
        conn.close()


def seed_assets():
    """Insert the sample organisational assets.

    :return: ``None``
    :rtype: NoneType
    """
    conn = connect_to_db()
    try:
        conn.executemany(
            "INSERT INTO assets (asset_name, asset_type, ip_address, "
            "operating_system, owner_id, department, location, "
            "criticality_level, status) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", ASSETS)
        conn.commit()
        print("Inserted %d assets" % len(ASSETS))
    except Exception as error:
        conn.rollback()
        print("Could not insert the assets: %s" % error)
    finally:
        conn.close()


def print_credentials():
    """Print the demo logins, so they are easy to copy into Postman.

    :return: ``None``
    :rtype: NoneType
    """
    print("\nDemo accounts")
    print("-" * 62)
    print("%-16s %-16s %s" % ("username", "password", "role"))
    print("-" * 62)
    for _, username, _, password, _, role in USERS:
        print("%-16s %-16s %s" % (username, password, role))
    print("-" * 62)


if __name__ == "__main__":
    create_db_tables()
    clear_tables()
    seed_users()
    seed_assets()
    print_credentials()
