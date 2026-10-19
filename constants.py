"""Shared vocabulary for the whole system.

Every enumerated value the specification mentions is written down once, here,
so that the nine services all spell them the same way. A typo like
``"under investigation"`` instead of ``"Under Investigation"`` would silently
break cross-service calls, so nothing hard-codes these strings anywhere else.

:author: Karim Hajj Ali
"""

# -- Roles -------------------------------------------------------------------
#
# Canonical role strings, fixed by section 4.2 of team-integration-v1.0.0.
# These are the values Natalio's identity service returns and the only ones
# used for permission decisions. They are internal authorisation constants,
# not part of any report contract, so the snake_case spelling here does not
# affect the Title Case severity and status enums below.

ROLE_ADMIN = "security_administrator"
ROLE_ANALYST = "security_analyst"
ROLE_EMPLOYEE = "regular_employee"
ROLE_AUDITOR = "auditor"

ROLES = (ROLE_ADMIN, ROLE_ANALYST, ROLE_EMPLOYEE, ROLE_AUDITOR)

#: Sprint I stored roles as display strings. Any that survive in old data are
#: mapped explicitly rather than compared loosely, so an unrecognised value
#: fails closed instead of matching by accident.
LEGACY_ROLE_MAP = {
    "Security Administrator": ROLE_ADMIN,
    "Security Analyst": ROLE_ANALYST,
    "Regular Employee": ROLE_EMPLOYEE,
    "Regular Employee/User": ROLE_EMPLOYEE,
    "Auditor": ROLE_AUDITOR,
}


def canonical_role(value):
    """Map any accepted spelling of a role to its canonical constant.

    :param value: A role string from a token, an identity response or old data.
    :type value: str
    :return: The canonical role, or ``None`` when it is not recognised.
    :rtype: str or NoneType
    """
    if value in ROLES:
        return value
    return LEGACY_ROLE_MAP.get(value)


# -- Account status (Service 1) ----------------------------------------------
#
# Lower-case states, fixed by section 4.2.

ACCOUNT_ACTIVE = "active"
ACCOUNT_STATUSES = ("active", "inactive", "suspended")

# -- Severity (shared by incidents, threats, vulnerabilities, notifications) --

SEVERITIES = ("Low", "Medium", "High", "Critical")

# -- Incidents (Service 3) ---------------------------------------------------

INCIDENT_STATUSES = (
    "Open",
    "Under Investigation",
    "Mitigated",
    "Resolved",
    "Closed",
)

#: Categories are suggestions from the spec, not a closed list, so the API
#: accepts any non-empty string. Kept here for the Postman examples.
INCIDENT_CATEGORIES = (
    "Malware Infection",
    "Unauthorized Access",
    "Phishing Attack",
    "Data Leakage",
    "Account Compromise",
    "Denial of Service",
)

# -- Vulnerabilities (Service 7) ---------------------------------------------

VULNERABILITY_STATUSES = (
    "Open",
    "Under Investigation",
    "In Progress",
    "Resolved",
    "Closed",
)

#: A vulnerability is considered "closed out" at these statuses, which is when
#: the resolution date gets stamped.
VULNERABILITY_CLOSING_STATUSES = ("Resolved", "Closed")

# -- Notifications (Service 8) -----------------------------------------------

NOTIFICATION_TYPES = (
    "Incident Assignment",
    "Security Alert",
    "System Notification",
    "Threat Alert",
    "Vulnerability Alert",
)

NOTIFICATION_STATUSES = ("Unread", "Read")

# -- Audit logs (Service 5) --------------------------------------------------

LOG_SEVERITIES = ("Information", "Warning", "Error", "Critical")

# -- Assets (Service 2) ------------------------------------------------------

ASSET_CRITICALITY = ("Low", "Medium", "High", "Critical")
ASSET_STATUSES = ("Active", "Inactive", "Under Maintenance")
