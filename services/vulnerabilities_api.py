"""REST API for Service 7 -- Vulnerability Management.

Six endpoints, as required by the specification:

====== ==================================== ===================================
Method Endpoint                             Who may call it
====== ==================================== ===================================
POST   /vulnerabilities                     Security Administrator
GET    /vulnerabilities                     Administrator, Analyst, Auditor
GET    /vulnerabilities/{id}                Administrator, Analyst, Auditor
PUT    /vulnerabilities/{id}                Administrator, Analyst
GET    /vulnerabilities/search              Administrator, Analyst, Auditor
DELETE /vulnerabilities/{id}                Security Administrator
====== ==================================== ===================================

Regular Employees have no access to this service at all, so they are absent
from every decorator in this file.

Like incidents, vulnerabilities walk a fixed lifecycle, but theirs has an
extra ``In Progress`` step for remediation work:
``Open -> Under Investigation -> In Progress -> Resolved -> Closed``.

:author: Karim Hajj Ali
"""

from datetime import datetime

from flask import Blueprint, jsonify, request

import constants
from audit import write_log
from auth import current_user, require_role
from database import record_exists
from models import ValidationError, Vulnerability, VulnerabilityWorkflow
from services.notifications_db import send_notification
from services.vulnerabilities_db import (
    delete_vulnerability,
    get_vulnerabilities,
    get_vulnerability_by_id,
    insert_vulnerability,
    search_vulnerabilities,
    update_vulnerability,
)

vulnerabilities_bp = Blueprint("vulnerabilities", __name__)

SERVICE_NAME = "Vulnerability Management"

#: One shared workflow object -- it holds no per-request state.
WORKFLOW = VulnerabilityWorkflow()

#: A new vulnerability at or above this severity alerts the asset owner.
_ALERT_SEVERITIES = ("High", "Critical")


# ---------------------------------------------------------------------------
# 1. Add New Vulnerability
# ---------------------------------------------------------------------------

# Route owner: Karim Hajj Ali
@vulnerabilities_bp.route("/vulnerabilities", methods=["POST"])
@require_role(constants.ROLE_ADMIN)
def api_create_vulnerability():
    """Register a newly discovered vulnerability against an asset.

    Developed by Karim Hajj Ali.

    Expects ``title``, ``description``, ``severity`` and ``affected_asset``.
    ``cve_identifier``, ``cvss_score`` and ``discovery_source`` are optional
    but validated when present.

    A High or Critical finding also raises a ``Vulnerability Alert`` for the
    owner of the affected asset, which is the hand-off into Service 8.

    :return: ``201`` with the stored vulnerability, ``400`` on a validation
        error, or ``404`` if the affected asset does not exist.
    :rtype: flask.Response
    """
    body = request.get_json(silent=True) or {}
    caller = current_user()

    try:
        vulnerability = Vulnerability(
            title=body.get("title"),
            description=body.get("description"),
            severity=body.get("severity"),
            asset_id=body.get("affected_asset"),
            cve_identifier=body.get("cve_identifier"),
            cvss_score=body.get("cvss_score"),
            discovery_source=body.get("discovery_source"))
        vulnerability.validate()
    except ValidationError as error:
        return jsonify({"status": "error", "message": error.message}), 400

    if not record_exists("assets", "asset_id", vulnerability.get_asset_id()):
        return jsonify({
            "status": "error",
            "message": "No asset with id %s exists"
                       % vulnerability.get_asset_id(),
        }), 404

    stored = insert_vulnerability(vulnerability.to_row())
    if not stored:
        return jsonify({
            "status": "error",
            "message": "The vulnerability could not be saved",
        }), 500

    write_log(caller["user_id"], "Vulnerability created",
              "Vulnerability %s '%s' (%s) logged against asset %s"
              % (stored["vulnerability_id"], stored["title"],
                 stored["severity_level"], stored["asset_id"]),
              "Warning" if stored["severity_level"] in _ALERT_SEVERITIES
              else "Information",
              SERVICE_NAME)

    # Service 8 hand-off: warn the asset owner about serious findings.
    if (stored["severity_level"] in _ALERT_SEVERITIES
            and stored["affected_asset_owner_id"]):
        send_notification(
            user_id=stored["affected_asset_owner_id"],
            title="%s vulnerability on %s"
                  % (stored["severity_level"],
                     stored["affected_asset_name"]),
            message="'%s' was found on your asset '%s'. CVE: %s. "
                    "CVSS score: %s."
                    % (stored["title"], stored["affected_asset_name"],
                       stored["cve_identifier"] or "not assigned",
                       stored["cvss_score"]
                       if stored["cvss_score"] is not None else "not scored"),
            notification_type="Vulnerability Alert",
            severity=stored["severity_level"])

    return jsonify({
        "status": "success",
        "message": "Vulnerability created successfully",
        "vulnerability": stored,
    }), 201


# ---------------------------------------------------------------------------
# 2. Retrieve All Vulnerabilities
# ---------------------------------------------------------------------------

# Route owner: Karim Hajj Ali
@vulnerabilities_bp.route("/vulnerabilities", methods=["GET"])
@require_role(constants.ROLE_ADMIN, constants.ROLE_ANALYST,
              constants.ROLE_AUDITOR)
def api_get_vulnerabilities():
    """Return every vulnerability in the system.

    Developed by Karim Hajj Ali.

    :return: ``200`` with the list, each entry carrying its severity,
        affected asset and current status.
    :rtype: flask.Response
    """
    vulnerabilities = get_vulnerabilities()

    by_severity = {}
    for item in vulnerabilities:
        key = item["severity_level"]
        by_severity[key] = by_severity.get(key, 0) + 1

    return jsonify({
        "status": "success",
        "count": len(vulnerabilities),
        "count_by_severity": by_severity,
        "vulnerabilities": vulnerabilities,
    }), 200


# ---------------------------------------------------------------------------
# 3. Retrieve Specific Vulnerability
# ---------------------------------------------------------------------------

# Route owner: Karim Hajj Ali
@vulnerabilities_bp.route("/vulnerabilities/<int:vulnerability_id>",
                          methods=["GET"])
@require_role(constants.ROLE_ADMIN, constants.ROLE_ANALYST,
              constants.ROLE_AUDITOR)
def api_get_vulnerability(vulnerability_id):
    """Return one vulnerability by its id.

    Developed by Karim Hajj Ali.

    :param vulnerability_id: The vulnerability to return.
    :type vulnerability_id: int
    :return: ``200`` with the vulnerability, or ``404`` if it does not exist.
    :rtype: flask.Response
    """
    vulnerability = get_vulnerability_by_id(vulnerability_id)
    if vulnerability is None:
        return jsonify({
            "status": "error",
            "message": "No vulnerability with id %s exists"
                       % vulnerability_id,
        }), 404

    return jsonify({
        "status": "success",
        "vulnerability": vulnerability,
    }), 200


# ---------------------------------------------------------------------------
# 4. Update Vulnerability Information
# ---------------------------------------------------------------------------

# Route owner: Karim Hajj Ali
@vulnerabilities_bp.route("/vulnerabilities/<int:vulnerability_id>",
                          methods=["PUT"])
@require_role(constants.ROLE_ADMIN, constants.ROLE_ANALYST)
def api_update_vulnerability(vulnerability_id):
    """Update a vulnerability.

    Developed by Karim Hajj Ali.

    Accepts any of ``description``, ``severity``, ``status``, ``cvss_score``
    and ``resolution_date``. Fields that are not sent are left alone.

    A ``status`` change goes through the same lifecycle check as incidents,
    so remediation progress cannot skip steps. Reaching ``Resolved`` stamps
    the resolution date automatically unless one was supplied.

    :param vulnerability_id: The vulnerability to update.
    :type vulnerability_id: int
    :return: ``200`` with the updated record, ``400`` on a validation error,
        or ``404`` if the vulnerability does not exist.
    :rtype: flask.Response
    """
    body = request.get_json(silent=True) or {}
    caller = current_user()

    existing = get_vulnerability_by_id(vulnerability_id)
    if existing is None:
        return jsonify({
            "status": "error",
            "message": "No vulnerability with id %s exists"
                       % vulnerability_id,
        }), 404

    fields = {}

    if "description" in body:
        description = body.get("description")
        if not isinstance(description, str) or not description.strip():
            return jsonify({
                "status": "error",
                "message": "'description' must be a non-empty string",
            }), 400
        fields["description"] = description.strip()

    if "severity" in body:
        severity = body.get("severity")
        if severity not in constants.SEVERITIES:
            return jsonify({
                "status": "error",
                "message": "'severity' must be one of: %s"
                           % ", ".join(constants.SEVERITIES),
            }), 400
        fields["severity_level"] = severity

    if "cvss_score" in body:
        try:
            score = float(body.get("cvss_score"))
        except (TypeError, ValueError):
            return jsonify({
                "status": "error",
                "message": "'cvss_score' must be a number",
            }), 400
        if score < 0.0 or score > 10.0:
            return jsonify({
                "status": "error",
                "message": "'cvss_score' must be between 0.0 and 10.0",
            }), 400
        fields["cvss_score"] = round(score, 1)

    if "resolution_date" in body:
        fields["resolution_date"] = body.get("resolution_date")

    if "status" in body:
        new_status = body.get("status")
        try:
            WORKFLOW.check_transition(existing["status"], new_status)
        except ValidationError as error:
            return jsonify({
                "status": "error",
                "message": error.message,
            }), 400
        fields["status"] = new_status
        if (new_status in constants.VULNERABILITY_CLOSING_STATUSES
                and "resolution_date" not in fields
                and existing["resolution_date"] is None):
            fields["resolution_date"] = datetime.now().isoformat(
                timespec="seconds")

    if not fields:
        return jsonify({
            "status": "error",
            "message": "No updatable fields were supplied. Send any of: "
                       "description, severity, status, cvss_score, "
                       "resolution_date.",
        }), 400

    updated = update_vulnerability(vulnerability_id, fields)
    if updated is None:
        return jsonify({
            "status": "error",
            "message": "The vulnerability could not be updated",
        }), 500

    write_log(caller["user_id"], "Vulnerability updated",
              "Vulnerability %s updated by %s. Fields changed: %s"
              % (vulnerability_id, caller["full_name"],
                 ", ".join(sorted(fields.keys()))),
              "Information", SERVICE_NAME)

    return jsonify({
        "status": "success",
        "message": "Vulnerability updated successfully",
        "fields_updated": sorted(fields.keys()),
        "vulnerability": updated,
    }), 200


# ---------------------------------------------------------------------------
# 5. Search Vulnerabilities
# ---------------------------------------------------------------------------

# Route owner: Karim Hajj Ali
@vulnerabilities_bp.route("/vulnerabilities/search", methods=["GET"])
@require_role(constants.ROLE_ADMIN, constants.ROLE_ANALYST,
              constants.ROLE_AUDITOR)
def api_search_vulnerabilities():
    """Search vulnerabilities by CVE, severity, asset and status.

    Developed by Karim Hajj Ali.

    Criteria arrive as query string parameters and combine with ``AND``::

        GET /vulnerabilities/search?severity=Critical&status=Open

    The CVE filter matches partially, so ``?cve=2024`` returns every CVE
    issued in 2024.

    :return: ``200`` with the matches, or ``400`` if a filter value is not a
        recognised option.
    :rtype: flask.Response
    """
    cve = request.args.get("cve")
    severity = request.args.get("severity")
    asset_id = request.args.get("asset_id")
    status = request.args.get("status")

    if severity and severity not in constants.SEVERITIES:
        return jsonify({
            "status": "error",
            "message": "'severity' must be one of: %s"
                       % ", ".join(constants.SEVERITIES),
        }), 400

    if status and status not in constants.VULNERABILITY_STATUSES:
        return jsonify({
            "status": "error",
            "message": "'status' must be one of: %s"
                       % ", ".join(constants.VULNERABILITY_STATUSES),
        }), 400

    if asset_id is not None:
        try:
            asset_id = int(asset_id)
        except ValueError:
            return jsonify({
                "status": "error",
                "message": "'asset_id' must be an integer",
            }), 400

    results = search_vulnerabilities(
        cve=cve, severity=severity, asset_id=asset_id, status=status)

    return jsonify({
        "status": "success",
        "count": len(results),
        "filters_applied": {
            "cve": cve,
            "severity": severity,
            "asset_id": asset_id,
            "status": status,
        },
        "vulnerabilities": results,
    }), 200


# ---------------------------------------------------------------------------
# 6. Delete Vulnerability
# ---------------------------------------------------------------------------

# Route owner: Karim Hajj Ali
@vulnerabilities_bp.route("/vulnerabilities/<int:vulnerability_id>",
                          methods=["DELETE"])
@require_role(constants.ROLE_ADMIN)
def api_delete_vulnerability(vulnerability_id):
    """Delete a vulnerability record.

    Developed by Karim Hajj Ali.

    Administrators only. An analyst attempting this is refused with ``403``
    and the attempt is recorded in the audit log by
    :func:`auth.require_role`.

    :param vulnerability_id: The vulnerability to delete.
    :type vulnerability_id: int
    :return: ``200`` on success, or ``404`` if it does not exist.
    :rtype: flask.Response
    """
    caller = current_user()

    existing = get_vulnerability_by_id(vulnerability_id)
    if existing is None:
        return jsonify({
            "status": "error",
            "message": "No vulnerability with id %s exists"
                       % vulnerability_id,
        }), 404

    if not delete_vulnerability(vulnerability_id):
        return jsonify({
            "status": "error",
            "message": "The vulnerability could not be deleted",
        }), 500

    write_log(caller["user_id"], "Vulnerability deleted",
              "Vulnerability %s '%s' was deleted by %s"
              % (vulnerability_id, existing["title"], caller["full_name"]),
              "Warning", SERVICE_NAME)

    return jsonify({
        "status": "success",
        "message": "Vulnerability deleted successfully",
    }), 200
