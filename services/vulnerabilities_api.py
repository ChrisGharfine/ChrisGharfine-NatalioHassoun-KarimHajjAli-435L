"""REST API for Service 7 -- Vulnerability Management.

Ported to team-integration-v1.0.0. Public paths, permissions, envelopes and
Title Case enums are unchanged; the authentication, the asset lookup and
the audit/notification delivery underneath them are all new.

:author: Karim Hajj Ali
"""

from flask import Blueprint, jsonify, request

import config
import constants
import db
from clients.assets_client import AssetsUnavailable, lookup_asset
from models import ValidationError, Vulnerability, VulnerabilityWorkflow
from outbox.audit_outbox import (
    ACTION_VULNERABILITY_CREATED,
    ACTION_VULNERABILITY_DELETED,
    ACTION_VULNERABILITY_UPDATED,
    queue_audit_event,
)
from outbox.notification_outbox import queue_notification
from security.guard import current_user, error, require_role
from security.identity import IdentityUnavailable, is_assignable, lookup_user
from serialization import utc_now
from services.vulnerabilities_db import (
    delete_vulnerability,
    get_vulnerabilities,
    get_vulnerability_by_id,
    insert_vulnerability,
    search_vulnerabilities,
    update_vulnerability,
)

vulnerabilities_bp = Blueprint("vulnerabilities", __name__)

SERVICE = config.SERVICE_VULNERABILITIES

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

    The affected asset is resolved through Chris's internal lookup, which
    also supplies the owner to notify when the finding is High or Critical.

    :return: ``201`` with the stored vulnerability, ``400`` on a validation
        error, ``404`` if the asset does not exist, or ``503`` if Assets or
        Users cannot be consulted.
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
    except ValidationError as failure:
        return error(failure.message, 400)

    try:
        asset = lookup_asset(vulnerability.get_asset_id(), SERVICE)
    except AssetsUnavailable as failure:
        return error(failure.message, 503)

    if asset is None:
        return error("No asset with id %s exists"
                     % vulnerability.get_asset_id(), 404)

    severity = vulnerability.get_severity()
    owner_id = asset.get("owner_id")
    notify_owner = severity in _ALERT_SEVERITIES and owner_id is not None

    # Only alert an owner who can actually receive it. An inactive or
    # deleted owner is not an error for the vulnerability itself.
    if notify_owner:
        try:
            owner = lookup_user(owner_id, SERVICE)
        except IdentityUnavailable as failure:
            return error(failure.message, 503)
        notify_owner = is_assignable(owner)

    row = vulnerability.to_row()
    with db.transaction() as cur:
        stored = insert_vulnerability(cur, row)
        queue_audit_event(
            source_service=SERVICE,
            user_id=caller["id"],
            action=ACTION_VULNERABILITY_CREATED,
            description="Vulnerability %s (%s) logged against asset %s"
                        % (stored["vulnerability_id"],
                           stored["severity_level"], stored["asset_id"]),
            severity="Warning" if severity in _ALERT_SEVERITIES
                     else "Information",
            related_service=SERVICE,
            cursor=cur)

        if notify_owner:
            queue_notification(
                source_service=SERVICE,
                recipient_user_id=owner_id,
                actor_user_id=caller["id"],
                title="%s vulnerability on %s"
                      % (severity, asset.get("name") or
                         "asset %s" % stored["asset_id"]),
                message="'%s' was found on your asset. CVE: %s. "
                        "CVSS score: %s."
                        % (stored["title"],
                           stored["cve_identifier"] or "not assigned",
                           stored["cvss_score"]
                           if stored["cvss_score"] is not None
                           else "not scored"),
                notification_type="Vulnerability Alert",
                severity_level=severity,
                cursor=cur)

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

    :return: ``200`` with the complete list.
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
    :return: ``200`` with the vulnerability, or ``404``.
    :rtype: flask.Response
    """
    vulnerability = get_vulnerability_by_id(vulnerability_id)
    if vulnerability is None:
        return error("No vulnerability with id %s exists" % vulnerability_id,
                     404)
    return jsonify({"status": "success",
                    "vulnerability": vulnerability}), 200


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

    :param vulnerability_id: The vulnerability to update.
    :type vulnerability_id: int
    :return: ``200`` with the updated record, ``400`` on a validation error,
        or ``404``.
    :rtype: flask.Response
    """
    body = request.get_json(silent=True) or {}
    caller = current_user()

    existing = get_vulnerability_by_id(vulnerability_id)
    if existing is None:
        return error("No vulnerability with id %s exists" % vulnerability_id,
                     404)

    fields = {}

    if "description" in body:
        description = body.get("description")
        if not isinstance(description, str) or not description.strip():
            return error("'description' must be a non-empty string", 400)
        fields["description"] = description.strip()

    if "severity" in body:
        severity = body.get("severity")
        if severity not in constants.SEVERITIES:
            return error("'severity' must be one of: %s"
                         % ", ".join(constants.SEVERITIES), 400)
        fields["severity_level"] = severity

    if "cvss_score" in body:
        try:
            score = float(body.get("cvss_score"))
        except (TypeError, ValueError):
            return error("'cvss_score' must be a number", 400)
        if score < 0.0 or score > 10.0:
            return error("'cvss_score' must be between 0.0 and 10.0", 400)
        fields["cvss_score"] = round(score, 1)

    if "resolution_date" in body:
        fields["resolution_date"] = body.get("resolution_date")

    if "status" in body:
        new_status = body.get("status")
        try:
            WORKFLOW.check_transition(existing["status"], new_status)
        except ValidationError as failure:
            return error(failure.message, 400)
        fields["status"] = new_status
        if (new_status in constants.VULNERABILITY_CLOSING_STATUSES
                and "resolution_date" not in fields
                and existing["resolution_date"] is None):
            fields["resolution_date"] = utc_now()

    if not fields:
        return error("No updatable fields were supplied. Send any of: "
                     "description, severity, status, cvss_score, "
                     "resolution_date.", 400)

    with db.transaction() as cur:
        updated = update_vulnerability(cur, vulnerability_id, fields)
        queue_audit_event(
            source_service=SERVICE,
            user_id=caller["id"],
            action=ACTION_VULNERABILITY_UPDATED,
            description="Vulnerability %s updated. Fields changed: %s"
                        % (vulnerability_id, ", ".join(sorted(fields))),
            severity="Information",
            related_service=SERVICE,
            cursor=cur)

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

    :return: ``200`` with the matches, or ``400`` on an invalid filter.
    :rtype: flask.Response
    """
    cve = request.args.get("cve")
    severity = request.args.get("severity")
    asset_id = request.args.get("asset_id")
    status = request.args.get("status")

    if severity and severity not in constants.SEVERITIES:
        return error("'severity' must be one of: %s"
                     % ", ".join(constants.SEVERITIES), 400)

    if status and status not in constants.VULNERABILITY_STATUSES:
        return error("'status' must be one of: %s"
                     % ", ".join(constants.VULNERABILITY_STATUSES), 400)

    if asset_id is not None:
        try:
            asset_id = int(asset_id)
        except ValueError:
            return error("'asset_id' must be an integer", 400)

    results = search_vulnerabilities(cve=cve, severity=severity,
                                     asset_id=asset_id, status=status)

    return jsonify({
        "status": "success",
        "count": len(results),
        "filters_applied": {"cve": cve, "severity": severity,
                            "asset_id": asset_id, "status": status},
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

    :param vulnerability_id: The vulnerability to delete.
    :type vulnerability_id: int
    :return: ``200`` on success, or ``404``.
    :rtype: flask.Response
    """
    caller = current_user()

    existing = get_vulnerability_by_id(vulnerability_id)
    if existing is None:
        return error("No vulnerability with id %s exists" % vulnerability_id,
                     404)

    with db.transaction() as cur:
        removed = delete_vulnerability(cur, vulnerability_id)
        if not removed:
            return error("The vulnerability could not be deleted", 500)
        queue_audit_event(
            source_service=SERVICE,
            user_id=caller["id"],
            action=ACTION_VULNERABILITY_DELETED,
            description="Vulnerability %s deleted" % vulnerability_id,
            severity="Warning",
            related_service=SERVICE,
            cursor=cur)

    return jsonify({"status": "success",
                    "message": "Vulnerability deleted successfully"}), 200
