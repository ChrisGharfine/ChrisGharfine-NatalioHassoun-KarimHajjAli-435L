"""REST API for Service 3 -- Incident Management.

Public paths and permissions are unchanged from Sprint I. What changed
under team-integration-v1.0.0 is everything behind them:

* ``@require_role`` now verifies a real JWT and asks Users for the
  caller's current role on every request.
* Reporter, analyst and asset existence are checked over HTTP against
  Natalio's and Chris's services instead of by querying their tables.
* Each mutation and its audit event commit in one transaction; the event
  is delivered to Logs later by the worker.
* Assignment queues a notification in the outbox and lets the worker POST
  it to the Notifications service. Nothing is imported from it.

:author: Karim Hajj Ali
"""

from flask import Blueprint, jsonify, request

import config
import constants
import db
from clients.assets_client import AssetsUnavailable, lookup_asset
from models import Incident, IncidentWorkflow, ValidationError, require_text
from outbox.audit_outbox import (
    ACTION_INCIDENT_ASSIGNED,
    ACTION_INCIDENT_CREATED,
    ACTION_INCIDENT_STATUS_UPDATED,
    ACTION_INVESTIGATION_NOTE_ADDED,
    queue_audit_event,
)
from outbox.notification_outbox import queue_notification
from security.guard import current_user, error, require_role
from security.identity import IdentityUnavailable, is_assignable, lookup_user
from services.incidents_db import (
    assign_incident,
    get_incident_by_id,
    get_incident_with_notes,
    get_incidents,
    insert_incident,
    insert_note,
    update_incident_status,
)

incidents_bp = Blueprint("incidents", __name__)

SERVICE = config.SERVICE_INCIDENTS

#: One shared workflow object; it holds no per-request state.
WORKFLOW = IncidentWorkflow()


# ---------------------------------------------------------------------------
# 1. Create Incident
# ---------------------------------------------------------------------------

# Route owner: Karim Hajj Ali
@incidents_bp.route("/incidents", methods=["POST"])
@require_role(constants.ROLE_ADMIN, constants.ROLE_EMPLOYEE)
def api_create_incident():
    """Report a new cybersecurity incident.

    Developed by Karim Hajj Ali.

    :return: ``201`` with the stored incident, ``400`` on a validation
        error, ``404`` if the reporter or asset does not exist, or ``503``
        if Users or Assets cannot be consulted.
    :rtype: flask.Response
    """
    body = request.get_json(silent=True) or {}
    caller = current_user()

    reporter_id = body.get("reporter", caller["id"])
    if caller["role"] == constants.ROLE_EMPLOYEE:
        reporter_id = caller["id"]

    try:
        incident = Incident(
            title=body.get("title"),
            description=body.get("description"),
            category=body.get("category"),
            severity=body.get("severity"),
            reporter_id=reporter_id,
            asset_id=body.get("affected_asset"))
        incident.validate()
    except ValidationError as failure:
        return error(failure.message, 400)

    try:
        reporter = lookup_user(incident.get_reporter_id(), SERVICE)
    except IdentityUnavailable as failure:
        return error(failure.message, 503)

    if reporter is None:
        return error("No user with id %s exists to report this incident"
                     % incident.get_reporter_id(), 404)
    if not is_assignable(reporter):
        return error("User %s cannot be recorded as the reporter because the "
                     "account is not active" % incident.get_reporter_id(), 400)

    if incident.get_asset_id() is not None:
        try:
            asset = lookup_asset(incident.get_asset_id(), SERVICE)
        except AssetsUnavailable as failure:
            return error(failure.message, 503)
        if asset is None:
            return error("No asset with id %s exists"
                         % incident.get_asset_id(), 404)

    row = incident.to_row()
    with db.transaction() as cur:
        stored = insert_incident(cur, row)
        queue_audit_event(
            source_service=SERVICE,
            user_id=caller["id"],
            action=ACTION_INCIDENT_CREATED,
            description="Incident %s reported with severity %s"
                        % (stored["incident_id"], stored["severity"]),
            severity="Warning" if stored["severity"] in ("High", "Critical")
                     else "Information",
            related_service=SERVICE,
            cursor=cur)

    return jsonify({
        "status": "success",
        "message": "Incident created successfully",
        "incident": stored,
    }), 201


# ---------------------------------------------------------------------------
# 2. Retrieve All Incidents
# ---------------------------------------------------------------------------

# Route owner: Karim Hajj Ali
@incidents_bp.route("/incidents", methods=["GET"])
@require_role(constants.ROLE_ADMIN, constants.ROLE_AUDITOR)
def api_get_incidents():
    """Return every incident in the system.

    Developed by Karim Hajj Ali.

    The complete list, with no role-based subset, as section 5 requires of
    a report source.

    :return: ``200`` with the list of incidents.
    :rtype: flask.Response
    """
    incidents = get_incidents()

    by_status = {}
    for incident in incidents:
        by_status[incident["status"]] = by_status.get(incident["status"], 0) + 1

    return jsonify({
        "status": "success",
        "count": len(incidents),
        "count_by_status": by_status,
        "incidents": incidents,
    }), 200


# ---------------------------------------------------------------------------
# 3. Retrieve Specific Incident
# ---------------------------------------------------------------------------

# Route owner: Karim Hajj Ali
@incidents_bp.route("/incidents/<int:incident_id>", methods=["GET"])
@require_role(constants.ROLE_ADMIN, constants.ROLE_ANALYST,
              constants.ROLE_EMPLOYEE, constants.ROLE_AUDITOR)
def api_get_incident(incident_id):
    """Return one incident together with its investigation notes.

    Developed by Karim Hajj Ali.

    :param incident_id: The incident to return.
    :type incident_id: int
    :return: ``200`` with the incident, ``403`` if an employee asks for an
        incident they did not report, or ``404``.
    :rtype: flask.Response
    """
    caller = current_user()
    incident = get_incident_with_notes(incident_id)

    if incident is None:
        return error("No incident with id %s exists" % incident_id, 404)

    if (caller["role"] == constants.ROLE_EMPLOYEE
            and incident["reporter_id"] != caller["id"]):
        return error("User does not have permission to perform this "
                     "operation", 403)

    return jsonify({"status": "success", "incident": incident}), 200


# ---------------------------------------------------------------------------
# 4. Assign Incident to Analyst
# ---------------------------------------------------------------------------

# Route owner: Karim Hajj Ali
@incidents_bp.route("/incidents/<int:incident_id>/assign", methods=["PUT"])
@require_role(constants.ROLE_ADMIN)
def api_assign_incident(incident_id):
    """Assign an incident to a security analyst.

    Developed by Karim Hajj Ali.

    The analyst's role comes from Users over HTTP, so an account that was
    demoted after the token was issued is refused. The assignment, its
    audit event and the notification work all commit together; the
    notification itself is posted to the Notifications service afterwards
    by the worker.

    :param incident_id: The incident to assign.
    :type incident_id: int
    :return: ``200`` with the updated incident, ``400`` if the target is not
        an assignable analyst, ``404``, or ``503`` if Users is unreachable.
    :rtype: flask.Response
    """
    body = request.get_json(silent=True) or {}
    caller = current_user()

    incident = get_incident_by_id(incident_id)
    if incident is None:
        return error("No incident with id %s exists" % incident_id, 404)

    analyst_id = body.get("analyst_id")
    if analyst_id is None:
        return error("'analyst_id' is required", 400)
    try:
        analyst_id = int(analyst_id)
    except (TypeError, ValueError):
        return error("'analyst_id' must be an integer", 400)

    try:
        analyst = lookup_user(analyst_id, SERVICE)
    except IdentityUnavailable as failure:
        return error(failure.message, 503)

    if analyst is None:
        return error("No user with id %s exists" % analyst_id, 404)
    if not is_assignable(analyst):
        return error("User %s cannot be assigned work because the account is "
                     "not active" % analyst_id, 400)
    if analyst["role"] != constants.ROLE_ANALYST:
        return error("User %s is not a Security Analyst, so this incident "
                     "cannot be assigned to them" % analyst_id, 400)

    with db.transaction() as cur:
        updated = assign_incident(cur, incident_id, analyst_id)
        queue_audit_event(
            source_service=SERVICE,
            user_id=caller["id"],
            action=ACTION_INCIDENT_ASSIGNED,
            description="Incident %s assigned to analyst %s"
                        % (incident_id, analyst_id),
            severity="Information",
            related_service=SERVICE,
            cursor=cur)
        queue_notification(
            source_service=SERVICE,
            recipient_user_id=analyst_id,
            actor_user_id=caller["id"],
            title="Incident #%s assigned to you" % incident_id,
            message="You have been assigned incident '%s' (severity %s). "
                    "Current status: %s."
                    % (updated["title"], updated["severity"],
                       updated["status"]),
            notification_type="Incident Assignment",
            severity_level=updated["severity"],
            cursor=cur)

    return jsonify({
        "status": "success",
        "message": "Incident assigned successfully",
        "incident": updated,
    }), 200


# ---------------------------------------------------------------------------
# 5. Update Incident Status
# ---------------------------------------------------------------------------

# Route owner: Karim Hajj Ali
@incidents_bp.route("/incidents/<int:incident_id>/status", methods=["PUT"])
@require_role(constants.ROLE_ADMIN, constants.ROLE_ANALYST)
def api_update_incident_status(incident_id):
    """Move an incident one step along its lifecycle.

    Developed by Karim Hajj Ali.

    ``Open -> Under Investigation -> Mitigated -> Resolved -> Closed``,
    one step at a time.

    :param incident_id: The incident to update.
    :type incident_id: int
    :return: ``200`` with the updated incident, ``400`` if the transition is
        not allowed, or ``404``.
    :rtype: flask.Response
    """
    body = request.get_json(silent=True) or {}
    caller = current_user()

    incident = get_incident_by_id(incident_id)
    if incident is None:
        return error("No incident with id %s exists" % incident_id, 404)

    new_status = body.get("status")
    if new_status is None:
        return error("'status' is required", 400)

    try:
        WORKFLOW.check_transition(incident["status"], new_status)
    except ValidationError as failure:
        return error(failure.message, 400)

    with db.transaction() as cur:
        updated = update_incident_status(cur, incident_id, new_status)
        queue_audit_event(
            source_service=SERVICE,
            user_id=caller["id"],
            action=ACTION_INCIDENT_STATUS_UPDATED,
            description="Incident %s moved from '%s' to '%s'"
                        % (incident_id, incident["status"], new_status),
            severity="Information",
            related_service=SERVICE,
            cursor=cur)

    return jsonify({
        "status": "success",
        "message": "Incident status updated from '%s' to '%s'"
                   % (incident["status"], new_status),
        "next_allowed_status": WORKFLOW.next_allowed(new_status),
        "incident": updated,
    }), 200


# ---------------------------------------------------------------------------
# 6. Add Investigation Notes
# ---------------------------------------------------------------------------

# Route owner: Karim Hajj Ali
@incidents_bp.route("/incidents/<int:incident_id>/notes", methods=["POST"])
@require_role(constants.ROLE_ADMIN, constants.ROLE_ANALYST)
def api_add_investigation_note(incident_id):
    """Add an investigation note to an incident.

    Developed by Karim Hajj Ali.

    :param incident_id: The incident to attach the note to.
    :type incident_id: int
    :return: ``201`` with the stored note, ``400`` if it is empty, or ``404``.
    :rtype: flask.Response
    """
    body = request.get_json(silent=True) or {}
    caller = current_user()

    if get_incident_by_id(incident_id) is None:
        return error("No incident with id %s exists" % incident_id, 404)

    try:
        note_content = require_text(body.get("note_content"), "note_content")
    except ValidationError as failure:
        return error(failure.message, 400)

    with db.transaction() as cur:
        stored = insert_note(cur, incident_id, caller["id"], note_content)
        queue_audit_event(
            source_service=SERVICE,
            user_id=caller["id"],
            action=ACTION_INVESTIGATION_NOTE_ADDED,
            description="Note %s added to incident %s"
                        % (stored["note_id"], incident_id),
            severity="Information",
            related_service=SERVICE,
            cursor=cur)

    return jsonify({
        "status": "success",
        "message": "Investigation note added successfully",
        "note": stored,
    }), 201
