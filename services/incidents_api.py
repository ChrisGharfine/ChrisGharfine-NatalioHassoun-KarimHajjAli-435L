"""REST API for Service 3 -- Incident Management.

Six endpoints, as required by the specification:

====== ================================= ======================================
Method Endpoint                          Who may call it
====== ================================= ======================================
POST   /incidents                        Administrator, Regular Employee
GET    /incidents                        Administrator, Auditor
GET    /incidents/{id}                   All four roles
PUT    /incidents/{id}/assign            Security Administrator
PUT    /incidents/{id}/status            Administrator, Analyst
POST   /incidents/{id}/notes             Administrator, Analyst
====== ================================= ======================================

Two rules on top of the plain role check:

* A Regular Employee may only read incidents **they reported themselves**.
  The spec limits them to "view submitted incidents" and "track the status
  of reported incidents", and explicitly says they cannot access wider
  organisational security information.
* Status changes follow the lifecycle one step at a time. The ordering lives
  in :class:`models.IncidentWorkflow`, not in this file.

:author: Karim Hajj Ali
"""

from flask import Blueprint, jsonify, request

import constants
from audit import write_log
from auth import current_user, require_role
from database import record_exists
from models import Incident, IncidentWorkflow, ValidationError, require_text
from services.incidents_db import (
    assign_incident,
    get_incident_by_id,
    get_incident_with_notes,
    get_incidents,
    insert_incident,
    insert_note,
    update_incident_status,
    user_has_role,
)
from services.notifications_db import send_notification

incidents_bp = Blueprint("incidents", __name__)

SERVICE_NAME = "Incident Management"

#: One shared workflow object -- it holds no per-request state.
WORKFLOW = IncidentWorkflow()


def _forbidden():
    """Build the standard 403 response used by the ownership checks.

    :return: A ``403`` JSON response.
    :rtype: tuple
    """
    return jsonify({
        "status": "error",
        "message": "User does not have permission to perform this operation",
    }), 403


# ---------------------------------------------------------------------------
# 1. Create Incident
# ---------------------------------------------------------------------------

# Route owner: Karim Hajj Ali
@incidents_bp.route("/incidents", methods=["POST"])
@require_role(constants.ROLE_ADMIN, constants.ROLE_EMPLOYEE)
def api_create_incident():
    """Report a new cybersecurity incident.

    Developed by Karim Hajj Ali.

    Expects ``title``, ``description``, ``category``, ``severity`` and
    ``affected_asset``. ``reporter`` is optional: it defaults to whoever is
    logged in, and a Regular Employee is forced to be the reporter of their
    own report so nobody can file an incident in someone else's name.

    :return: ``201`` with the stored incident, ``400`` on a validation error,
        or ``404`` if the reporter or the affected asset does not exist.
    :rtype: flask.Response
    """
    body = request.get_json(silent=True) or {}
    caller = current_user()

    reporter_id = body.get("reporter", caller["user_id"])
    if caller["role"] == constants.ROLE_EMPLOYEE:
        reporter_id = caller["user_id"]

    try:
        incident = Incident(
            title=body.get("title"),
            description=body.get("description"),
            category=body.get("category"),
            severity=body.get("severity"),
            reporter_id=reporter_id,
            asset_id=body.get("affected_asset"))
        incident.validate()
    except ValidationError as error:
        return jsonify({"status": "error", "message": error.message}), 400

    if not record_exists("users", "user_id", incident.get_reporter_id()):
        return jsonify({
            "status": "error",
            "message": "No user with id %s exists to report this incident"
                       % incident.get_reporter_id(),
        }), 404

    if incident.get_asset_id() is not None:
        if not record_exists("assets", "asset_id", incident.get_asset_id()):
            return jsonify({
                "status": "error",
                "message": "No asset with id %s exists"
                           % incident.get_asset_id(),
            }), 404

    stored = insert_incident(incident.to_row())
    if not stored:
        return jsonify({
            "status": "error",
            "message": "The incident could not be saved",
        }), 500

    write_log(caller["user_id"], "Incident created",
              "Incident %s '%s' reported with severity %s"
              % (stored["incident_id"], stored["title"], stored["severity"]),
              "Warning" if stored["severity"] in ("High", "Critical")
              else "Information",
              SERVICE_NAME)

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

    Each entry carries its current status and the analyst it is assigned to,
    resolved to a readable name rather than a bare id.

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
        incident they did not report, or ``404`` if it does not exist.
    :rtype: flask.Response
    """
    caller = current_user()
    incident = get_incident_with_notes(incident_id)

    if incident is None:
        return jsonify({
            "status": "error",
            "message": "No incident with id %s exists" % incident_id,
        }), 404

    if (caller["role"] == constants.ROLE_EMPLOYEE
            and incident["reporter_id"] != caller["user_id"]):
        return _forbidden()

    return jsonify({
        "status": "success",
        "incident": incident,
    }), 200


# ---------------------------------------------------------------------------
# 4. Assign Incident to Analyst
# ---------------------------------------------------------------------------

# Route owner: Karim Hajj Ali
@incidents_bp.route("/incidents/<int:incident_id>/assign", methods=["PUT"])
@require_role(constants.ROLE_ADMIN)
def api_assign_incident(incident_id):
    """Assign an incident to a security analyst.

    Developed by Karim Hajj Ali.

    Runs the three checks the spec asks for: the incident exists, the target
    user holds the Security Analyst role, and the assignment is written to
    the audit log. It also raises an ``Incident Assignment`` notification for
    the analyst, which is the hand-off point into Service 8.

    :param incident_id: The incident to assign.
    :type incident_id: int
    :return: ``200`` with the updated incident, ``400`` if the target is not
        an analyst, or ``404`` if the incident or the user does not exist.
    :rtype: flask.Response
    """
    body = request.get_json(silent=True) or {}
    caller = current_user()

    incident = get_incident_by_id(incident_id)
    if incident is None:
        return jsonify({
            "status": "error",
            "message": "No incident with id %s exists" % incident_id,
        }), 404

    analyst_id = body.get("analyst_id")
    if analyst_id is None:
        return jsonify({
            "status": "error",
            "message": "'analyst_id' is required",
        }), 400

    try:
        analyst_id = int(analyst_id)
    except (TypeError, ValueError):
        return jsonify({
            "status": "error",
            "message": "'analyst_id' must be an integer",
        }), 400

    if not record_exists("users", "user_id", analyst_id):
        return jsonify({
            "status": "error",
            "message": "No user with id %s exists" % analyst_id,
        }), 404

    if not user_has_role(analyst_id, constants.ROLE_ANALYST):
        return jsonify({
            "status": "error",
            "message": "User %s is not a Security Analyst, so this incident "
                       "cannot be assigned to them" % analyst_id,
        }), 400

    updated = assign_incident(incident_id, analyst_id)
    if updated is None:
        return jsonify({
            "status": "error",
            "message": "The incident could not be assigned",
        }), 500

    write_log(caller["user_id"], "Incident assigned",
              "Incident %s assigned to analyst %s (%s)"
              % (incident_id, analyst_id, updated["assigned_analyst_name"]),
              "Information", SERVICE_NAME)

    # Service 8 hand-off: tell the analyst they have work.
    send_notification(
        user_id=analyst_id,
        title="Incident #%s assigned to you" % incident_id,
        message="You have been assigned incident '%s' (severity %s). "
                "Current status: %s."
                % (updated["title"], updated["severity"], updated["status"]),
        notification_type="Incident Assignment",
        severity=updated["severity"])

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

    The lifecycle is ``Open -> Under Investigation -> Mitigated -> Resolved
    -> Closed`` and only the immediate next step is accepted, so an incident
    cannot be closed without being investigated first. The rejection message
    names the status that *would* have been allowed.

    :param incident_id: The incident to update.
    :type incident_id: int
    :return: ``200`` with the updated incident, ``400`` if the transition is
        not allowed, or ``404`` if the incident does not exist.
    :rtype: flask.Response
    """
    body = request.get_json(silent=True) or {}
    caller = current_user()

    incident = get_incident_by_id(incident_id)
    if incident is None:
        return jsonify({
            "status": "error",
            "message": "No incident with id %s exists" % incident_id,
        }), 404

    new_status = body.get("status")
    if new_status is None:
        return jsonify({
            "status": "error",
            "message": "'status' is required",
        }), 400

    try:
        WORKFLOW.check_transition(incident["status"], new_status)
    except ValidationError as error:
        return jsonify({"status": "error", "message": error.message}), 400

    updated = update_incident_status(incident_id, new_status)
    if updated is None:
        return jsonify({
            "status": "error",
            "message": "The incident status could not be updated",
        }), 500

    write_log(caller["user_id"], "Incident status updated",
              "Incident %s moved from '%s' to '%s' by %s"
              % (incident_id, incident["status"], new_status,
                 caller["full_name"]),
              "Information", SERVICE_NAME)

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

    The note records who wrote it and when, and is linked to the incident by
    foreign key, so ``GET /incidents/{id}`` returns the whole investigation
    trail in order.

    :param incident_id: The incident to attach the note to.
    :type incident_id: int
    :return: ``201`` with the stored note, ``400`` if the note is empty, or
        ``404`` if the incident does not exist.
    :rtype: flask.Response
    """
    body = request.get_json(silent=True) or {}
    caller = current_user()

    if get_incident_by_id(incident_id) is None:
        return jsonify({
            "status": "error",
            "message": "No incident with id %s exists" % incident_id,
        }), 404

    try:
        note_content = require_text(body.get("note_content"), "note_content")
    except ValidationError as error:
        return jsonify({"status": "error", "message": error.message}), 400

    stored = insert_note(incident_id, caller["user_id"], note_content)
    if not stored:
        return jsonify({
            "status": "error",
            "message": "The investigation note could not be saved",
        }), 500

    write_log(caller["user_id"], "Investigation note added",
              "Note %s added to incident %s by %s"
              % (stored["note_id"], incident_id, caller["full_name"]),
              "Information", SERVICE_NAME)

    return jsonify({
        "status": "success",
        "message": "Investigation note added successfully",
        "note": stored,
    }), 201
