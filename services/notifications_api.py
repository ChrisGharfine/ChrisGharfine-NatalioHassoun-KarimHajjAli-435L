"""REST API for Service 8 -- Notification and Alert Management.

Six endpoints, as required by the specification:

====== ================================== =====================================
Method Endpoint                           Who may call it
====== ================================== =====================================
POST   /notifications                     Security Administrator
GET    /notifications/user/{user_id}      All four roles
GET    /notifications/{id}                All four roles
PUT    /notifications/{id}/read           Administrator, Analyst, Employee
GET    /notifications/search              Administrator, Analyst, Auditor
DELETE /notifications/{id}                Security Administrator
====== ================================== =====================================

On top of the role check there is an ownership rule. A Security Analyst and
a Regular Employee may only reach **their own** notifications -- the spec
describes their access as "view assigned notifications" and "view personal
notifications". Administrators and Auditors have oversight of the whole
system, so they can read anybody's.

:author: Karim Hajj Ali
"""

from flask import Blueprint, jsonify, request

import constants
from audit import write_log
from auth import current_user, require_role
from database import record_exists
from models import Notification, ValidationError
from services.notifications_db import (
    delete_notification,
    get_notification_by_id,
    get_notifications_by_user,
    insert_notification,
    mark_notification_read,
    search_notifications,
)

notifications_bp = Blueprint("notifications", __name__)

SERVICE_NAME = "Notification Management"

#: Roles that may look at notifications belonging to somebody else.
_OVERSIGHT_ROLES = (constants.ROLE_ADMIN, constants.ROLE_AUDITOR)


def _may_access_user(target_user_id):
    """Check whether the caller is allowed to see another user's inbox.

    :param target_user_id: The recipient whose notifications were requested.
    :type target_user_id: int
    :return: ``True`` if the caller may read them.
    :rtype: bool
    """
    user = current_user()
    if user["role"] in _OVERSIGHT_ROLES:
        return True
    return user["user_id"] == target_user_id


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
# 1. Create Notification
# ---------------------------------------------------------------------------

# Route owner: Karim Hajj Ali
@notifications_bp.route("/notifications", methods=["POST"])
@require_role(constants.ROLE_ADMIN)
def api_create_notification():
    """Create a notification for a user.

    Developed by Karim Hajj Ali.

    Expects a JSON body with ``user_id``, ``title``, ``message``,
    ``notification_type`` and ``severity``.

    :return: ``201`` with the stored notification, ``400`` on a validation
        error, or ``404`` if the recipient does not exist.
    :rtype: flask.Response
    """
    body = request.get_json(silent=True) or {}
    caller = current_user()

    try:
        notification = Notification(
            user_id=body.get("user_id"),
            title=body.get("title"),
            message=body.get("message"),
            notification_type=body.get("notification_type"),
            severity=body.get("severity"))
        notification.validate()
    except ValidationError as error:
        return jsonify({"status": "error", "message": error.message}), 400

    if not record_exists("users", "user_id", notification.get_user_id()):
        return jsonify({
            "status": "error",
            "message": "No user with id %s exists"
                       % notification.get_user_id(),
        }), 404

    stored = insert_notification(notification.to_row())
    if not stored:
        return jsonify({
            "status": "error",
            "message": "The notification could not be saved",
        }), 500

    write_log(caller["user_id"], "Notification created",
              "Notification %s (%s) sent to user %s"
              % (stored["notification_id"], stored["notification_type"],
                 stored["user_id"]),
              "Information", SERVICE_NAME)

    return jsonify({
        "status": "success",
        "message": "Notification created successfully",
        "notification": stored,
    }), 201


# ---------------------------------------------------------------------------
# 2. Retrieve User Notifications
# ---------------------------------------------------------------------------

# Route owner: Karim Hajj Ali
@notifications_bp.route("/notifications/user/<int:user_id>", methods=["GET"])
@require_role(constants.ROLE_ADMIN, constants.ROLE_ANALYST,
              constants.ROLE_EMPLOYEE, constants.ROLE_AUDITOR)
def api_get_user_notifications(user_id):
    """Return every notification belonging to one user.

    Developed by Karim Hajj Ali.

    A user with no notifications gets ``200`` and an empty list rather than
    a ``404`` -- an empty inbox is a valid answer, not a missing resource.

    :param user_id: The recipient whose notifications to return.
    :type user_id: int
    :return: ``200`` with the list, ``403`` if the caller may not read this
        user's inbox, or ``404`` if the user does not exist.
    :rtype: flask.Response
    """
    if not _may_access_user(user_id):
        return _forbidden()

    if not record_exists("users", "user_id", user_id):
        return jsonify({
            "status": "error",
            "message": "No user with id %s exists" % user_id,
        }), 404

    notifications = get_notifications_by_user(user_id)
    return jsonify({
        "status": "success",
        "count": len(notifications),
        "unread": len([n for n in notifications if n["status"] == "Unread"]),
        "notifications": notifications,
    }), 200


# ---------------------------------------------------------------------------
# 3. Retrieve Specific Notification
# ---------------------------------------------------------------------------

# Route owner: Karim Hajj Ali
@notifications_bp.route("/notifications/<int:notification_id>",
                        methods=["GET"])
@require_role(constants.ROLE_ADMIN, constants.ROLE_ANALYST,
              constants.ROLE_EMPLOYEE, constants.ROLE_AUDITOR)
def api_get_notification(notification_id):
    """Return one notification by its id.

    Developed by Karim Hajj Ali.

    :param notification_id: The notification to return.
    :type notification_id: int
    :return: ``200`` with the notification, ``403`` if it belongs to somebody
        else, or ``404`` if there is no such notification.
    :rtype: flask.Response
    """
    notification = get_notification_by_id(notification_id)
    if notification is None:
        return jsonify({
            "status": "error",
            "message": "No notification with id %s exists" % notification_id,
        }), 404

    if not _may_access_user(notification["user_id"]):
        return _forbidden()

    return jsonify({
        "status": "success",
        "notification": notification,
    }), 200


# ---------------------------------------------------------------------------
# 4. Mark Notification as Read
# ---------------------------------------------------------------------------

# Route owner: Karim Hajj Ali
@notifications_bp.route("/notifications/<int:notification_id>/read",
                        methods=["PUT"])
@require_role(constants.ROLE_ADMIN, constants.ROLE_ANALYST,
              constants.ROLE_EMPLOYEE)
def api_mark_notification_read(notification_id):
    """Mark a notification as read.

    Developed by Karim Hajj Ali.

    :param notification_id: The notification to mark.
    :type notification_id: int
    :return: ``200`` with the updated notification, ``403`` if it belongs to
        somebody else, or ``404`` if there is no such notification.
    :rtype: flask.Response
    """
    notification = get_notification_by_id(notification_id)
    if notification is None:
        return jsonify({
            "status": "error",
            "message": "No notification with id %s exists" % notification_id,
        }), 404

    if not _may_access_user(notification["user_id"]):
        return _forbidden()

    was_unread = notification["status"] == "Unread"
    updated = mark_notification_read(notification_id)

    return jsonify({
        "status": "success",
        "message": "Notification marked as read" if was_unread
                   else "Notification was already read",
        "notification": updated,
    }), 200


# ---------------------------------------------------------------------------
# 5. Search Notifications
# ---------------------------------------------------------------------------

# Route owner: Karim Hajj Ali
@notifications_bp.route("/notifications/search", methods=["GET"])
@require_role(constants.ROLE_ADMIN, constants.ROLE_ANALYST,
              constants.ROLE_AUDITOR)
def api_search_notifications():
    """Search notifications by user, type, severity and status.

    Developed by Karim Hajj Ali.

    Criteria arrive as query string parameters and are combined with ``AND``,
    for example::

        GET /notifications/search?severity=Critical&status=Unread

    An analyst searching is silently restricted to their own notifications,
    so the filter cannot be used to read somebody else's inbox.

    :return: ``200`` with the matches, or ``400`` if a filter value is not a
        recognised option.
    :rtype: flask.Response
    """
    caller = current_user()

    user_id = request.args.get("user_id")
    notification_type = request.args.get("notification_type")
    severity = request.args.get("severity")
    status = request.args.get("status")

    if user_id is not None:
        try:
            user_id = int(user_id)
        except ValueError:
            return jsonify({
                "status": "error",
                "message": "'user_id' must be an integer",
            }), 400

    if notification_type and notification_type not in constants.NOTIFICATION_TYPES:
        return jsonify({
            "status": "error",
            "message": "'notification_type' must be one of: %s"
                       % ", ".join(constants.NOTIFICATION_TYPES),
        }), 400

    if severity and severity not in constants.SEVERITIES:
        return jsonify({
            "status": "error",
            "message": "'severity' must be one of: %s"
                       % ", ".join(constants.SEVERITIES),
        }), 400

    if status and status not in constants.NOTIFICATION_STATUSES:
        return jsonify({
            "status": "error",
            "message": "'status' must be one of: %s"
                       % ", ".join(constants.NOTIFICATION_STATUSES),
        }), 400

    # An analyst only ever searches their own inbox, whatever they asked for.
    if caller["role"] not in _OVERSIGHT_ROLES:
        user_id = caller["user_id"]

    results = search_notifications(
        user_id=user_id,
        notification_type=notification_type,
        severity=severity,
        status=status)

    return jsonify({
        "status": "success",
        "count": len(results),
        "filters_applied": {
            "user_id": user_id,
            "notification_type": notification_type,
            "severity": severity,
            "status": status,
        },
        "notifications": results,
    }), 200


# ---------------------------------------------------------------------------
# 6. Delete Notification
# ---------------------------------------------------------------------------

# Route owner: Karim Hajj Ali
@notifications_bp.route("/notifications/<int:notification_id>",
                        methods=["DELETE"])
@require_role(constants.ROLE_ADMIN)
def api_delete_notification(notification_id):
    """Delete a notification.

    Developed by Karim Hajj Ali.

    Restricted to administrators. An analyst or employee who tries this is
    refused with ``403`` and the attempt is written to the audit log by the
    :func:`auth.require_role` decorator.

    :param notification_id: The notification to delete.
    :type notification_id: int
    :return: ``200`` on success, or ``404`` if there is no such notification.
    :rtype: flask.Response
    """
    caller = current_user()

    if get_notification_by_id(notification_id) is None:
        return jsonify({
            "status": "error",
            "message": "No notification with id %s exists" % notification_id,
        }), 404

    if not delete_notification(notification_id):
        return jsonify({
            "status": "error",
            "message": "The notification could not be deleted",
        }), 500

    write_log(caller["user_id"], "Notification deleted",
              "Notification %s was deleted by %s"
              % (notification_id, caller["full_name"]),
              "Warning", SERVICE_NAME)

    return jsonify({
        "status": "success",
        "message": "Notification deleted successfully",
    }), 200
