"""REST API for Service 8 -- Notification and Alert Management.

The six public endpoints keep their Sprint I paths, permissions and
envelopes. Section 7 of team-integration-v1.0.0 adds a seventh, internal
endpoint that other services call over HTTP with their own service key,
which is how Incidents and Vulnerabilities now raise alerts instead of
importing this service's code.

The internal endpoint is idempotent. Every delivery carries an
``Idempotency-Key``; the first one creates the notification, its receipt
and its audit event in one transaction, and any identical retry returns
the same result without creating anything. Receipts outlive the
notifications they point at, so a retry after a deletion reports
``notification: null`` rather than quietly recreating it.

:author: Karim Hajj Ali
"""

import uuid

from flask import Blueprint, jsonify, request

import config
import constants
import db
from models import Notification, ValidationError
from outbox.audit_outbox import ACTION_NOTIFICATION_DELETED, queue_audit_event
from security.guard import current_user, error, require_role
from security.identity import IdentityUnavailable, is_assignable, lookup_user
from security.service_auth import ServiceAuthError, authenticate_service
from services.notifications_db import (
    create_notification_with_receipt,
    delete_notification,
    get_notification_by_id,
    get_notifications_by_user,
    get_receipt,
    insert_notification,
    mark_notification_read,
    payload_digest,
    search_notifications,
)

notifications_bp = Blueprint("notifications", __name__)

SERVICE = config.SERVICE_NOTIFICATIONS

#: Roles that may read notifications belonging to somebody else.
_OVERSIGHT_ROLES = (constants.ROLE_ADMIN, constants.ROLE_AUDITOR)

#: Caller/type pairs permitted on the internal endpoint (section 7).
_ALLOWED_CALLER_TYPES = {
    "incidents": ("Incident Assignment",),
    "vulnerabilities": ("Vulnerability Alert",),
    "threats": ("Threat Alert",),
    "users": ("System Notification",),
    "playbooks": ("System Notification",),
}


def _may_access_user(target_user_id):
    """Check whether the caller may read another user's inbox.

    :param target_user_id: The recipient whose notifications were requested.
    :type target_user_id: int
    :return: ``True`` if the caller may read them.
    :rtype: bool
    """
    caller = current_user()
    if caller["role"] in _OVERSIGHT_ROLES:
        return True
    return caller["id"] == target_user_id


def _forbidden():
    """Return the standard ``403`` used by the ownership checks.

    :return: A Flask response tuple.
    :rtype: tuple
    """
    return error("User does not have permission to perform this operation",
                 403)


# ---------------------------------------------------------------------------
# Internal delivery endpoint (section 7)
# ---------------------------------------------------------------------------

# Route owner: Karim Hajj Ali
@notifications_bp.route("/internal/notifications", methods=["POST"])
def api_internal_create_notification():
    """Accept a notification raised by another service.

    Developed by Karim Hajj Ali.

    Authenticated by ``X-Service-Name`` and ``X-Service-Key``, never by a
    user token. Requires an ``Idempotency-Key`` so retries are safe.

    :return: ``201`` on first creation, ``200`` on an identical retry,
        ``400`` invalid fields, ``401`` bad credentials, ``403`` a caller
        raising a type it may not, ``404`` unknown recipient, ``409``
        unavailable recipient or an idempotency conflict, ``503`` if Users
        cannot be consulted.
    :rtype: flask.Response
    """
    try:
        caller_service = authenticate_service(request.headers)
    except ServiceAuthError as failure:
        return error(failure.message, failure.status)

    raw_key = (request.headers.get("Idempotency-Key") or "").strip()
    try:
        event_id = str(uuid.UUID(raw_key))
    except ValueError:
        return error("A valid UUID 'Idempotency-Key' header is required", 400)

    body = request.get_json(silent=True) or {}
    notification_type = body.get("notification_type")

    allowed_types = _ALLOWED_CALLER_TYPES.get(caller_service, ())
    if notification_type not in allowed_types:
        return error(
            "Service '%s' may not raise '%s' notifications"
            % (caller_service, notification_type), 403)

    actor_user_id = body.get("actor_user_id")
    if actor_user_id is not None:
        try:
            actor_user_id = int(actor_user_id)
        except (TypeError, ValueError):
            return error("'actor_user_id' must be an integer or null", 400)

    try:
        notification = Notification(
            user_id=body.get("user_id"),
            title=body.get("title"),
            message=body.get("message"),
            notification_type=notification_type,
            severity=body.get("severity_level"))
        notification.validate()
    except ValidationError as failure:
        return error(failure.message, 400)

    row = notification.to_row()
    digest = payload_digest({
        "user_id": row["user_id"],
        "actor_user_id": actor_user_id,
        "title": row["title"],
        "message": row["message"],
        "notification_type": row["notification_type"],
        "severity_level": row["severity_level"],
    })

    # An existing receipt short-circuits everything, including recipient
    # revalidation, so an exact retry stays safe after the recipient has
    # been deactivated or the notification deleted.
    receipt = get_receipt(event_id)
    if receipt is not None:
        if receipt["source_service"] != caller_service or \
                receipt["payload_digest"] != digest:
            return jsonify({
                "status": "error",
                "code": "IDEMPOTENCY_CONFLICT",
                "message": "This Idempotency-Key was already used with a "
                           "different payload or by a different service",
            }), 409
        stored = (get_notification_by_id(receipt["notification_id"])
                  if receipt["notification_id"] is not None else None)
        return jsonify({
            "status": "success",
            "data": {"event_id": event_id, "notification": stored,
                     "duplicate": True},
        }), 200

    try:
        recipient = lookup_user(row["user_id"], SERVICE)
    except IdentityUnavailable as failure:
        return error(failure.message, 503)

    if recipient is None:
        return error("No user with id %s exists" % row["user_id"], 404)
    if not is_assignable(recipient):
        return jsonify({
            "status": "error",
            "code": "RECIPIENT_UNAVAILABLE",
            "message": "User %s cannot receive notifications because the "
                       "account is inactive or deleted" % row["user_id"],
        }), 409

    row["actor_user_id"] = actor_user_id
    stored = create_notification_with_receipt(
        event_id, caller_service, digest, row)

    return jsonify({
        "status": "success",
        "data": {"event_id": event_id, "notification": stored,
                 "duplicate": False},
    }), 201


# ---------------------------------------------------------------------------
# 1. Create Notification (public, administrator only)
# ---------------------------------------------------------------------------

# Route owner: Karim Hajj Ali
@notifications_bp.route("/notifications", methods=["POST"])
@require_role(constants.ROLE_ADMIN)
def api_create_notification():
    """Create a notification for a user.

    Developed by Karim Hajj Ali.

    :return: ``201`` with the stored notification, ``400`` on a validation
        error, ``404`` unknown recipient, or ``503`` if Users is unreachable.
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
    except ValidationError as failure:
        return error(failure.message, 400)

    try:
        recipient = lookup_user(notification.get_user_id(), SERVICE)
    except IdentityUnavailable as failure:
        return error(failure.message, 503)

    if recipient is None:
        return error("No user with id %s exists" % notification.get_user_id(),
                     404)
    if not is_assignable(recipient):
        return error("User %s cannot receive notifications because the "
                     "account is inactive or deleted"
                     % notification.get_user_id(), 409)

    from outbox.audit_outbox import ACTION_NOTIFICATION_CREATED

    with db.transaction() as cur:
        stored = insert_notification(cur, notification.to_row())
        queue_audit_event(
            source_service=SERVICE,
            user_id=caller["id"],
            action=ACTION_NOTIFICATION_CREATED,
            description="Notification %s (%s) created for user %s"
                        % (stored["notification_id"],
                           stored["notification_type"], stored["user_id"]),
            severity="Information",
            related_service=SERVICE,
            cursor=cur)

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

    :param user_id: The recipient whose notifications to return.
    :type user_id: int
    :return: ``200`` with the list, ``403``, ``404``, or ``503``.
    :rtype: flask.Response
    """
    if not _may_access_user(user_id):
        return _forbidden()

    try:
        recipient = lookup_user(user_id, SERVICE)
    except IdentityUnavailable as failure:
        return error(failure.message, 503)

    if recipient is None:
        return error("No user with id %s exists" % user_id, 404)

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
    :return: ``200`` with the notification, ``403``, or ``404``.
    :rtype: flask.Response
    """
    notification = get_notification_by_id(notification_id)
    if notification is None:
        return error("No notification with id %s exists" % notification_id,
                     404)
    if not _may_access_user(notification["user_id"]):
        return _forbidden()
    return jsonify({"status": "success",
                    "notification": notification}), 200


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
    :return: ``200`` with the updated notification, ``403``, or ``404``.
    :rtype: flask.Response
    """
    notification = get_notification_by_id(notification_id)
    if notification is None:
        return error("No notification with id %s exists" % notification_id,
                     404)
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

    An analyst's search is silently scoped to their own inbox.

    :return: ``200`` with the matches, or ``400`` on an invalid filter.
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
            return error("'user_id' must be an integer", 400)

    if notification_type and \
            notification_type not in constants.NOTIFICATION_TYPES:
        return error("'notification_type' must be one of: %s"
                     % ", ".join(constants.NOTIFICATION_TYPES), 400)

    if severity and severity not in constants.SEVERITIES:
        return error("'severity' must be one of: %s"
                     % ", ".join(constants.SEVERITIES), 400)

    if status and status not in constants.NOTIFICATION_STATUSES:
        return error("'status' must be one of: %s"
                     % ", ".join(constants.NOTIFICATION_STATUSES), 400)

    if caller["role"] not in _OVERSIGHT_ROLES:
        user_id = caller["id"]

    results = search_notifications(user_id=user_id,
                                   notification_type=notification_type,
                                   severity=severity, status=status)

    return jsonify({
        "status": "success",
        "count": len(results),
        "filters_applied": {"user_id": user_id,
                            "notification_type": notification_type,
                            "severity": severity, "status": status},
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

    The delivery receipt survives, so an identical retry of the original
    internal delivery will not recreate it.

    :param notification_id: The notification to delete.
    :type notification_id: int
    :return: ``200`` on success, or ``404``.
    :rtype: flask.Response
    """
    caller = current_user()

    if get_notification_by_id(notification_id) is None:
        return error("No notification with id %s exists" % notification_id,
                     404)

    with db.transaction() as cur:
        removed = delete_notification(cur, notification_id)
        if not removed:
            return error("The notification could not be deleted", 500)
        queue_audit_event(
            source_service=SERVICE,
            user_id=caller["id"],
            action=ACTION_NOTIFICATION_DELETED,
            description="Notification %s deleted" % notification_id,
            severity="Warning",
            related_service=SERVICE,
            cursor=cur)

    return jsonify({"status": "success",
                    "message": "Notification deleted successfully"}), 200
