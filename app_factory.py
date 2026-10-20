"""Build one Flask app per service.

Section 2 of team-integration-v1.0.0 requires my three services to be
independently addressable, each on its own port. The Sprint I design
registered all three blueprints in one process and kept tokens in that
process's memory; both are gone.

Each app exposes ``/health`` in the shape section 2 fixes for Chris and me,
``{"status":"ok","service":"<name>"}``, and the health check queries that
service's own required tables rather than merely reporting that the process
is alive.

:author: Karim Hajj Ali
"""

from flask import Flask, jsonify, request
from flask_cors import CORS

import config
import db

#: Tables each service needs before it can answer requests.
REQUIRED_TABLES = {
    config.SERVICE_INCIDENTS: ("incidents", "investigation_notes",
                               "karim_audit_outbox",
                               "karim_notification_outbox"),
    config.SERVICE_VULNERABILITIES: ("vulnerabilities", "karim_audit_outbox",
                                     "karim_notification_outbox"),
    config.SERVICE_NOTIFICATIONS: ("notifications",
                                   "karim_notification_receipts",
                                   "karim_audit_outbox"),
}


def create_app(service_name, blueprint):
    """Build the Flask app for one service.

    :param service_name: One of :data:`config.MY_SERVICES`.
    :type service_name: str
    :param blueprint: That service's blueprint.
    :type blueprint: flask.Blueprint
    :return: The configured application.
    :rtype: flask.Flask
    """
    app = Flask(service_name, static_folder=None)
    app.config["KARIM_SERVICE_NAME"] = service_name
    CORS(app, resources={r"/*": {"origins": "*"}})

    app.register_blueprint(blueprint, url_prefix=config.API_PREFIX)
    _register_health(app, service_name)
    _register_error_handlers(app)

    @app.before_request
    def require_json_object():
        # Empty-body operations such as mark-read stay valid. A supplied body
        # must be an object; arrays/scalars must not escape as AttributeError.
        if request.url_rule is not None and request.method in ("POST", "PUT", "PATCH") and request.content_length:
            if not request.is_json or not isinstance(request.get_json(silent=True), dict):
                return jsonify(status="error", code="INVALID_INPUT", message="The request body must be a valid JSON object."), 400

    @app.after_request
    def standard_errors(response):
        response.headers["Cache-Control"] = "no-store"
        if response.status_code >= 400 and response.is_json:
            body = response.get_json()
            if isinstance(body, dict) and body.get("status") == "error":
                body.setdefault("code", {400: "INVALID_INPUT", 401: "AUTHENTICATION_REQUIRED", 403: "FORBIDDEN",
                                          404: "NOT_FOUND", 405: "METHOD_NOT_ALLOWED", 409: "CONFLICT",
                                          500: "INTERNAL_ERROR", 503: "SERVICE_UNAVAILABLE"}.get(response.status_code, "HTTP_ERROR"))
                response.set_data(app.json.dumps(body))
        return response
    return app


def _register_health(app, service_name):
    """Attach ``/health`` and ``/ready`` to an app.

    :param app: The application.
    :type app: flask.Flask
    :param service_name: The service this app serves.
    :type service_name: str
    :return: ``None``
    :rtype: NoneType
    """
    required = REQUIRED_TABLES[service_name]

    def _tables_queryable():
        """Check that every required table can actually be queried.

        :return: ``(ok, missing table name or None)``.
        :rtype: tuple
        """
        try:
            for table in required:
                db.query_one("SELECT 1 FROM %s LIMIT 1" % table)
        except Exception:
            return False, table
        return True, None

    @app.route(config.API_PREFIX + "/health", methods=["GET"])
    def health():
        """Report whether this service can serve requests.

        :return: ``200`` when its own tables are queryable, else ``503``.
        :rtype: flask.Response
        """
        ok, missing = _tables_queryable()
        if not ok:
            return jsonify({"status": "error", "service": service_name,
                            "message": "Required service storage is unavailable."}), 503
        return jsonify({"status": "ok", "service": service_name}), 200

    @app.route(config.API_PREFIX + "/ready", methods=["GET"])
    def ready():
        """Report readiness, ``200`` only when the tables can be queried.

        :return: ``200`` or ``503``.
        :rtype: flask.Response
        """
        ok, missing = _tables_queryable()
        if not ok:
            return jsonify({"status": "error", "service": service_name,
                            "message": "Required service storage is unavailable."}), 503
        return jsonify({"status": "ok", "service": service_name}), 200


def _register_error_handlers(app):
    """Make Flask's built-in errors come back in the standard envelope.

    :param app: The application.
    :type app: flask.Flask
    :return: ``None``
    :rtype: NoneType
    """

    @app.errorhandler(400)
    def bad_request(_error):
        """Return a malformed request as JSON.

        :param _error: The werkzeug exception.
        :type _error: werkzeug.exceptions.HTTPException
        :return: A ``400`` response.
        :rtype: tuple
        """
        return jsonify({
            "status": "error",
            "message": "The request could not be understood. Check that the "
                       "body is valid JSON and Content-Type is "
                       "application/json.",
        }), 400

    @app.errorhandler(404)
    def not_found(_error):
        """Return an unknown route as JSON.

        :param _error: The werkzeug exception.
        :type _error: werkzeug.exceptions.HTTPException
        :return: A ``404`` response.
        :rtype: tuple
        """
        return jsonify({
            "status": "error",
            "message": "The requested resource does not exist. Check the "
                       "URL, and that any id in it is a number.",
        }), 404

    @app.errorhandler(405)
    def method_not_allowed(_error):
        """Return a wrong HTTP method as JSON.

        :param _error: The werkzeug exception.
        :type _error: werkzeug.exceptions.HTTPException
        :return: A ``405`` response.
        :rtype: tuple
        """
        return jsonify({
            "status": "error",
            "message": "That HTTP method is not allowed on this endpoint.",
        }), 405

    @app.errorhandler(Exception)
    def unexpected(error):
        """Return an unhandled exception as JSON, never a traceback.

        :param error: The exception that escaped a view.
        :type error: Exception
        :return: A ``500`` response.
        :rtype: tuple
        """
        app.logger.error("Unhandled exception type: %s", type(error).__name__)
        return jsonify({
            "status": "error",
            "message": "An unexpected error occurred while processing the "
                       "request.",
        }), 500
