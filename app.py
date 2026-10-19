"""Application entry point for the SIRMS backend.

Same shape as the Flask app from Lab 5, with one change: instead of all the
routes sitting in this file, each service registers its own ``Blueprint``.
That keeps the nine services in separate files and means two people adding a
service touch different files instead of fighting over this one.

Services 3, 7 and 8 are implemented here. The remaining six are team members'
work and get registered the same way once they are ready -- the commented
lines below are the slots they drop into.

Run it with::

    python app.py

:author: Karim Hajj Ali
"""

from flask import Flask, jsonify
from flask_cors import CORS

from auth import auth_bp
from database import create_db_tables
from services.incidents_api import incidents_bp
from services.notifications_api import notifications_bp
from services.vulnerabilities_api import vulnerabilities_bp


def create_app():
    """Build and configure the Flask application.

    :return: The configured application, ready to run.
    :rtype: flask.Flask
    """
    app = Flask(__name__)
    CORS(app, resources={r"/*": {"origins": "*"}})

    # Shared authentication (temporary -- belongs to Service 1).
    app.register_blueprint(auth_bp)

    # --- My three services (Karim Hajj Ali) ------------------------------
    app.register_blueprint(incidents_bp)        # Service 3
    app.register_blueprint(vulnerabilities_bp)  # Service 7
    app.register_blueprint(notifications_bp)    # Service 8

    # --- Team members' services, registered here when ready --------------
    # app.register_blueprint(users_bp)      # Service 1
    # app.register_blueprint(assets_bp)     # Service 2
    # app.register_blueprint(threats_bp)    # Service 4
    # app.register_blueprint(logs_bp)       # Service 5
    # app.register_blueprint(reports_bp)    # Service 6
    # app.register_blueprint(playbooks_bp)  # Service 9

    register_error_handlers(app)

    @app.route("/", methods=["GET"])
    def index():
        """Report which services this process is currently serving.

        :return: ``200`` with a short description of the running system.
        :rtype: flask.Response
        """
        return jsonify({
            "status": "success",
            "system": "Security Incident Detection and Response "
                      "Management System",
            "sprint": "Sprint I",
            "services_running": {
                "3": "Incident Management (Karim Hajj Ali)",
                "7": "Vulnerability Management (Karim Hajj Ali)",
                "8": "Notification and Alert Management (Karim Hajj Ali)",
            },
        }), 200

    return app


def register_error_handlers(app):
    """Make Flask's built-in errors come back as JSON.

    Without this, a request to a path that does not exist returns an HTML
    error page, which looks wrong next to the JSON every other endpoint
    produces. The spec asks for consistent error responses across all
    services, so the same ``{"status": "error", "message": ...}`` envelope is
    used here too.

    :param app: The application to attach the handlers to.
    :type app: flask.Flask
    :return: ``None``
    :rtype: NoneType
    """

    @app.errorhandler(400)
    def handle_bad_request(error):
        """Return a malformed request as JSON.

        :param error: The werkzeug exception Flask raised.
        :type error: werkzeug.exceptions.HTTPException
        :return: A ``400`` JSON response.
        :rtype: tuple
        """
        return jsonify({
            "status": "error",
            "message": "The request could not be understood. Check that the "
                       "body is valid JSON and Content-Type is "
                       "application/json.",
        }), 400

    @app.errorhandler(404)
    def handle_not_found(error):
        """Return an unknown route or a non-numeric id as JSON.

        :param error: The werkzeug exception Flask raised.
        :type error: werkzeug.exceptions.HTTPException
        :return: A ``404`` JSON response.
        :rtype: tuple
        """
        return jsonify({
            "status": "error",
            "message": "The requested resource does not exist. Check the "
                       "URL, and that any id in it is a number.",
        }), 404

    @app.errorhandler(405)
    def handle_method_not_allowed(error):
        """Return a wrong HTTP method as JSON.

        :param error: The werkzeug exception Flask raised.
        :type error: werkzeug.exceptions.HTTPException
        :return: A ``405`` JSON response.
        :rtype: tuple
        """
        return jsonify({
            "status": "error",
            "message": "That HTTP method is not allowed on this endpoint.",
        }), 405

    @app.errorhandler(500)
    def handle_server_error(error):
        """Return an unexpected failure as JSON instead of a traceback.

        :param error: The exception that escaped a view.
        :type error: Exception
        :return: A ``500`` JSON response.
        :rtype: tuple
        """
        return jsonify({
            "status": "error",
            "message": "An unexpected error occurred while processing the "
                       "request.",
        }), 500


app = create_app()


if __name__ == "__main__":
    create_db_tables()
    app.run(debug=True)
