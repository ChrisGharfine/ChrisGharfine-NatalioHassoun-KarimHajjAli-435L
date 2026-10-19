"""Authentication and role-based access control.

.. note::

   Login itself belongs to **Service 1 (Users and Identity Management)**,
   which is another team member's work. What is here is the smallest piece
   needed to make services 3, 7 and 8 testable on their own: a login route
   that hands out a token, and the decorator the protected routes use to
   check who is calling.

   When Service 1 lands, :func:`login` gets deleted and the token store is
   replaced by whatever that service issues. :func:`require_role` and
   :func:`current_user` stay as they are -- they only read the token.

How it works: ``POST /auth/login`` verifies the password against the hash in
the ``users`` table and returns a random token. The client then sends that
token on every later request as ``Authorization: Bearer <token>``. Tokens
live in a module-level dictionary, so restarting the server logs everyone
out, which is fine for a sprint demo.

:author: Karim Hajj Ali
"""

import hashlib
import hmac
import os
import uuid
from datetime import datetime
from functools import wraps

from flask import Blueprint, g, jsonify, request

from database import connect_to_db, row_to_dict

auth_bp = Blueprint("auth", __name__)

#: Issued tokens, mapped to the user record they belong to.
_ACTIVE_TOKENS = {}

#: Rounds for PBKDF2. 100k is the usual recommendation and is fast enough
#: that a login still feels instant.
_HASH_ROUNDS = 100000


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------

def hash_password(password):
    """Hash a password with PBKDF2-HMAC-SHA256 and a fresh random salt.

    The spec requires that passwords are never stored in plain text. The salt
    is generated per password and stored alongside the hash in a single
    ``salt$hash`` string, so two users with the same password still end up
    with different rows.

    :param password: The plain text password.
    :type password: str
    :return: The stored form, ``"<salt hex>$<hash hex>"``.
    :rtype: str
    """
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, _HASH_ROUNDS)
    return "%s$%s" % (salt.hex(), digest.hex())


def verify_password(password, stored):
    """Check a plain text password against a stored hash.

    :param password: The password the user typed.
    :type password: str
    :param stored: The ``"<salt hex>$<hash hex>"`` value from the database.
    :type stored: str
    :return: ``True`` if the password matches.
    :rtype: bool
    """
    try:
        salt_hex, hash_hex = stored.split("$")
    except (ValueError, AttributeError):
        return False
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex),
        _HASH_ROUNDS)
    # Constant time comparison, so a wrong password cannot be narrowed down
    # by timing how long the check took.
    return hmac.compare_digest(digest.hex(), hash_hex)


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------

@auth_bp.route("/auth/login", methods=["POST"])
def login():
    """Authenticate a user and issue a token.

    Temporary stand-in for ``POST /users/login`` from Service 1.

    :return: ``200`` with a token and the user record, or ``401`` when the
        credentials are wrong, or ``403`` when the account is not active.
    :rtype: flask.Response
    """
    body = request.get_json(silent=True) or {}
    username = body.get("username")
    password = body.get("password")

    if not username or not password:
        return jsonify({
            "status": "error",
            "message": "Both 'username' and 'password' are required",
        }), 400

    conn = connect_to_db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = row_to_dict(cur.fetchone())
    finally:
        conn.close()

    if user is None or not verify_password(password, user["password_hash"]):
        return jsonify({
            "status": "error",
            "message": "Invalid username or password",
        }), 401

    # The spec says inactive and suspended accounts must not be able to
    # authenticate, even with the right password.
    if user["account_status"] != "Active":
        return jsonify({
            "status": "error",
            "message": "This account is %s and cannot log in"
                       % user["account_status"].lower(),
        }), 403

    token = uuid.uuid4().hex
    _ACTIVE_TOKENS[token] = user

    conn = connect_to_db()
    try:
        conn.execute("UPDATE users SET last_login_date = ? WHERE user_id = ?",
                     (datetime.now().isoformat(timespec="seconds"),
                      user["user_id"]))
        conn.commit()
    finally:
        conn.close()

    return jsonify({
        "status": "success",
        "message": "Login successful",
        "token": token,
        "user": {
            "user_id": user["user_id"],
            "full_name": user["full_name"],
            "username": user["username"],
            "role": user["role"],
        },
    }), 200


# ---------------------------------------------------------------------------
# Reading the caller off the request
# ---------------------------------------------------------------------------

def current_user():
    """Return the user making the current request.

    :return: The user row, or ``None`` if the request had no valid token.
    :rtype: dict or NoneType
    """
    return getattr(g, "user", None)


def _token_from_request():
    """Pull the bearer token out of the ``Authorization`` header.

    :return: The token, or ``None`` if the header was missing or malformed.
    :rtype: str or NoneType
    """
    header = request.headers.get("Authorization", "")
    if header.startswith("Bearer "):
        return header[len("Bearer "):].strip()
    return None


def require_role(*allowed_roles):
    """Protect a route so only the listed roles may call it.

    Applies the three checks the spec asks for, in order: the caller is
    authenticated, their role is known, and their role is permitted here.
    A rejected call is written to the audit log before the response goes out.

    Usage::

        @incidents_bp.route("/incidents", methods=["GET"])
        @require_role(constants.ROLE_ADMIN, constants.ROLE_AUDITOR)
        def api_get_incidents():
            ...

    :param allowed_roles: The roles that may call the decorated route.
    :type allowed_roles: str
    :return: The decorator.
    :rtype: function
    """

    def decorator(view_function):

        @wraps(view_function)
        def wrapper(*args, **kwargs):
            # Imported here rather than at the top of the file: audit.py
            # imports auth.py for current_user(), so importing it at module
            # level would be a circular import.
            from audit import write_log

            token = _token_from_request()
            if token is None:
                return jsonify({
                    "status": "error",
                    "message": "Authentication required. Send your token as "
                               "'Authorization: Bearer <token>'.",
                }), 401

            user = _ACTIVE_TOKENS.get(token)
            if user is None:
                return jsonify({
                    "status": "error",
                    "message": "Invalid or expired token. Please log in again.",
                }), 401

            if user["role"] not in allowed_roles:
                write_log(
                    user_id=user["user_id"],
                    action="Unauthorized access attempt",
                    description="%s (%s) tried to call %s %s, which is "
                                "restricted to: %s"
                                % (user["full_name"], user["role"],
                                   request.method, request.path,
                                   ", ".join(allowed_roles)),
                    severity="Warning",
                    service=_service_from_path(request.path))
                return jsonify({
                    "status": "error",
                    "message": "User does not have permission to perform "
                               "this operation",
                }), 403

            g.user = user
            return view_function(*args, **kwargs)

        return wrapper

    return decorator


def _service_from_path(path):
    """Work out which service a request path belongs to, for the audit log.

    :param path: The request path, e.g. ``"/incidents/3/status"``.
    :type path: str
    :return: A readable service name.
    :rtype: str
    """
    first_segment = path.strip("/").split("/")[0]
    names = {
        "incidents": "Incident Management",
        "vulnerabilities": "Vulnerability Management",
        "notifications": "Notification Management",
        "users": "Users and Identity Management",
        "assets": "Asset Management",
        "threats": "Threat Intelligence",
        "logs": "Security Audit Logging",
        "reports": "Security Reports",
        "playbooks": "Security Playbook",
        "actions": "Security Playbook",
        "auth": "Users and Identity Management",
    }
    return names.get(first_segment, "Unknown")


def register_token_for_tests(token, user):
    """Insert a token directly into the store, for the automated tests.

    :param token: The token string to register.
    :type token: str
    :param user: The user row it should map to.
    :type user: dict
    :return: ``None``
    :rtype: NoneType
    """
    _ACTIVE_TOKENS[token] = user
