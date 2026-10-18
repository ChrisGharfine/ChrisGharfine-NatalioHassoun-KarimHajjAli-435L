"""User registration, authentication, profile ownership, and current identity."""

from flask import Blueprint, g, request
from flask_jwt_extended import create_access_token, get_jwt_identity, verify_jwt_in_request
from sqlalchemy import select
from werkzeug.security import check_password_hash, generate_password_hash

from .app import success
from .models import User
from .shared import validation as v
from .shared.audit import record_event
from .shared.auth import local_identity, protected, service_auth
from .shared.constants import ACCOUNT_STATUSES, ADMIN, AUDITOR, EMPLOYEE, ROLES
from .shared.errors import APIError, missing

bp = Blueprint("users", __name__)
# Constant dummy hash reduces the obvious timing difference for unknown usernames.
_DUMMY_HASH = generate_password_hash("Unused-Dummy-Password-837!", method="scrypt")


def find_user(user_id):
    user = g.db.scalar(select(User).where(User.id == user_id, User.deleted_at.is_(None)))
    if not user:
        missing("User")
    return user


@bp.post("/users/register")
def register():
    data = v.body(("full_name", "username", "email", "password", "department", "role"),
                  ("full_name", "username", "email", "password", "department", "role"))
    role = v.choice(data["role"], "role", ROLES)
    actor = None
    # A supplied token must be valid. Administrators can register privileged accounts.
    if request.headers.get("Authorization"):
        verify_jwt_in_request()
        actor = local_identity(get_jwt_identity())
        g.actor = actor
        if actor["role"] not in (ADMIN, EMPLOYEE):
            raise APIError(403, "FORBIDDEN", "This role cannot register user accounts.")
    if role != EMPLOYEE and (not actor or actor["role"] != ADMIN):
        raise APIError(403, "FORBIDDEN", "Only administrators may create privileged accounts.")
    user = User(full_name=v.text(data["full_name"], "full_name"), username=v.username(data["username"]),
                email=v.email(data["email"]), department=v.text(data["department"], "department"),
                password_hash=generate_password_hash(v.password(data["password"]), method="scrypt"),
                role=role, account_status="active")
    g.db.add(user)
    g.db.flush()
    record_event(g.db, "user_created", f"Created user {user.id}.", actor["id"] if actor else user.id)
    return success(user.public(), 201, commit=True)


@bp.post("/users/login")
def login():
    data = v.body(("identifier", "password"), ("identifier", "password"))
    identifier = v.text(data["identifier"], "identifier", 254).lower()
    password = data["password"]
    if not isinstance(password, str) or len(password) > 128:
        v.invalid("password must be text of at most 128 characters.")
    # Usernames cannot contain @, so username/email namespaces cannot collide.
    column = User.email if "@" in identifier else User.username
    user = g.db.scalar(select(User).where(column == identifier, User.deleted_at.is_(None)))
    valid = check_password_hash(user.password_hash if user else _DUMMY_HASH, password)
    if not user or not valid or user.account_status != "active":
        record_event(g.db, "login_failed", "Login rejected.", user.id if user else None, "Warning")
        g.db.commit()
        g.audit_needed = True
        raise APIError(401, "INVALID_CREDENTIALS", "Invalid credentials or unavailable account.")
    user.last_login_date = v.utcnow()
    record_event(g.db, "login_success", f"User {user.id} authenticated.", user.id)
    token = create_access_token(identity=str(user.id))
    return success({"access_token": token, "token_type": "Bearer", "expires_in": 1800,
                    "user": user.public()}, commit=True)


@bp.get("/users")
@protected(ADMIN, AUDITOR)
def list_users():
    return success([user.public() for user in g.db.scalars(
        select(User).where(User.deleted_at.is_(None)).order_by(User.id))])


@bp.get("/users/<string:username>")
@protected(ADMIN, AUDITOR, EMPLOYEE)
def retrieve_user(username):
    user = g.db.scalar(select(User).where(User.username == username.lower(), User.deleted_at.is_(None)))
    if g.actor["role"] == EMPLOYEE and (not user or user.id != g.actor["id"]):
        raise APIError(403, "FORBIDDEN", "Employees may access only their own profile.")
    if not user:
        missing("User")
    return success(user.public())


@bp.put("/users/<int:user_id>")
@protected(ADMIN, EMPLOYEE)
def update_user(user_id):
    if g.actor["role"] == EMPLOYEE and user_id != g.actor["id"]:
        raise APIError(403, "FORBIDDEN", "Employees may update only their own profile.")
    data = v.body(("full_name", "email", "department"))
    user = find_user(user_id)
    for key, value in data.items():
        setattr(user, key, v.email(value) if key == "email" else v.text(value, key))
    record_event(g.db, "user_updated", f"Updated user {user.id}.", g.actor["id"])
    return success(user.public(), commit=True)


@bp.delete("/users/<int:user_id>")
@protected(ADMIN)
def delete_user(user_id):
    if user_id == g.actor["id"]:
        raise APIError(409, "SELF_DELETE", "Administrators cannot delete their own account.")
    user = find_user(user_id)
    user.deleted_at, user.account_status = v.utcnow(), "inactive"
    record_event(g.db, "user_deleted", f"Deleted user {user.id}; retained historical references.", g.actor["id"])
    return success({"id": user.id, "deleted": True, "deletion_mode": "soft"}, commit=True)


@bp.put("/users/<int:user_id>/role")
@protected(ADMIN)
def update_role(user_id):
    data = v.body(("role",), ("role",))
    role = v.choice(data["role"], "role", ROLES)
    if user_id == g.actor["id"] and role != ADMIN:
        raise APIError(409, "SELF_DEMOTION", "Administrators cannot demote their own account.")
    user = find_user(user_id)
    old = user.role
    user.role = role
    record_event(g.db, "role_changed", f"User {user.id}: {old} to {role}.", g.actor["id"])
    return success(user.public(), commit=True)


@bp.put("/users/<int:user_id>/status")
@protected(ADMIN)
def update_status(user_id):
    data = v.body(("account_status",), ("account_status",))
    status = v.choice(data["account_status"], "account_status", ACCOUNT_STATUSES)
    if user_id == g.actor["id"] and status != "active":
        raise APIError(409, "SELF_SUSPENSION", "Administrators cannot disable their own account.")
    user = find_user(user_id)
    user.account_status = status
    record_event(g.db, "account_status_changed", f"User {user.id} status changed to {status}.", g.actor["id"])
    return success(user.public(), commit=True)


@bp.post("/internal/identity/verify")
def verify_identity():
    service_auth()
    verify_jwt_in_request()
    return success(local_identity(get_jwt_identity()))


@bp.get("/internal/users/<int:user_id>")
def reference_user(user_id):
    service_auth()
    user = g.db.get(User, user_id)
    if not user:
        missing("User")
    # Minimal data for FK validation, including historical users; never credentials.
    return success({"id": user.id, "role": user.role, "account_status": user.account_status,
                    "deleted": user.deleted_at is not None})
