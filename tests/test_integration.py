"""HTTP integration tests against live threaded services and real PostgreSQL."""

import uuid
import json
import os
import subprocess
import sys
from datetime import timedelta

import pytest
from flask_jwt_extended import create_access_token
from sqlalchemy import func, select, text
from sqlalchemy.exc import DBAPIError

from security_backend.shared.audit import drain_outbox
from security_backend.models import ActionHistory, Log, Playbook, ResponseAction, User, UsersOutbox
from security_backend.shared.constants import ADMIN, ANALYST, AUDITOR, EMPLOYEE
from .conftest import PASSWORD, PREFIX


def data(response, status=200):
    assert response.status_code == status, response.text
    return response.json()["data"]


def test_registration_hashing_duplicates_and_case_normalization(api):
    user, _ = api.new_user()
    assert "password_hash" not in user and "password" not in user
    with api.apps["users"].extensions["session_factory"]() as session:
        stored = session.get(User, user["id"])
        assert stored.password_hash.startswith("scrypt:") and PASSWORD not in stored.password_hash
    response = api.request("users", "POST", "/users/register", json={
        "full_name": "Duplicate", "username": user["username"].upper(), "email": "duplicate@example.edu",
        "password": PASSWORD, "department": "IT", "role": EMPLOYEE})
    assert response.status_code == 409
    response = api.request("users", "POST", "/users/login",
                           json={"identifier": user["email"].upper(), "password": PASSWORD})
    assert data(response)["user"]["id"] == user["id"]


@pytest.mark.parametrize("change", [{"email": "bad"}, {"password": "short"}, {"department": ""},
                                    {"username": "bad@username"}, {"role": "admin"}, {"extra": 1}])
def test_invalid_registration(api, change):
    payload = {"full_name": "Validation", "username": "validation." + uuid.uuid4().hex[:8],
               "email": uuid.uuid4().hex + "@example.edu", "password": PASSWORD,
               "department": "IT", "role": EMPLOYEE, **change}
    response = api.request("users", "POST", "/users/register", json=payload)
    assert response.status_code == 400
    assert response.json()["code"] == "INVALID_INPUT"


@pytest.mark.parametrize("payload", [{}, [], {"username": "missing"}])
def test_missing_fields_or_empty_body(api, payload):
    assert api.request("users", "POST", "/users/register", json=payload).status_code == 400


def test_public_privilege_escalation_and_account_field_injection(api):
    response = api.request("users", "POST", "/users/register", json={
        "full_name": "Forbidden", "username": "forbidden", "email": "forbidden@example.edu",
        "password": PASSWORD, "department": "IT", "role": ADMIN})
    assert response.status_code == 403
    user, token = api.new_user()
    assert api.request("users", "PUT", f"/users/{user['id']}", token, json={"role": ADMIN}).status_code == 400
    assert api.request("users", "PUT", f"/users/{user['id']}/role", token, json={"role": ADMIN}).status_code == 403


def test_successful_and_failed_login_and_unknown_actor_logs(api):
    user, _ = api.new_user()
    for identifier in (user["username"], "unknown.user.435"):
        response = api.request("users", "POST", "/users/login", json={"identifier": identifier, "password": "Wrong-Password-435!"})
        assert response.status_code == 401
    logs = data(api.request("logs", "GET", "/logs/search?action=login_failed", api.admin_token))
    assert any(row["user_id"] == user["id"] for row in logs)
    assert any(row["user_id"] is None for row in logs)
    assert "Wrong-Password" not in str(logs)


@pytest.mark.parametrize("status", ["inactive", "suspended"])
def test_account_status_blocks_login_and_existing_token(api, status):
    user, token = api.new_user(ANALYST)
    data(api.request("users", "PUT", f"/users/{user['id']}/status", api.admin_token, json={"account_status": status}))
    assert api.request("users", "POST", "/users/login", json={"identifier": user["username"], "password": PASSWORD}).status_code == 401
    assert api.request("playbooks", "GET", "/playbooks", token).status_code == 401


def test_current_role_checked_for_existing_token(api):
    user, token = api.new_user(ANALYST)
    assert api.request("playbooks", "GET", "/playbooks", token).status_code == 200
    data(api.request("users", "PUT", f"/users/{user['id']}/role", api.admin_token, json={"role": EMPLOYEE}))
    assert api.request("playbooks", "GET", "/playbooks", token).status_code == 403


@pytest.mark.parametrize("kind", ["missing", "invalid", "expired"])
def test_invalid_authentication(api, kind):
    token = None
    if kind == "invalid":
        token = "not.a.valid.jwt"
    elif kind == "expired":
        with api.apps["users"].app_context():
            token = create_access_token(identity=str(api.admin_id), expires_delta=timedelta(seconds=-10))
    response = api.request("playbooks", "GET", "/playbooks", token)
    assert response.status_code == 401
    assert response.json()["status"] == "error"


@pytest.mark.parametrize("role,users_code,logs_code,search_code,books_code", [
    (ADMIN, 200, 200, 200, 200), (ANALYST, 403, 403, 200, 200),
    (EMPLOYEE, 403, 403, 403, 403), (AUDITOR, 200, 200, 200, 200)])
def test_role_matrix(api, role, users_code, logs_code, search_code, books_code):
    _, token = api.new_user(role)
    assert api.request("users", "GET", "/users", token).status_code == users_code
    assert api.request("logs", "GET", "/logs", token).status_code == logs_code
    assert api.request("logs", "GET", "/logs/search", token).status_code == search_code
    assert api.request("playbooks", "GET", "/playbooks", token).status_code == books_code


def test_profile_ownership_update_and_missing_user(api):
    user, token = api.new_user()
    other, _ = api.new_user()
    assert data(api.request("users", "GET", "/users/" + user["username"], token))["id"] == user["id"]
    assert api.request("users", "GET", "/users/" + other["username"], token).status_code == 403
    assert api.request("users", "PUT", f"/users/{other['id']}", token, json={"department": "Other"}).status_code == 403
    updated = data(api.request("users", "PUT", f"/users/{user['id']}", token, json={"department": "Updated"}))
    assert updated["department"] == "Updated"
    assert api.request("users", "GET", "/users/not-a-real-user", api.admin_token).status_code == 404
    assert api.request("users", "DELETE", f"/users/{other['id']}", token).status_code == 403


def test_soft_user_deletion_preserves_foreign_keys_and_revokes_access(api):
    user, token = api.new_user(ADMIN)
    playbook = data(api.request("playbooks", "POST", "/playbooks", token, json={
        "name": "Historical", "description": "Retain", "incident_category": "Other", "severity": "Low"}), 201)
    data(api.request("users", "DELETE", f"/users/{user['id']}", api.admin_token))
    assert api.request("users", "GET", "/users/" + user["username"], api.admin_token).status_code == 404
    assert api.request("playbooks", "GET", "/playbooks", token).status_code == 401
    assert data(api.request("playbooks", "GET", f"/playbooks/{playbook['id']}", api.admin_token))["created_by"] == user["id"]
    with api.apps["users"].extensions["session_factory"]() as session:
        assert session.get(User, user["id"]).deleted_at is not None
        assert session.scalar(select(func.count()).select_from(Log).where(Log.user_id == user["id"])) > 0


def test_service_auth_and_identity_reference(api):
    assert api.request("users", "POST", "/internal/identity/verify", api.admin_token).status_code == 401
    headers = {"X-Service-Name": "logs", "X-Service-Key": api.apps["logs"].config["SERVICE_TOKENS"]["logs"]}
    result = data(api.request("users", "POST", "/internal/identity/verify", api.admin_token, headers=headers))
    assert result == {"id": api.admin_id, "role": ADMIN, "account_status": "active"}
    assert api.request("users", "GET", "/internal/users/2147483647", headers=headers).status_code == 404


def test_internal_log_deduplication_conflicts_and_deleted_retry(api):
    event_id = str(uuid.uuid4())
    headers = {"X-Service-Name": "playbooks", "X-Service-Key": api.apps["playbooks"].config["SERVICE_TOKENS"]["playbooks"],
               "Idempotency-Key": event_id}
    payload = {"user_id": api.admin_id, "action": "integration_event", "description": "Real integration event.",
               "severity": "Information", "related_service": "playbooks"}
    assert api.request("logs", "POST", "/internal/logs", json=payload).status_code == 401
    first = data(api.request("logs", "POST", "/internal/logs", headers=headers, json=payload), 201)
    second = data(api.request("logs", "POST", "/internal/logs", headers=headers, json=payload))
    assert second["duplicate"] and first["log"]["id"] == second["log"]["id"]
    assert api.request("logs", "POST", "/internal/logs", headers=headers, json={**payload, "description": "Different"}).status_code == 409
    data(api.request("logs", "DELETE", f"/logs/{first['log']['id']}", api.admin_token))
    duplicate = data(api.request("logs", "POST", "/internal/logs", headers=headers, json=payload))
    assert duplicate["duplicate"] and duplicate["log"] is None


def test_log_filters_invalid_ids_manual_actor_and_no_updates(api):
    payload = {"user_id": api.admin_id, "action": "manual_check", "description": "Manual administrative record.",
               "severity": "Warning", "related_service": "users"}
    log = data(api.request("logs", "POST", "/logs", api.admin_token, json=payload), 201)
    for query in (f"user_id={api.admin_id}", "action=manual_check", "severity=Warning", "related_service=users",
                  "date=" + log["timestamp"][:10]):
        rows = data(api.request("logs", "GET", "/logs/search?" + query, api.admin_token))
        assert any(row["id"] == log["id"] for row in rows)
    assert data(api.request("logs", "GET", "/logs/user/2147483647", api.admin_token)) == []
    assert api.request("logs", "GET", "/logs/2147483647", api.admin_token).status_code == 404
    assert api.request("logs", "GET", "/logs/search?date=bad", api.admin_token).status_code == 400
    assert api.request("logs", "PUT", f"/logs/{log['id']}", api.admin_token, json=payload).status_code == 405
    assert api.request("logs", "POST", "/logs", api.admin_token, json={**payload, "user_id": None}).status_code == 403
    _, analyst = api.new_user(ANALYST)
    assert data(api.request("logs", "GET", f"/logs/{log['id']}", analyst))["id"] == log["id"]
    assert api.request("logs", "DELETE", f"/logs/{log['id']}", analyst).status_code == 403
    with api.apps["logs"].extensions["engine"].connect() as connection:
        with pytest.raises(DBAPIError):
            connection.execute(text("UPDATE logs SET description='changed' WHERE id=:id"), {"id": log["id"]})
        connection.rollback()


def test_playbook_order_workflow_history_and_deletion(api):
    book = api.playbook()
    analyst_user, analyst = api.new_user(ANALYST)
    actions = []
    for step in (2, 1):
        actions.append(data(api.request("playbooks", "POST", f"/playbooks/{book['id']}/actions", analyst,
                                       json={"description": f"Step {step}", "step_number": step,
                                             "assigned_user_id": analyst_user["id"]}), 201))
    retrieved = data(api.request("playbooks", "GET", f"/playbooks/{book['id']}", analyst))
    assert [row["step_number"] for row in retrieved["actions"]] == [1, 2]
    action = actions[0]
    for status in ("In Progress", "Completed", "Pending"):
        updated = data(api.request("playbooks", "PUT", f"/actions/{action['id']}/status", analyst, json={"status": status}))
        assert bool(updated["completion_date"]) == (status == "Completed")
    retrieved = data(api.request("playbooks", "GET", f"/playbooks/{book['id']}", analyst))
    history = next(row for row in retrieved["actions"] if row["id"] == action["id"])["history"]
    assert len(history) == 4 and history[0]["previous"] is None
    assert history[2]["current"]["status"] == "Completed"
    assert api.request("playbooks", "DELETE", f"/playbooks/{book['id']}", analyst).status_code == 403
    data(api.request("playbooks", "DELETE", f"/playbooks/{book['id']}", api.admin_token))
    assert api.request("playbooks", "GET", f"/playbooks/{book['id']}", api.admin_token).status_code == 404
    assert api.request("playbooks", "PUT", f"/actions/{action['id']}/status", analyst, json={"status": "Completed"}).status_code == 404
    with api.apps["playbooks"].extensions["session_factory"]() as session:
        assert session.get(Playbook, book["id"]).deleted_at
        assert session.scalar(select(func.count()).select_from(ActionHistory).where(ActionHistory.action_id == action["id"])) == 4
    with api.apps["playbooks"].extensions["engine"].connect() as connection:
        with pytest.raises(DBAPIError):
            connection.execute(text("DELETE FROM response_action_history WHERE action_id=:id"), {"id": action["id"]})
        connection.rollback()


def test_playbook_validation_and_auditor_read_only(api):
    book = api.playbook()
    for step in (0, -1, True, "1"):
        assert api.request("playbooks", "POST", f"/playbooks/{book['id']}/actions", api.admin_token,
                           json={"description": "Invalid step", "step_number": step}).status_code == 400
    action = data(api.request("playbooks", "POST", f"/playbooks/{book['id']}/actions", api.admin_token,
                              json={"description": "First", "step_number": 1}), 201)
    assert api.request("playbooks", "POST", f"/playbooks/{book['id']}/actions", api.admin_token,
                       json={"description": "Duplicate", "step_number": 1}).status_code == 409
    assert api.request("playbooks", "PUT", f"/actions/{action['id']}/status", api.admin_token, json={"status": "Closed"}).status_code == 400
    assert api.request("playbooks", "PUT", f"/actions/{action['id']}/status", api.admin_token,
                       json={"assigned_user_id": 2147483647}).status_code == 400
    assert api.request("playbooks", "PUT", f"/actions/{action['id']}/status", api.admin_token,
                       json={"completion_date": "2020-01-01T00:00:00Z"}).status_code == 400
    assert api.request("playbooks", "PUT", f"/actions/{action['id']}/status", api.admin_token,
                       json={"status": "Completed", "completion_date": "2999-01-01T00:00:00Z"}).status_code == 400
    assert api.request("playbooks", "GET", "/playbooks/2147483647", api.admin_token).status_code == 404
    _, auditor = api.new_user(AUDITOR)
    assert api.request("playbooks", "GET", f"/playbooks/{book['id']}", auditor).status_code == 200
    assert api.request("playbooks", "POST", f"/playbooks/{book['id']}/actions", auditor,
                       json={"description": "Forbidden", "step_number": 2}).status_code == 403


def test_identity_outage_fails_closed_without_mutation(api):
    app = api.apps["playbooks"]
    original = app.config["USERS_URL"]
    with app.extensions["session_factory"]() as session:
        before = session.scalar(select(func.count()).select_from(Playbook))
    try:
        app.config["USERS_URL"] = "http://127.0.0.1:1"
        response = api.request("playbooks", "POST", "/playbooks", api.admin_token, json={
            "name": "Must not exist", "description": "Outage", "incident_category": "Test", "severity": "Low"})
        assert response.status_code == 503 and response.json()["code"] == "IDENTITY_UNAVAILABLE"
    finally:
        app.config["USERS_URL"] = original
    with app.extensions["session_factory"]() as session:
        assert session.scalar(select(func.count()).select_from(Playbook)) == before


def test_log_outage_durable_outbox_and_recovery(api):
    app = api.apps["users"]
    original = app.config["LOGS_URL"]
    marker = uuid.uuid4().hex[:10]
    try:
        app.config["LOGS_URL"] = "http://127.0.0.1:1"
        response = api.request("users", "POST", "/users/register", json={
            "full_name": "Outage Test", "username": "outage." + marker, "email": marker + "@example.edu",
            "password": PASSWORD, "department": "IT", "role": EMPLOYEE})
        created = data(response, 201)
        assert response.json()["audit_delivery"]["status"] == "pending"
        with app.extensions["session_factory"]() as session:
            pending = session.scalars(select(UsersOutbox).where(UsersOutbox.delivered_at.is_(None))).all()
            assert any(row.payload["user_id"] == created["id"] for row in pending)
    finally:
        app.config["LOGS_URL"] = original
    with app.app_context():
        assert drain_outbox() == 0
        assert drain_outbox() == 0
    logs = data(api.request("logs", "GET", f"/logs/search?user_id={created['id']}&action=user_created", api.admin_token))
    assert len(logs) == 1


def test_duplicate_email_invalid_json_and_parameterized_lookup(api):
    user, _ = api.new_user()
    response = api.request("users", "POST", "/users/register", json={
        "full_name": "Duplicate email", "username": "email." + uuid.uuid4().hex[:8],
        "email": user["email"].upper(), "password": PASSWORD, "department": "IT", "role": EMPLOYEE})
    assert response.status_code == 409
    response = api.request("users", "POST", "/users/register", data="{bad json", headers={"Content-Type": "application/json"})
    assert response.status_code == 400
    response = api.request("logs", "GET", "/logs/search", api.admin_token,
                           params={"action": "x' OR 1=1 --"})
    assert data(response) == []


def test_assignment_rejects_disabled_users_and_preserves_deleted_assignee(api):
    user, _ = api.new_user(ANALYST)
    book = api.playbook()
    action = data(api.request("playbooks", "POST", f"/playbooks/{book['id']}/actions", api.admin_token,
                              json={"description": "Assigned", "step_number": 1, "assigned_user_id": user["id"]}), 201)
    data(api.request("users", "PUT", f"/users/{user['id']}/status", api.admin_token, json={"account_status": "inactive"}))
    assert api.request("playbooks", "POST", f"/playbooks/{book['id']}/actions", api.admin_token,
                       json={"description": "Inactive", "step_number": 2, "assigned_user_id": user["id"]}).status_code == 400
    data(api.request("users", "DELETE", f"/users/{user['id']}", api.admin_token))
    result = data(api.request("playbooks", "GET", f"/playbooks/{book['id']}", api.admin_token))
    assert result["actions"][0]["assigned_user_id"] == user["id"]
    assert result["actions"][0]["history"][0]["current"]["assigned_user_id"] == user["id"]
    assert api.request("playbooks", "PUT", f"/actions/{action['id']}/status", api.admin_token,
                       json={"assigned_user_id": user["id"]}).status_code == 400


def test_manual_secret_rejection_and_action_missing_id(api):
    response = api.request("logs", "POST", "/logs", api.admin_token, json={
        "user_id": api.admin_id, "action": "unsafe_description", "description": "password=do-not-store",
        "severity": "Information", "related_service": "users"})
    assert response.status_code == 400
    assert api.request("playbooks", "PUT", "/actions/2147483647/status", api.admin_token,
                       json={"status": "Completed"}).status_code == 404


def test_self_lockout_and_missing_role_status_target(api):
    for path, payload in ((f"/users/{api.admin_id}/role", {"role": EMPLOYEE}),
                          (f"/users/{api.admin_id}/status", {"account_status": "suspended"})):
        assert api.request("users", "PUT", path, api.admin_token, json=payload).status_code == 409
    assert api.request("users", "DELETE", f"/users/{api.admin_id}", api.admin_token).status_code == 409
    assert api.request("users", "PUT", "/users/2147483647/role", api.admin_token, json={"role": ANALYST}).status_code == 404


def test_cli_bootstrap_repeatability_migration_and_http_seed(api):
    config = api.apps["users"].config
    suffix = uuid.uuid4().hex[:8]
    environment = {**os.environ, "DATABASE_URL": config["DATABASE_URL"],
                   "JWT_SECRET_KEY": config["JWT_SECRET_KEY"],
                   "SERVICE_TOKENS": json.dumps(config["SERVICE_TOKENS"]),
                   "API_PREFIX": PREFIX, "USERS_URL": api.urls["users"], "LOGS_URL": api.urls["logs"],
                   "PLAYBOOKS_URL": api.urls["playbooks"], "ADMIN_FULL_NAME": "CLI Administrator",
                   "ADMIN_USERNAME": "cli.admin." + suffix, "ADMIN_EMAIL": "cli." + suffix + "@example.edu",
                   "ADMIN_PASSWORD": PASSWORD, "ADMIN_DEPARTMENT": "Security", "DEMO_PASSWORD": PASSWORD}
    for command in (("security_backend", "migrate"), ("security_backend", "create-admin"),
                    ("security_backend", "create-admin"), ("scripts.seed_demo",)):
        result = subprocess.run([sys.executable, "-m", *command], env=environment,
                                capture_output=True, text=True, timeout=45)
        assert result.returncode == 0, result.stdout + result.stderr
    response = api.request("users", "POST", "/users/login", json={"identifier": environment["ADMIN_USERNAME"], "password": PASSWORD})
    login_data = data(response)
    token = login_data["access_token"]
    assert data(api.request("users", "GET", "/users/demo.analyst", token))["role"] == ANALYST
    books = data(api.request("playbooks", "GET", "/playbooks", token))
    created = [book for book in books if book["name"] in ("Phishing response", "Malware response")
               and book["created_by"] == login_data["user"]["id"]]
    assert len(created) == 2
    for book in created:
        assert len(data(api.request("playbooks", "GET", f"/playbooks/{book['id']}", token))["actions"]) == 3
