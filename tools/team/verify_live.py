"""Run nine actual services from the three fixed working trees in one isolated test schema.
No teammate doubles. Generated credentials stay in process memory; only sanitized results are exported.
"""
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import sys
import time
import uuid

import psycopg
from psycopg import sql
import requests
from dotenv import dotenv_values
from sqlalchemy.engine import make_url

import argparse
from datetime import datetime, timezone

REPOSITORY = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--natalio-root", type=Path, default=REPOSITORY)
parser.add_argument("--chris-root", type=Path, default=REPOSITORY)
parser.add_argument("--karim-root", type=Path, default=REPOSITORY)
parser.add_argument("--env-file", type=Path, default=REPOSITORY / ".env.team")
parser.add_argument("--output", type=Path)
arguments = parser.parse_args()
SOURCES = {name: path.resolve() for name, path in (("natalio", arguments.natalio_root), ("chris", arguments.chris_root), ("karim", arguments.karim_root))}
for owner, expected in (("natalio", "security_backend/__main__.py"), ("chris", "services/chris_support/app.py"), ("karim", "apps/incidents_app.py")):
    if not (SOURCES[owner] / expected).is_file():
        parser.error("Missing " + owner + " source root; supply --" + owner + "-root")
if not arguments.env_file.is_file():
    parser.error("Supply a private --env-file containing TEST_DATABASE_URL")
ROOT = arguments.output.resolve() if arguments.output else REPOSITORY / ".runtime" / ("team-live-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8])
ROOT.mkdir(parents=True, exist_ok=False)
PY = {name: Path(sys.executable) for name in SOURCES}
PROCESS_FLAGS = 0x08000000 if os.name == "nt" else 0
RESULT = {"baseline_commits": {"natalio": "caa2de2831590d07149faedd2b63321e0f570b5f",
          "chris": "2ad8c9a2c92e5bc8d30fa9d9945dff112a7894bb", "karim": "0661c950d626fe634f8d30c23f716bf1e517808c"},
          "environment_note": "Nine actual service processes from the supplied roots using one Python runtime. No upstream doubles. Baseline commits identify the v1.1 starting point.",
          "executed_at_utc": datetime.now(timezone.utc).isoformat(),
          "checks": [], "requests": [], "observations": {}}
PROCESSES = {}
HANDLES = []
SESSION = requests.Session()
SESSION.trust_env = False
NAMES = ("users", "assets", "incidents", "threats", "logs", "reports", "vulnerabilities", "notifications", "playbooks")


def check(name, condition, detail=None):
    RESULT["checks"].append({"name": name, "passed": bool(condition), "detail": detail})
    print(("PASS " if condition else "FAIL ") + name, flush=True)
    return bool(condition)


def api(service, method, path, expected=None, token=None, **kwargs):
    headers = kwargs.pop("headers", {})
    if token: headers["Authorization"] = "Bearer " + token
    r = SESSION.request(method, URLS[service] + path, headers=headers, timeout=12, allow_redirects=False, **kwargs)
    RESULT["requests"].append({"service": service, "method": method, "path": path, "status": r.status_code})
    if expected is not None:
        check(f"{service} {method} {path}: HTTP {expected}", r.status_code == expected,
              None if r.status_code == expected else {"actual": r.status_code, "error_code": r.json().get("code")})
    return r


def command(owner, args, label, require=True):
    log = ROOT / (re.sub(r"[^a-z0-9]+", "_", label.lower()) + ".log")
    with log.open("w", encoding="utf-8") as handle:
        p = subprocess.run([str(PY[owner]), *args], cwd=SOURCES[owner], env=ENV,
                           stdout=handle, stderr=subprocess.STDOUT, timeout=50, creationflags=PROCESS_FLAGS)
    check(label, p.returncode == 0, {"exit_code": p.returncode, "log": log.name})
    if require and p.returncode: raise RuntimeError(label + " failed; inspect local sanitized summary/log")
    return p.returncode


def start(name):
    owner = "natalio" if name in ("users", "logs", "playbooks") else "chris" if name in ("assets", "threats", "reports") else "karim"
    if owner == "natalio": args = ["-m", "security_backend", "run", name, "--port", str(PORTS[name])]
    elif owner == "chris": args = ["-m", "uvicorn", f"services.{name}.main:app", "--host", "127.0.0.1", "--port", str(PORTS[name])]
    else: args = [f"apps/{name}_app.py"]
    handle = (ROOT / (name + "-server.log")).open("a", encoding="utf-8")
    HANDLES.append(handle)
    PROCESSES[name] = subprocess.Popen([str(PY[owner]), *args], cwd=SOURCES[owner], env=ENV,
                                        stdout=handle, stderr=subprocess.STDOUT, creationflags=PROCESS_FLAGS)


def stop(name):
    p = PROCESSES.pop(name, None)
    if p:
        p.terminate()
        try: p.wait(timeout=8)
        except subprocess.TimeoutExpired: p.kill(); p.wait(timeout=5)


def ready(name):
    suffix = "/ready" if name in ("assets", "threats", "reports") else "/health"
    for _ in range(60):
        if PROCESSES[name].poll() is not None: raise RuntimeError(name + " process exited; inspect its local log")
        try:
            if SESSION.get(URLS[name] + suffix, timeout=1).status_code == 200:
                check(name + " real service ready", True)
                return
        except requests.RequestException: pass
        time.sleep(.25)
    raise RuntimeError(name + " did not become ready")


def rows(query, parameters=()):
    with psycopg.connect(RAW_SCOPED) as c:
        return c.execute(query, parameters).fetchall()


def scalar(query, parameters=()): return rows(query, parameters)[0][0]


def flush():
    command("chris", ["-m", "services.chris_support.audit_worker", "--once"], "Chris audit flush", False)
    command("karim", ["worker.py", "--flush"], "Karim audit and notification flush", False)
    command("karim", ["worker.py", "--flush"], "Karim notification creation audit flush", False)
    for name in ("users", "playbooks"):
        command("natalio", ["-m", "security_backend", "flush-audit", name], name + " audit flush", False)


def report_check(token, label):
    for suffix in ("summary", "assets", "incidents", "threats", "vulnerabilities", "activity"):
        api("reports", "GET", "/reports/" + suffix, 200, token)
    checker_env = {**ENV, "TEAM_ADMIN_TOKEN": token, "TEAM_REPORTS_SERVICE_KEY": KEYS["reports"]}
    checker_env.update({"TEAM_" + name.upper() + "_URL": url for name, url in URLS.items()})
    result = subprocess.run([str(PY["chris"]), "tools/chris/check_team_integration.py"], cwd=SOURCES["chris"],
                            env=checker_env, capture_output=True, text=True, timeout=60, creationflags=PROCESS_FLAGS)
    (ROOT / (label + "-checker.txt")).write_text(result.stdout + result.stderr, encoding="utf-8")
    check(label + " actual nine-service reconciliation checker", result.returncode == 0, {"exit_code": result.returncode})


values = dotenv_values(arguments.env_file)
if not values.get("TEST_DATABASE_URL"):
    parser.error("Private environment must define TEST_DATABASE_URL for a pre-existing dedicated *_test database")
base = make_url(values["TEST_DATABASE_URL"])
if base.host not in ("127.0.0.1", "localhost") or not (base.database or "").endswith("_test") or base.drivername != "postgresql+psycopg":
    parser.error("Refusing live tests: use a local PostgreSQL+Psycopg TEST_DATABASE_URL ending in _test")
SCHEMA = "team_audit_test_" + uuid.uuid4().hex
assert re.fullmatch(r"team_audit_test_[0-9a-f]{32}", SCHEMA)
ROOT_RAW = base.set(drivername="postgresql").render_as_string(hide_password=False)
scoped = base.update_query_dict({"options": "-csearch_path=" + SCHEMA})
SQL_URL = scoped.render_as_string(hide_password=False)
RAW_SCOPED = scoped.set(drivername="postgresql").render_as_string(hide_password=False)
SOCKETS = [socket.socket() for _ in NAMES]
for sock in SOCKETS: sock.bind(("127.0.0.1", 0))
PORTS = {name: sock.getsockname()[1] for name, sock in zip(NAMES, SOCKETS)}
for sock in SOCKETS: sock.close()
ORIGINS = {name: f"http://127.0.0.1:{port}" for name, port in PORTS.items()}
URLS = {name: origin + ("/api/natalio-hassoun" if name in ("users", "logs", "playbooks") else "/api/chris-gharfine" if name in ("assets", "threats", "reports") else "/api/karim-hajj-ali") for name, origin in ORIGINS.items()}
KEYS = {name: secrets.token_hex(32) for name in NAMES}
SECRET = secrets.token_hex(32)
PASSWORD = "Audit-" + secrets.token_hex(16) + "!"
ENV = {key: value for key, value in os.environ.items()
       if not key.startswith(("KARIM_", "CHRIS_", "JWT_", "TEAM_")) and key not in ("DATABASE_URL", "SERVICE_TOKENS", "PYTHONPATH")}
ENV.update(DATABASE_URL=SQL_URL, API_PREFIX="/api/natalio-hassoun", JWT_SECRET_KEY=SECRET,
           SERVICE_TOKENS=json.dumps(KEYS), USERS_URL=ORIGINS["users"], LOGS_URL=ORIGINS["logs"],
           SERVICE_TIMEOUT="1", JWT_ENCODE_ISSUER="security-sprint1-users", JWT_DECODE_ISSUER="security-sprint1-users",
           JWT_ENCODE_AUDIENCE="security-sprint1-services", JWT_DECODE_AUDIENCE="security-sprint1-services",
           ADMIN_FULL_NAME="Natalio Hassoun Audit", ADMIN_USERNAME="audit.admin", ADMIN_EMAIL="audit.admin@example.edu",
           ADMIN_PASSWORD=PASSWORD, ADMIN_DEPARTMENT="Security", PYTHONUNBUFFERED="1",
           CHRIS_API_PREFIX="/api/chris-gharfine", KARIM_API_PREFIX="/api/karim-hajj-ali", CHRIS_DATABASE_URL=SQL_URL, CHRIS_JWT_VERIFICATION_KEY=SECRET, CHRIS_SERVICE_TOKENS=json.dumps(KEYS),
           CHRIS_HTTP_TIMEOUT_SECONDS="1", CHRIS_USERS_URL=URLS["users"], CHRIS_ASSETS_URL=URLS["assets"],
           CHRIS_THREATS_URL=URLS["threats"], CHRIS_INCIDENTS_URL=URLS["incidents"], CHRIS_AUDIT_URL=URLS["logs"],
           CHRIS_VULNERABILITIES_URL=URLS["vulnerabilities"], KARIM_DATABASE_URL=RAW_SCOPED,
           KARIM_JWT_VERIFICATION_KEY=SECRET, KARIM_USERS_URL=URLS["users"], KARIM_ASSETS_URL=URLS["assets"],
           KARIM_LOGS_URL=URLS["logs"], KARIM_NOTIFICATIONS_URL=URLS["notifications"],
           KARIM_SERVICE_TOKENS=",".join(name + ":" + key for name, key in KEYS.items()), KARIM_HTTP_TIMEOUT_SECONDS="1")
for name in ("incidents", "vulnerabilities", "notifications"):
    ENV["KARIM_" + name.upper() + "_SERVICE_KEY"] = KEYS[name]
    ENV["KARIM_" + name.upper() + "_PORT"] = str(PORTS[name])
created = False
try:
    with psycopg.connect(ROOT_RAW, autocommit=True) as c:
        c.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(SCHEMA)))
    created = True
    command("natalio", ["-m", "security_backend", "migrate"], "Natalio migration")
    command("chris", ["-m", "alembic", "-c", "services/chris_support/alembic.ini", "upgrade", "head"], "Chris migration")
    command("karim", ["migrate.py"], "Karim migration")
    command("natalio", ["-m", "security_backend", "migrate"], "Natalio repeated migration preserves data")
    command("chris", ["-m", "alembic", "-c", "services/chris_support/alembic.ini", "upgrade", "head"], "Chris repeated migration")
    command("karim", ["migrate.py"], "Karim repeated migration checksums")
    for name in NAMES: start(name)
    for name in NAMES: ready(name)
    command("natalio", ["-m", "security_backend", "create-admin"], "Native administrator bootstrap")
    admin = api("users", "POST", "/users/login", 200, json={"identifier": "audit.admin", "password": PASSWORD}).json()["data"]
    ADMIN = admin["access_token"]
    ACTORS = {"admin": admin["user"]}
    TOKENS = {"admin": ADMIN}
    for role, value in (("analyst", "security_analyst"), ("employee", "regular_employee"), ("auditor", "auditor")):
        user = api("users", "POST", "/users/register", 201, ADMIN, json={"full_name": "Team Audit " + role,
                   "username": "audit." + role, "email": "audit." + role + "@example.edu", "password": PASSWORD,
                   "department": "Security", "role": value}).json()["data"]
        ACTORS[role] = user
        TOKENS[role] = api("users", "POST", "/users/login", 200,
                          json={"identifier": user["username"], "password": PASSWORD}).json()["data"]["access_token"]
    api("users", "POST", "/users/login", 401, json={"identifier": "audit.employee", "password": "Deliberately-Incorrect!"})
    asset = api("assets", "POST", "/assets", 201, ADMIN, json={"name": "Integration audit server", "asset_type": "server",
                "ip_address": "192.0.2.10", "department": "Security", "owner_id": ACTORS["employee"]["id"],
                "criticality": "high", "status": "active"}).json()
    api("threats", "POST", "/threats", 201, ADMIN, json={"threat_type": "domain", "threat_value": "audit-indicator.example",
          "description": "Isolated integration audit indicator", "severity": "critical", "source": "Team audit"})
    incident = api("incidents", "POST", "/incidents", 201, TOKENS["employee"], json={"title": "Integration audit incident",
                   "description": "Isolated workflow", "category": "Malware Infection", "severity": "High", "affected_asset": asset["id"]}).json()["incident"]
    iid = incident["incident_id"]
    api("incidents", "PUT", f"/incidents/{iid}/assign", 200, ADMIN, json={"analyst_id": ACTORS["analyst"]["id"]})
    vuln = api("vulnerabilities", "POST", "/vulnerabilities", 201, ADMIN, json={"title": "Integration audit finding",
               "description": "Isolated finding", "severity": "Critical", "affected_asset": asset["id"],
               "cvss_score": 9.8, "cve_identifier": "CVE-2026-12345", "discovery_source": "Audit"}).json()["vulnerability"]
    book = api("playbooks", "POST", "/playbooks", 201, ADMIN, json={"name": "Integration response", "description": "Audit response",
                "incident_category": "Malware Infection", "severity": "High"}).json()["data"]
    action = api("playbooks", "POST", f"/playbooks/{book['id']}/actions", 201, TOKENS["analyst"],
                 json={"description": "Investigate", "step_number": 1, "assigned_user_id": ACTORS["analyst"]["id"]}).json()["data"]
    api("playbooks", "PUT", f"/actions/{action['id']}/status", 200, TOKENS["analyst"], json={"status": "Completed"})
    flush()
    for role, notification_type in (("analyst", "Incident Assignment"), ("employee", "Vulnerability Alert")):
        found = api("notifications", "GET", f"/notifications/user/{ACTORS[role]['id']}", 200, TOKENS[role]).json()["notifications"]
        check(role + " receives exactly one automatic " + notification_type,
              len([n for n in found if n["notification_type"] == notification_type]) == 1)
    report_check(ADMIN, "initial")
    api("assets", "DELETE", f"/assets/{asset['id']}", 409, ADMIN)
    api("reports", "GET", "/reports/summary", 200, TOKENS["auditor"])
    api("reports", "GET", "/reports/summary", 403, TOKENS["employee"])
    api("logs", "GET", "/logs", 403, TOKENS["analyst"])
    # Real status updates use the SAME issued token across owners.
    aid = ACTORS["analyst"]["id"]
    api("users", "PUT", f"/users/{aid}/status", 200, ADMIN, json={"account_status": "suspended"})
    for name, path in (("assets", f"/assets/{asset['id']}"), ("incidents", f"/incidents/{iid}"), ("playbooks", "/playbooks")):
        api(name, "GET", path, 401, TOKENS["analyst"])
    api("users", "PUT", f"/users/{aid}/status", 200, ADMIN, json={"account_status": "active"})
    # Actual Logging outage; mutation succeeds once, real outboxes recover.
    stop("logs")
    api("incidents", "POST", f"/incidents/{iid}/notes", 201, TOKENS["analyst"], json={"note_content": "Audit outage note"})
    command("karim", ["worker.py", "--flush"], "Audit delivery during real Logs outage", False)
    check("Karim audit remains pending through real outage", scalar("SELECT count(*) FROM karim_audit_outbox WHERE delivered_at IS NULL") > 0)
    start("logs"); ready("logs"); time.sleep(3)
    flush()
    check("Karim audit recovered without duplicate event UUIDs", scalar("SELECT count(*) FROM karim_audit_outbox WHERE delivered_at IS NULL") == 0
          and scalar("SELECT count(*) FROM (SELECT event_id FROM logs GROUP BY event_id HAVING count(*)>1) d") == 0)
    # Notification outage and restart; persisted assignment work delivered once.
    stop("notifications")
    api("incidents", "PUT", f"/incidents/{iid}/assign", 200, ADMIN, json={"analyst_id": aid})
    command("karim", ["worker.py", "--flush"], "Notification delivery during real outage", False)
    check("Notification work remains pending through real outage", scalar("SELECT count(*) FROM karim_notification_outbox WHERE delivered_at IS NULL") > 0)
    start("notifications"); ready("notifications"); time.sleep(3)
    flush()
    check("Notification work recovers after restart", scalar("SELECT count(*) FROM karim_notification_outbox WHERE delivered_at IS NULL") == 0)
    # Reproduce suspected missing audit event from a real data modification.
    notification = api("notifications", "GET", f"/notifications/user/{aid}", 200, TOKENS["analyst"]).json()["notifications"][0]
    before = scalar("SELECT count(*) FROM karim_audit_outbox WHERE source_service='notifications'")
    api("notifications", "PUT", f"/notifications/{notification['notification_id']}/read", 200, TOKENS["analyst"])
    after = scalar("SELECT count(*) FROM karim_audit_outbox WHERE source_service='notifications'")
    RESULT["observations"]["mark_read_audit_events_added"] = after - before
    check("Notification mark-read queues exactly one required mutation audit", after == before + 1)
    # Re-reading is idempotent and ownership denials are durably audited.
    api("notifications", "PUT", f"/notifications/{notification['notification_id']}/read", 200, TOKENS["analyst"])
    check("Repeated mark-read does not duplicate mutation audit", scalar("SELECT count(*) FROM karim_audit_outbox WHERE source_service='notifications'") == after)
    api("notifications", "PUT", f"/notifications/{notification['notification_id']}/read", 403, TOKENS["employee"])
    check("Notification ownership denial queues audit", scalar("SELECT count(*) FROM karim_audit_outbox WHERE source_service='notifications' AND action='unauthorized_access'") > 0)
    # All public error envelopes share status/code/message.

    for name, path in (("users", "/users"), ("assets", "/assets"), ("incidents", "/incidents")):
        denied = api(name, "GET", path, 401)
        RESULT["observations"][name + "_error_keys"] = sorted(denied.json())
        check(name + " standard error envelope", denied.json().get("status") == "error" and isinstance(denied.json().get("code"), str) and isinstance(denied.json().get("message"), str))
    invalid = api("assets", "POST", "/assets", 400, ADMIN, json={})
    check("Chris validation includes common error code", invalid.json().get("code") == "INVALID_INPUT")
    for name in NAMES:
        legacy = SESSION.get(ORIGINS[name] + "/health", timeout=4)
        check(name + " does not expose unprefixed legacy API", legacy.status_code == 404)
    invalid_actor = api("notifications", "POST", "/internal/notifications", 404,
        headers={"X-Service-Name": "incidents", "X-Service-Key": KEYS["incidents"], "Idempotency-Key": str(uuid.uuid4())},
        json={"user_id": aid, "actor_user_id": 2147483647, "title": "Invalid actor test", "message": "Isolated negative test", "notification_type": "Incident Assignment", "severity_level": "Low"})
    for name, path in (("incidents", "/incidents"), ("vulnerabilities", "/vulnerabilities"), ("notifications", "/notifications")):
        invalid_json = api(name, "POST", path, 400, ADMIN, json=[1])
        check(name + " rejects non-object JSON safely", invalid_json.json().get("code") == "INVALID_INPUT")
    # Complete lifecycles through actual APIs and reconcile changed counts.
    for state in ("Under Investigation", "Mitigated", "Resolved", "Closed"):
        api("incidents", "PUT", f"/incidents/{iid}/status", 200, ADMIN, json={"status": state})
    for state in ("Under Investigation", "In Progress", "Resolved", "Closed"):
        api("vulnerabilities", "PUT", f"/vulnerabilities/{vuln['vulnerability_id']}", 200, ADMIN, json={"status": state})
    flush()
    report_check(ADMIN, "final")
except Exception as exc:
    RESULT["fatal_error"] = type(exc).__name__ + ": inspect the local ignored runtime logs; exception details are omitted to protect configuration"
    print("AUDIT STOPPED: " + RESULT["fatal_error"], flush=True)
finally:
    for name in list(PROCESSES): stop(name)
    for handle in HANDLES: handle.close()
    if created:
        with psycopg.connect(ROOT_RAW, autocommit=True) as c:
            c.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(SCHEMA)))
        RESULT["isolated_schema_removed"] = True
    RESULT["passed"] = sum(c["passed"] for c in RESULT["checks"])
    RESULT["failed"] = sum(not c["passed"] for c in RESULT["checks"])
    (ROOT / "live-results.json").write_text(json.dumps(RESULT, indent=2), encoding="utf-8")
    print(f"RESULT: {RESULT['passed']} passed, {RESULT['failed']} failed; fatal={bool(RESULT.get('fatal_error'))}", flush=True)

if RESULT.get("fatal_error") or RESULT["failed"]:
    raise SystemExit(1)
