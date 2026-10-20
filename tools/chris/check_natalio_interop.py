"""Optional, destructive-only-to-its-own-schema Chris/Natalio HTTP smoke check.

Requires CHRIS_NATALIO_SOURCE pointing at an unchanged ignored snapshot of
cb2728cdfc52b9fc3bd314deccea0aea02c1f48d, and CHRIS_TEST_DATABASE_URL pointing
at PostgreSQL with a database name starting chris_test. It creates, migrates and
removes one random schema. It never alters the original snapshot or existing
schemas. Native issuer/audience factory overrides enable this partial check;
they do not establish that Natalio has implemented all v1 requirements.

Install Natalio's requirements in an isolated runtime alongside Chris's test
requirements. Run from the repository root with that runtime's Python:
    python tools/chris/check_natalio_interop.py
"""

from collections import Counter
from contextlib import ExitStack, contextmanager, redirect_stdout
from datetime import datetime, timezone
import hashlib
import importlib
import io
import logging
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import sys
import threading
import time
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[2]
NATALIO_COMMIT = "cb2728cdfc52b9fc3bd314deccea0aea02c1f48d"
SERVICE_NAMES = (
    "users", "assets", "incidents", "threats", "logs", "reports",
    "vulnerabilities", "notifications", "playbooks",
)
PREFIX = "/api/natalio-hassoun"


class CheckFailure(Exception):
    pass


class ConfigurationFailure(CheckFailure):
    pass


def require(condition, message):
    if not condition:
        raise CheckFailure(message)


@contextmanager
def temporary_environment(values):
    previous = {name: os.environ.get(name) for name in values}
    os.environ.update(values)
    try:
        yield
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def verify_snapshot(source):
    # Windows Git exports may convert LF to CRLF. Normalize only that exact
    # byte pair; every other source byte and the complete Python file list must
    # still match the inspected commit. Do not rewrite the snapshot itself.
    def source_hash(value):
        return hashlib.sha256(value.replace(b"\r\n", b"\n")).digest()

    def git(*args):
        result = subprocess.run(
            ["git", *args], cwd=ROOT, capture_output=True, timeout=15, check=False,
        )
        if result.returncode:
            raise ConfigurationFailure("Cannot verify the expected Natalio source revision")
        return result.stdout
    paths = git("ls-tree", "-r", "--name-only", NATALIO_COMMIT,
                "security_backend", "database/001_student1.sql").decode().splitlines()
    expected = {path for path in paths if path.endswith((".py", ".sql"))}
    actual = {path.relative_to(source).as_posix() for path in (source / "security_backend").rglob("*.py")}
    require(bool(expected), "The expected native source tree is unavailable")
    require(actual == {path for path in expected if path.endswith(".py")},
            "Native Python files differ from the expected snapshot")
    for relative in sorted(expected):
        path = source / relative
        require(path.is_file(), "Native snapshot is missing a required source file")
        require(source_hash(path.read_bytes()) == source_hash(
            git("show", f"{NATALIO_COMMIT}:{relative}")
        ), "Native source differs from the inspected revision")


def quiet_werkzeug_server(app):
    from werkzeug.serving import WSGIRequestHandler, make_server

    class QuietHandler(WSGIRequestHandler):
        def log(self, *args, **kwargs):
            pass

    return make_server("127.0.0.1", 0, app, threaded=True, request_handler=QuietHandler)


@contextmanager
def run_wsgi(server):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@contextmanager
def run_asgi(app):
    import uvicorn

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(128)
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=0,
                                         log_level="critical", access_log=False))
    thread = threading.Thread(target=lambda: server.run(sockets=[sock]), daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 10
        while not server.started and thread.is_alive() and time.monotonic() < deadline:
            time.sleep(0.02)
        require(server.started, "A Chris HTTP server did not start")
        yield f"http://127.0.0.1:{sock.getsockname()[1]}{app.state.settings.api_prefix}"
    finally:
        server.should_exit = True
        thread.join(timeout=5)
        if thread.is_alive():
            server.force_exit = True
            thread.join(timeout=2)
        sock.close()


def run():
    # Dependency imports stay inside the guarded entry point: failures never
    # print environment values, connection strings, tokens or response bodies.
    import httpx
    import jwt
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, func, select, text
    from sqlalchemy.engine import make_url
    from sqlalchemy.orm import sessionmaker

    source_text = os.environ.get("CHRIS_NATALIO_SOURCE", "")
    database_text = os.environ.get("CHRIS_TEST_DATABASE_URL", "")
    if not source_text or not database_text:
        raise ConfigurationFailure("Set CHRIS_NATALIO_SOURCE and a dedicated CHRIS_TEST_DATABASE_URL")
    source = Path(source_text).resolve()
    database_url = make_url(database_text)
    if database_url.drivername != "postgresql+psycopg" or not (database_url.database or "").startswith("chris_test"):
        raise ConfigurationFailure("Refusing integration outside a dedicated chris_test* PostgreSQL database")
    verify_snapshot(source)
    sys.path.insert(0, str(source))
    sys.path.insert(0, str(ROOT))
    native = importlib.import_module("security_backend.app")
    setup = importlib.import_module("security_backend.__main__")
    native_audit = importlib.import_module("security_backend.shared.audit")
    require(Path(native.__file__).resolve() == source / "security_backend/app.py",
            "The imported native factory is not the verified snapshot")
    from services.chris_support.app import create_app
    from services.chris_support.audit import AuditOutbox
    from services.chris_support.audit_worker import deliver_batch, queue_counts, valid_receipt
    from services.chris_support.config import Settings
    from services.chris_support.database import utcnow

    print(f"Native snapshot verified (CRLF/LF normalized): {NATALIO_COMMIT}", flush=True)
    print("Partial actual HTTP integration; native issuer/audience use runtime factory overrides.", flush=True)
    schema = "chris_test_interop_" + uuid4().hex
    require(bool(re.fullmatch(r"chris_test_interop_[0-9a-f]{32}", schema)), "Invalid owned schema name")
    scoped_url = database_url.update_query_dict({"options": f"-csearch_path={schema}"})
    scoped_text = scoped_url.render_as_string(hide_password=False)
    root_engine = create_engine(database_url, hide_parameters=True)
    native_apps = []
    scoped_engine = None
    schema_created = False
    secret = secrets.token_urlsafe(48)
    keys = {name: secrets.token_urlsafe(48) for name in SERVICE_NAMES}
    password = "Aa1!" + secrets.token_urlsafe(32)
    phase = "isolated migration"
    try:
        with root_engine.begin() as connection:
            connection.execute(text(f'CREATE SCHEMA "{schema}"'))
        schema_created = True
        # The URL itself scopes every connection, including engines built by
        # the unchanged native factory. No application engine can see public.
        overrides = {
            "DATABASE_URL": scoped_text, "JWT_SECRET_KEY": secret,
            "SERVICE_TOKENS": keys, "API_PREFIX": PREFIX, "SERVICE_TIMEOUT": 3,
            "USERS_URL": "http://127.0.0.1:1", "LOGS_URL": "http://127.0.0.1:1",
            "JWT_ALGORITHM": "HS256", "JWT_ENCODE_ISSUER": "security-sprint1-users",
            "JWT_DECODE_ISSUER": "security-sprint1-users",
            "JWT_ENCODE_AUDIENCE": "security-sprint1-services",
            "JWT_DECODE_AUDIENCE": "security-sprint1-services",
        }
        users_app = native.create_app("users", overrides)
        native_apps.append(users_app)
        logs_app = native.create_app("logs", overrides)
        native_apps.append(logs_app)
        for app in native_apps:
            with app.extensions["engine"].connect() as connection:
                require(connection.scalar(text("SELECT current_schema()")) == schema,
                        "A native engine escaped the owned schema")
        with users_app.app_context(), redirect_stdout(io.StringIO()):
            setup.migrate(users_app)
        scoped_engine = create_engine(scoped_url, hide_parameters=True)
        with scoped_engine.begin() as connection, temporary_environment({"CHRIS_DATABASE_URL": scoped_text}):
            require(connection.scalar(text("SELECT current_schema()")) == schema,
                    "Chris engine escaped the owned schema")
            config = Config(str(ROOT / "services/chris_support/alembic.ini"))
            config.attributes["connection"] = connection
            command.upgrade(config, "head")
        print("PASS native migration then Chris migration in a new owned schema", flush=True)

        users_server, logs_server = quiet_werkzeug_server(users_app), quiet_werkzeug_server(logs_app)
        users_origin = f"http://127.0.0.1:{users_server.server_port}"
        logs_origin = f"http://127.0.0.1:{logs_server.server_port}"
        for app in native_apps:
            app.config.update(USERS_URL=users_origin, LOGS_URL=logs_origin)
        with ExitStack() as stack:
            stack.enter_context(run_wsgi(users_server))
            stack.enter_context(run_wsgi(logs_server))
            settings = Settings(
                database_url=scoped_text, jwt_verification_key=secret,
                users_url=users_origin + PREFIX, audit_url=logs_origin + PREFIX,
                service_tokens=keys,
            )
            apps = {name: create_app(name, settings=settings, engine=scoped_engine)
                    for name in ("assets", "threats", "reports")}
            addresses = {name: stack.enter_context(run_asgi(app)) for name, app in apps.items()}
            # Apps share only immutable interface settings and separate HTTP
            # clients; all lookups/reports still cross real local HTTP sockets.
            settings.assets_url, settings.threats_url = addresses["assets"], addresses["threats"]
            client = stack.enter_context(httpx.Client(timeout=5, follow_redirects=False, trust_env=False))

            def call(label, method, url, *, expected=200, **kwargs):
                response = client.request(method, url, **kwargs)
                expected_codes = {expected} if type(expected) is int else set(expected)
                require(response.status_code in expected_codes, f"{label}: HTTP {response.status_code}")
                try:
                    return response.json()
                except ValueError:
                    raise CheckFailure(f"{label}: invalid JSON response") from None

            def service_headers(name, event_id=None):
                headers = {"X-Service-Name": name, "X-Service-Key": keys[name]}
                if event_id:
                    headers["Idempotency-Key"] = event_id
                return headers

            phase = "native administrator bootstrap"
            with temporary_environment({
                "ADMIN_FULL_NAME": "Chris Integration Administrator", "ADMIN_USERNAME": "interop_admin",
                "ADMIN_EMAIL": "interop_admin@example.com", "ADMIN_PASSWORD": password,
                "ADMIN_DEPARTMENT": "Integration verification",
            }), users_app.app_context(), redirect_stdout(io.StringIO()):
                setup.create_admin(users_app)
            login = call("Native admin login", "POST", settings.users_url + "/users/login",
                         json={"identifier": "interop_admin", "password": password})
            admin_token = login["data"]["access_token"]
            admin_id = login["data"]["user"]["id"]
            admin_headers = {"Authorization": f"Bearer {admin_token}"}
            claims = jwt.decode(admin_token, secret, algorithms=["HS256"],
                                issuer=settings.jwt_issuer, audience=settings.jwt_audience,
                                options={"require": ["sub", "iat", "exp", "iss", "aud", "type"]})
            require(claims["type"] == "access", "Native login did not issue an access token")
            for base in (settings.users_url, settings.audit_url, *addresses.values()):
                call("Actual service health", "GET", base + "/health")
            for base in addresses.values():
                call("Chris database readiness", "GET", base + "/ready")
            print("PASS five actual HTTP services and a Users-issued HS256 access token", flush=True)

            phase = "owner references and scoped internal Assets"
            account = call("Register temporary administrator", "POST", settings.users_url + "/users/register",
                           headers=admin_headers, expected=201, json={
                               "full_name": "Integration Mutable Account", "username": "interop_mutable",
                               "email": "interop_mutable@example.com", "password": password,
                               "department": "Integration verification", "role": "security_administrator",
                           })["data"]
            account_id = account["id"]
            user_login = call("Temporary account login", "POST", settings.users_url + "/users/login",
                              json={"identifier": "interop_mutable", "password": password})
            user_headers = {"Authorization": "Bearer " + user_login["data"]["access_token"]}
            asset_body = {
                "name": "Integration reference server", "asset_type": "server",
                "ip_address": "192.0.2.30", "department": "Integration verification",
                "owner_id": account_id, "criticality": "critical", "status": "active",
            }
            asset = call("Create asset using native owner reference", "POST", addresses["assets"] + "/assets",
                         headers=admin_headers, json=asset_body, expected=201)
            asset_url = addresses["assets"] + f"/assets/{asset['id']}"
            call("Change asset owner", "PUT", asset_url, headers=admin_headers, json={"owner_id": admin_id})
            call("Restore asset owner", "PUT", asset_url, headers=admin_headers, json={"owner_id": account_id})
            call("Reject nonexistent owner", "POST", addresses["assets"] + "/assets", headers=admin_headers,
                 json=asset_body | {"owner_id": 2_147_483_647}, expected=404)
            internal_asset = addresses["assets"] + f"/internal/assets/{asset['id']}"
            for service in ("incidents", "vulnerabilities"):
                reference = call("Scoped internal asset lookup", "GET", internal_asset,
                                 headers=service_headers(service))
                require(reference == {"status": "success", "data": {
                    "id": asset["id"], "name": asset["name"], "criticality": "critical", "owner_id": account_id,
                }}, "Internal Assets reference differs from v1")
            call("Reject valid unscoped service", "GET", internal_asset,
                 headers=service_headers("reports"), expected=403)
            call("Reject invalid service key", "GET", internal_asset,
                 headers={"X-Service-Name": "incidents", "X-Service-Key": "invalid"}, expected=401)
            print("PASS real owner lookups/reassignment and scoped internal Assets credentials", flush=True)

            phase = "actual Assets and Threats report sources"
            threat = call("Create threat", "POST", addresses["threats"] + "/threats", headers=admin_headers,
                          expected=201, json={
                              "threat_type": "domain", "threat_value": "interop-indicator.example",
                              "description": "Actual isolated integration indicator", "severity": "critical",
                              "source": "Isolated integration run",
                          })
            asset_report = call("Assets report", "GET", addresses["reports"] + "/reports/assets", headers=admin_headers)
            require(asset_report == {
                "total_assets": 1, "critical_assets": 1,
                "assets_by_type": {name: int(name == "server") for name in (
                    "server", "workstation", "database", "application", "network_device", "cloud_resource",
                )},
            }, "Actual Assets report totals differ")
            threat_report = call("Threats report", "GET", addresses["reports"] + "/reports/threats", headers=admin_headers)
            require(threat_report["total_threats"] == 1 and threat_report["recent_threats"] == [threat],
                    "Actual Threats report records differ")
            require(threat_report["threats_by_severity"] == {
                name: int(name == "critical") for name in ("low", "medium", "high", "critical")
            } and threat_report["threats_by_type"] == {
                name: int(name == "domain") for name in ("ip_address", "domain", "file_hash", "malware_signature", "other")
            }, "Actual Threats report buckets differ")
            print("PASS Assets/Threats reports reconcile against actual HTTP source records", flush=True)

            phase = "durable audit delivery and native receipts"
            factory = sessionmaker(scoped_engine, expire_on_commit=False)
            require(deliver_batch(factory, client, settings) > 0, "No Chris events delivered to native Logs")
            require(queue_counts(factory) == (0, 0), "Chris audit queue did not drain")
            with factory() as session:
                event = session.scalar(select(AuditOutbox).where(
                    AuditOutbox.action == "asset_updated",
                ).order_by(AuditOutbox.created_at, AuditOutbox.id).limit(1))
                event_id, event_payload = event.id, dict(event.transport_payload)
            duplicate = call("Native identical audit retry", "POST", settings.audit_url + "/internal/logs",
                             headers=service_headers("assets", event_id), json=event_payload)
            require(valid_receipt(duplicate, 200, event_id), "Native duplicate receipt rejected")
            log_id = duplicate["data"]["log"]["id"]
            conflict = call("Native changed-payload conflict", "POST", settings.audit_url + "/internal/logs",
                            headers=service_headers("assets", event_id),
                            json=event_payload | {"description": "Changed isolated test payload"}, expected=409)
            require(conflict.get("code") == "IDEMPOTENCY_CONFLICT", "Native conflict code differs")
            call("Native legitimate log deletion", "DELETE", settings.audit_url + f"/logs/{log_id}", headers=admin_headers)
            with factory.begin() as session:
                row = session.get(AuditOutbox, event_id)
                row.delivered_at, row.next_attempt_at = None, utcnow()
            require(deliver_batch(factory, client, settings) == 1, "Worker did not accept native deleted-log receipt")
            require(queue_counts(factory) == (0, 0), "Deleted-log retry remained pending")
            with scoped_engine.connect() as connection:
                require(connection.scalar(text("SELECT count(*) FROM logs WHERE event_id=:event"),
                                          {"event": event_id}) == 0, "Deleted log was recreated on exact retry")
            print("PASS actual Logs delivery, exact retry, payload conflict and deleted-log receipt", flush=True)

            phase = "current identity changes using the same real token"
            call("Original account authorized", "GET", addresses["assets"] + "/assets", headers=user_headers)
            account_url = settings.users_url + f"/users/{account_id}"
            call("Native role downgrade", "PUT", account_url + "/role", headers=admin_headers,
                 json={"role": "security_analyst"})
            call("Same JWT reflects analyst restriction", "GET", addresses["assets"] + "/assets",
                 headers=user_headers, expected=403)
            call("Same JWT retains analyst asset lookup", "GET", asset_url, headers=user_headers)
            call("Native role auditor", "PUT", account_url + "/role", headers=admin_headers, json={"role": "auditor"})
            call("Same JWT reflects auditor report permission", "GET", addresses["reports"] + "/reports/assets",
                 headers=user_headers)
            call("Native account suspension", "PUT", account_url + "/status", headers=admin_headers,
                 json={"account_status": "suspended"})
            call("Same JWT rejected after suspension", "GET", addresses["assets"] + "/assets",
                 headers=user_headers, expected=401)
            call("Native account reactivation", "PUT", account_url + "/status", headers=admin_headers,
                 json={"account_status": "active"})
            call("Same JWT accepted after reactivation", "GET", addresses["assets"] + "/assets", headers=user_headers)
            call("Native account soft deletion", "DELETE", account_url, headers=admin_headers)
            call("Same JWT rejected after deletion", "GET", addresses["assets"] + "/assets",
                 headers=user_headers, expected=401)
            call("Deleted owner unavailable for new asset", "POST", addresses["assets"] + "/assets",
                 headers=admin_headers, json=asset_body, expected=400)
            with scoped_engine.connect() as connection:
                require(connection.scalar(text("SELECT owner_id FROM assets WHERE id=:id"), {"id": asset["id"]}) == account_id,
                        "Historical asset ownership was lost")
                require(connection.scalar(text("SELECT deleted_at IS NOT NULL FROM users WHERE id=:id"),
                                          {"id": account_id}) is True, "Native soft deletion did not retain the user")
            print("PASS same JWT respects real role changes, suspension/reactivation and soft deletion", flush=True)

            phase = "actual Logs activity report reconciliation"
            call("Actual failed login", "POST", settings.users_url + "/users/login",
                 json={"identifier": "interop_admin", "password": "IntentionallyWrong1!"}, expected=401)
            with users_app.app_context():
                require(native_audit.drain_outbox() == 0, "Native Users audit queue did not drain")
            deliver_batch(factory, client, settings)
            require(queue_counts(factory) == (0, 0), "Final Chris audit queue did not drain")
            logs = call("Actual native Logs source", "GET", settings.audit_url + "/logs", headers=admin_headers)["data"]
            activity = call("Activity report", "GET", addresses["reports"] + "/reports/activity", headers=admin_headers)
            actions = Counter(row["action"] for row in logs)
            require(activity["total_user_activities"] == len(logs)
                    and activity["login_attempts"] == actions["login_success"] + actions["login_failed"]
                    and activity["failed_login_attempts"] == actions["login_failed"] > 0,
                    "Actual activity totals/login action mapping differs")
            ranking = [{"action": action, "count": count} for action, count in
                       sorted(actions.items(), key=lambda value: (-value[1], value[0]))[:10]]
            require(activity["most_performed_actions"] == ranking, "Actual action ranking differs")
            parse_time = lambda value: datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
            expected_recent = []
            for row in sorted(logs, key=lambda value: (parse_time(value["timestamp"]), value["id"]), reverse=True)[:10]:
                expected_recent.append({field: (row[field].lower() if field == "severity" else
                                               parse_time(row[field]) if field == "timestamp" else row[field])
                                        for field in ("id", "user_id", "action", "timestamp", "severity", "related_service")})
            actual_recent = [row | {"timestamp": parse_time(row["timestamp"])} for row in activity["recent_activities"]]
            require(actual_recent == expected_recent, "Actual recent activity normalization/order differs")
            require({"asset_created", "asset_updated", "threat_created", "unauthorized_access"} <= set(actions),
                    "Required Chris events are absent from native Logs")
            print("PASS activity report reconciles actual native Logs, login actions and UTC recent ordering", flush=True)
        print("PASS partial actual integration: Users, Logs, Assets, Threats and Reports.", flush=True)
        print("PENDING Karim services, three remaining reports, full workflows/outages, and native v1 compliance.", flush=True)
        return 0
    except CheckFailure:
        raise
    except Exception as error:
        raise CheckFailure(f"{phase}: unexpected {type(error).__name__}; details suppressed") from None
    finally:
        for app in native_apps:
            app.extensions["engine"].dispose()
        if scoped_engine is not None:
            scoped_engine.dispose()
        if schema_created:
            require(bool(re.fullmatch(r"chris_test_interop_[0-9a-f]{32}", schema)), "Unsafe cleanup target")
            with root_engine.begin() as connection:
                connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
            print("Owned temporary schema and HTTP servers cleaned up.", flush=True)
        root_engine.dispose()


def main():
    logging.getLogger("werkzeug").setLevel(logging.CRITICAL)
    try:
        return run()
    except ConfigurationFailure as error:
        print(f"CONFIGURATION: {error}", flush=True)
        return 2
    except CheckFailure as error:
        print(f"FAIL: {error}", flush=True)
        return 1
    except Exception as error:
        print(f"FAIL: unexpected {type(error).__name__}; details suppressed", flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
