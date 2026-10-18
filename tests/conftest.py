"""Real HTTP + PostgreSQL integration fixtures. No application/API mocks.

Each run owns a random schema in an explicitly named *_test database. Only that
schema is removed on teardown. Existing schemas and databases are never dropped.
"""

import os
import secrets
import threading
import uuid
from pathlib import Path

import pytest
import requests
from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from werkzeug.security import generate_password_hash
from werkzeug.serving import make_server

from security_backend.app import create_app
from security_backend.__main__ import migrate
from security_backend.models import User
from security_backend.shared.constants import ADMIN, EMPLOYEE

PASSWORD = "Integration-Test-435!"
PREFIX = "/api/natalio-hassoun"


class API:
    def __init__(self, apps, urls, admin_id, admin_token):
        self.apps, self.urls = apps, urls
        self.admin_id, self.admin_token = admin_id, admin_token

    def request(self, service, method, path, token=None, **kwargs):
        headers = kwargs.pop("headers", {})
        if token:
            headers["Authorization"] = "Bearer " + token
        return requests.request(method, self.urls[service] + PREFIX + path,
                                headers=headers, timeout=15, **kwargs)

    def new_user(self, role=EMPLOYEE):
        suffix = uuid.uuid4().hex[:12]
        body = {"full_name": "Integration Test User", "username": "test." + suffix,
                "email": suffix + "@example.edu", "password": PASSWORD,
                "department": "Security", "role": role}
        response = self.request("users", "POST", "/users/register", self.admin_token, json=body)
        assert response.status_code == 201, response.text
        user = response.json()["data"]
        login = self.request("users", "POST", "/users/login", json={"identifier": user["username"], "password": PASSWORD})
        assert login.status_code == 200, login.text
        return user, login.json()["data"]["access_token"]

    def playbook(self):
        response = self.request("playbooks", "POST", "/playbooks", self.admin_token,
                                json={"name": "Phishing response", "description": "Investigate a reported message",
                                      "incident_category": "Phishing", "severity": "High"})
        assert response.status_code == 201, response.text
        return response.json()["data"]


@pytest.fixture(scope="session")
def api():
    load_dotenv()
    raw = os.getenv("TEST_DATABASE_URL")
    if not raw:
        pytest.fail("Set TEST_DATABASE_URL to a dedicated PostgreSQL database ending in _test.")
    url = make_url(raw)
    if not url.database or not url.database.endswith("_test") or url.drivername != "postgresql+psycopg":
        pytest.fail("Refusing tests: database must end in _test and use postgresql+psycopg.")
    schema = "student1_test_" + uuid.uuid4().hex
    admin_engine = create_engine(url, connect_args={"connect_timeout": 5})
    with admin_engine.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    isolated_url = url.update_query_dict({"options": f"-csearch_path={schema}"})
    config = {"DATABASE_URL": isolated_url.render_as_string(hide_password=False),
              "JWT_SECRET_KEY": secrets.token_hex(32),
              "SERVICE_TOKENS": {name: secrets.token_hex(32) for name in ("users", "logs", "playbooks")},
              "API_PREFIX": PREFIX, "SERVICE_TIMEOUT": 0.6}
    apps, servers, threads, urls = {}, {}, {}, {}
    try:
        for name in ("users", "logs", "playbooks"):
            apps[name] = create_app(name, config)
            servers[name] = make_server("127.0.0.1", 0, apps[name], threaded=True)
            urls[name] = f"http://127.0.0.1:{servers[name].server_port}"
        for app in apps.values():
            app.config.update(USERS_URL=urls["users"], LOGS_URL=urls["logs"])
        with apps["users"].app_context():
            migrate(apps["users"])
            migrate(apps["users"])  # Prove repeatability before creating data.
        with apps["users"].extensions["session_factory"]() as session:
            admin = User(full_name="Integration Administrator", username="integration.admin",
                         email="integration.admin@example.edu", department="Security", role=ADMIN,
                         account_status="active", password_hash=generate_password_hash(PASSWORD, method="scrypt"))
            session.add(admin)
            session.commit()
            admin_id = admin.id
        for name, server in servers.items():
            threads[name] = threading.Thread(target=server.serve_forever, daemon=True)
            threads[name].start()
        response = requests.post(urls["users"] + PREFIX + "/users/login",
                                 json={"identifier": "integration.admin", "password": PASSWORD}, timeout=15)
        assert response.status_code == 200, response.text
        yield API(apps, urls, admin_id, response.json()["data"]["access_token"])
    finally:
        for name, server in servers.items():
            if name in threads:
                server.shutdown()
                threads[name].join(timeout=5)
            server.server_close()
        for app in apps.values():
            app.extensions["engine"].dispose()
        with admin_engine.begin() as connection:
            # schema is generated above, never accepted from external input.
            connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin_engine.dispose()
