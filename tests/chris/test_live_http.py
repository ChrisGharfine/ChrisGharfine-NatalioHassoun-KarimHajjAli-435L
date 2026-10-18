"""Real localhost HTTP between Chris's services; isolated external Users fixture."""

import socket
import threading
import time
from contextlib import contextmanager

import httpx
import uvicorn

from services.chris_support.app import create_app


@contextmanager
def running_server(app):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(128)
    url = f"http://127.0.0.1:{listener.getsockname()[1]}"
    server = uvicorn.Server(uvicorn.Config(app, log_level="error", access_log=False))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 10
        with httpx.Client(timeout=1, trust_env=False) as client:
            while time.monotonic() < deadline:
                try:
                    if client.get(url + "/ready").status_code == 200:
                        break
                except httpx.HTTPError:
                    pass
                time.sleep(0.05)
            else:
                raise AssertionError("Local test service did not become ready")
        yield url
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        listener.close()
        assert not thread.is_alive(), "Local test service did not stop"


def test_live_asset_and_threat_reports_reflect_database_changes(db_engine, settings, auth_headers, asset_body, threat_body):
    assets = create_app("assets", settings=settings, engine=db_engine)
    threats = create_app("threats", settings=settings, engine=db_engine)
    with running_server(assets) as asset_url, running_server(threats) as threat_url:
        report_settings = settings.model_copy(update={"assets_url": asset_url, "threats_url": threat_url})
        reports = create_app("reports", settings=report_settings, engine=db_engine)
        with running_server(reports) as report_url, httpx.Client(timeout=5, trust_env=False) as client:
            headers = auth_headers()
            asset = client.post(asset_url + "/assets", json=asset_body, headers=headers)
            threat = client.post(threat_url + "/threats", json=threat_body, headers=headers)
            assert asset.status_code == threat.status_code == 201
            asset_id, threat_id = asset.json()["id"], threat.json()["id"]
            asset_report = client.get(report_url + "/reports/assets", headers=headers).json()
            assert asset_report["total_assets"] == 1 and asset_report["critical_assets"] == 0
            threat_report = client.get(report_url + "/reports/threats", headers=headers).json()
            assert threat_report["total_threats"] == 1 and threat_report["threats_by_severity"]["critical"] == 1
            assert client.put(asset_url + f"/assets/{asset_id}", json={"criticality": "critical"}, headers=headers).status_code == 200
            assert client.put(threat_url + f"/threats/{threat_id}", json={"severity": "low"}, headers=headers).status_code == 200
            assert client.get(report_url + "/reports/assets", headers=headers).json()["critical_assets"] == 1
            updated = client.get(report_url + "/reports/threats", headers=headers).json()
            assert updated["threats_by_severity"]["critical"] == 0 and updated["threats_by_severity"]["low"] == 1
