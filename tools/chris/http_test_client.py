"""Test client that resolves resource paths under the configured owner prefix.

Absolute URLs bypass this convenience, allowing explicit legacy-route 404 tests.
"""
from fastapi.testclient import TestClient as BaseTestClient


class TestClient(BaseTestClient):
    __test__ = False

    def request(self, method, url, *args, **kwargs):
        path = str(url)
        if path.startswith("/") and not path.startswith("/api/"):
            url = self.app.state.settings.api_prefix + path
        return super().request(method, url, *args, **kwargs)
