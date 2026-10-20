"""Unit fault injection only; real cross-owner execution is tested separately."""
import copy
import os
import secrets
import time
import unittest
from unittest.mock import Mock, patch
import uuid

import jwt
from flask import Flask

from security.jwt_auth import TokenError, verify_access_token
from security.guard import error
from outbox.receipts import valid_receipt
from app_factory import create_app
from flask import Blueprint


class StrictContracts(unittest.TestCase):
    def setUp(self):
        self.key = secrets.token_hex(32)
        self.environment = patch.dict(os.environ, {"KARIM_JWT_VERIFICATION_KEY": self.key})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        now = int(time.time())
        self.claims = {"sub": "1", "iat": now-1, "exp": now+300, "iss": "security-sprint1-users",
                       "aud": "security-sprint1-services", "type": "access"}

    def test_valid_access_token(self):
        self.assertEqual(verify_access_token(jwt.encode(self.claims, self.key, algorithm="HS256"))["sub_id"], 1)

    def test_invalid_numeric_dates_subject_and_claims(self):
        cases = [{"iat": "1"}, {"iat": True}, {"exp": str(int(time.time())+300)},
                 {"iat": float("nan")}, {"exp": float("inf")}, {"sub": "+1"}, {"sub": " 1"},
                 {"sub": "01"}, {"sub": "0"}, {"sub": "2147483648"}, {"type": "refresh"},
                 {"iss": "wrong"}, {"aud": "wrong"}, {"nbf": int(time.time())+999}]
        for changed in cases:
            with self.subTest(changed=list(changed)):
                token = jwt.encode({**self.claims, **changed}, self.key, algorithm="HS256")
                with self.assertRaises(TokenError): verify_access_token(token)
        for name in ("sub", "iat", "exp", "iss", "aud", "type"):
            with self.subTest(missing=name):
                claims = self.claims.copy(); claims.pop(name)
                with self.assertRaises(TokenError): verify_access_token(jwt.encode(claims, self.key, algorithm="HS256"))

    def test_wrong_algorithm(self):
        for algorithm, key in (("HS384", self.key), ("none", "")):
            with self.subTest(algorithm=algorithm), self.assertRaises(TokenError):
                verify_access_token(jwt.encode(self.claims, key, algorithm=algorithm))

    def test_new_duplicate_and_deleted_receipts(self):
        event_id = str(uuid.uuid4())
        for resource, key in (("log", "id"), ("notification", "notification_id")):
            for status, duplicate, result in ((201, False, {key: 1}), (200, True, {key: 1}), (200, True, None)):
                with self.subTest(resource=resource, status=status, deleted=result is None):
                    body = {"status": "success", "data": {"event_id": event_id, "duplicate": duplicate, resource: result}}
                    self.assertTrue(valid_receipt(body, status, event_id, resource, key))

    def test_incomplete_and_wrong_receipts_stay_pending(self):
        event_id = str(uuid.uuid4())
        for resource, key in (("log", "id"), ("notification", "notification_id")):
            data = {"event_id": event_id, "duplicate": False, resource: {key: 1}}
            bad = [{"event_id": event_id}, {**data, "event_id": str(uuid.uuid4())}, {**data, "duplicate": "false"},
                   {**data, "duplicate": True}, {**data, resource: None}, {**data, resource: {key: True}},
                   {**data, resource: {key: 0}}]
            for variant in bad:
                with self.subTest(resource=resource, fields=list(variant)):
                    self.assertFalse(valid_receipt({"status": "success", "data": variant}, 201, event_id, resource, key))
            self.assertFalse(valid_receipt({"status": "success", "data": data}, 202, event_id, resource, key))

    def test_denials_are_durable_and_not_duplicated(self):
        app = Flask("denial-unit", static_folder=None)
        app.config["KARIM_SERVICE_NAME"] = "notifications"
        with app.test_request_context("/api/karim-hajj-ali/notifications/1"):
            with patch("outbox.audit_outbox.queue_audit_event") as enqueue:
                response, status = error("Forbidden ownership", 403)
                self.assertEqual(status, 403)
                self.assertEqual(response.get_json()["code"], "FORBIDDEN")
                error("Forbidden ownership", 403)
                self.assertEqual(enqueue.call_count, 1)
        with app.test_request_context("/api/karim-hajj-ali/notifications/1"):
            with patch("outbox.audit_outbox.queue_audit_event", side_effect=RuntimeError("private detail")):
                response, status = error("Forbidden ownership", 403)
                self.assertEqual(status, 503)
                self.assertEqual(response.get_json()["code"], "AUDIT_STORAGE_UNAVAILABLE")
                self.assertNotIn("private detail", response.get_data(as_text=True))

    def test_non_object_json_is_rejected_safely(self):
        blueprint = Blueprint("json-unit", __name__)
        @blueprint.post("/notifications")
        def receive():
            return {"status": "success"}
        app = create_app("notifications", blueprint)
        with app.test_client() as client:
            for payload in ([1], "text", True, 1, None):
                import json
                with self.subTest(payload=payload):
                    result = client.post("/api/karim-hajj-ali/notifications", data=json.dumps(payload), content_type="application/json")
                    self.assertEqual(result.status_code, 400)
                    self.assertEqual(result.get_json()["code"], "INVALID_INPUT")
            self.assertEqual(client.post("/api/karim-hajj-ali/notifications", json={}).status_code, 200)
            self.assertEqual(client.get("/health").status_code, 404)


if __name__ == "__main__":
    unittest.main()
