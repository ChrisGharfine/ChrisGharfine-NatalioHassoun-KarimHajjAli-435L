"""Offline tests of the checker itself; these do not exercise team services."""

import base64
from copy import deepcopy
from email.message import Message
import io
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError

from tools.chris import check_team_integration as check


def source_examples():
    return {
        "users": {"status": "success", "data": [{"id": 1}, {"id": 2}]},
        "assets": [{"id": 7, "asset_type": "server", "criticality": "critical", "status": "active"}],
        "incidents": {"status": "success", "count": 2, "incidents": [
            {"incident_id": 8, "severity": "Critical", "status": "Open"},
            {"incident_id": 9, "severity": "Low", "status": "Closed"},
        ]},
        "threats": [
            {"id": 10, "threat_type": "ip_address", "threat_value": "192.0.2.1",
             "description": "Offline unit fixture", "severity": "critical", "source": "fixture",
             "date_added": "2026-10-19T07:00:00Z"},
            {"id": 11, "threat_type": "domain", "threat_value": "example.test",
             "description": "Offline unit fixture", "severity": "high", "source": "fixture",
             "date_added": "2026-10-19T07:00:00.001Z"},
        ],
        "logs": {"status": "success", "data": [
            {"id": 20, "user_id": 1, "action": "login_success", "timestamp": "2026-10-19T07:01:00Z",
             "severity": "Information", "related_service": "users"},
            {"id": 21, "user_id": None, "action": "login_failed", "timestamp": "2026-10-19T07:02:00Z",
             "severity": "Warning", "related_service": "users"},
            {"id": 22, "user_id": None, "action": "login_failed", "timestamp": "2026-10-19T07:02:00Z",
             "severity": "Warning", "related_service": "users"},
        ]},
        "vulnerabilities": {"status": "success", "count": 2, "vulnerabilities": [
            {"vulnerability_id": 30, "severity_level": "High", "status": "Open"},
            {"vulnerability_id": 31, "severity_level": "Critical", "status": "In Progress"},
        ]},
    }


def report_examples():
    sources = source_examples()
    # Values are written independently from the calculator, using the contract.
    activity = [deepcopy(sources["logs"]["data"][i]) for i in (2, 1, 0)]
    for row in activity:
        row["severity"] = "information" if row["severity"] == "Information" else "warning"
    return {
        "summary": {"users": 2, "assets": 1, "open_incidents": 1, "critical_threats": 1},
        "incidents": {"total_incidents": 2,
                      "incidents_by_severity": {"low": 1, "medium": 0, "high": 0, "critical": 1},
                      "incidents_by_status": {"open": 1, "under_investigation": 0, "mitigated": 0, "resolved": 0, "closed": 1}},
        "assets": {"total_assets": 1, "critical_assets": 1,
                   "assets_by_type": {"server": 1, "workstation": 0, "database": 0, "application": 0, "network_device": 0, "cloud_resource": 0}},
        "threats": {"total_threats": 2,
                    "threats_by_severity": {"low": 0, "medium": 0, "high": 1, "critical": 1},
                    "threats_by_type": {"ip_address": 1, "domain": 1, "file_hash": 0, "malware_signature": 0, "other": 0},
                    "recent_threats": list(reversed(deepcopy(sources["threats"])))},
        "vulnerabilities": {"total_vulnerabilities": 2, "critical_vulnerabilities": 1,
                            "vulnerabilities_by_severity": {"low": 0, "medium": 0, "high": 1, "critical": 1},
                            "vulnerabilities_by_status": {"open": 1, "under_investigation": 0, "in_progress": 1, "resolved": 0, "closed": 0}},
        "activity": {"total_user_activities": 3, "login_attempts": 3, "failed_login_attempts": 2,
                     "most_performed_actions": [{"action": "login_failed", "count": 2}, {"action": "login_success", "count": 1}],
                     "recent_activities": activity},
    }


class FixtureAPI:
    def __init__(self):
        self.sources = source_examples()
        self.reports = report_examples()
        self.calls = []
        self.identity = {"status": "success", "data": {"id": 1, "role": "security_administrator", "account_status": "active"}}
        self.change_after = False

    def request(self, service, path, *, method="GET", protected=True):
        self.calls.append((service, path, method, protected))
        if path in {"/ready", "/health"}:
            if service in check.NATALIO:
                return {"status": "success", "data": {"service": service}}
            return {"status": "ready" if service in check.CHRIS else "ok", "service": service}
        if path == "/internal/identity/verify":
            return deepcopy(self.identity)
        if service == "reports":
            return deepcopy(self.reports[path.rsplit("/", 1)[1]])
        value = deepcopy(self.sources[service])
        if self.change_after and service == "users" and sum(c[0:2] == ("users", "/users") for c in self.calls) > 1:
            value["data"].append({"id": 3})
        return value


class SourceAndReportTests(unittest.TestCase):
    def test_all_six_realistic_wire_shapes_and_report_values(self):
        normalized = {key: check.normalize_source(key, body) for key, body in source_examples().items()}
        actual = check.expected_reports(normalized)
        expected = check.canonical_report(report_examples())
        self.assertTrue(check.strict_equal(actual, expected))

    def test_complete_offline_scenario_uses_all_services_and_reports(self):
        api = FixtureAPI()
        check.run_checks(api, 1, lambda _: None)
        self.assertEqual(len(api.calls), 28)
        self.assertEqual(sum(c[0] == "reports" and c[1].startswith("/reports/") for c in api.calls), 6)
        self.assertTrue(all(not c[3] for c in api.calls[:9]))

    def test_wrong_report_and_boolean_count_fail(self):
        for bad_value in (0, True, 2.0):
            with self.subTest(value=bad_value):
                api = FixtureAPI()
                api.reports["summary"]["users"] = bad_value
                with self.assertRaisesRegex(check.CheckError, "summary"):
                    check.run_checks(api, 1, lambda _: None)

    def test_source_changes_fail_final_verification(self):
        api = FixtureAPI()
        api.change_after = True
        with self.assertRaisesRegex(check.CheckError, "Source data changed"):
            check.run_checks(api, 1, lambda _: None)

    def test_current_identity_must_match_and_be_active_admin(self):
        for field, value in (("id", 2), ("id", True), ("role", "auditor"), ("account_status", "inactive")):
            with self.subTest(field=field, value=value):
                api = FixtureAPI()
                api.identity["data"][field] = value
                with self.assertRaisesRegex(check.CheckError, "same active administrator"):
                    check.run_checks(api, 1, lambda _: None)

    def test_envelopes_pagination_counts_and_duplicate_ids_are_checked(self):
        bad_cases = [
            ("users", [{"id": 1}]),
            ("users", {"status": "error", "data": []}),
            ("users", {"status": "success", "data": [{"id": 1}], "next": "/users?page=2"}),
            ("assets", {"data": []}),
            ("incidents", {"status": "success", "count": 99, "incidents": []}),
            ("vulnerabilities", {"status": "success", "count": False, "vulnerabilities": []}),
            ("users", {"status": "success", "data": [{"id": 1}, {"id": 1}]}),
            ("users", {"status": "success", "data": [{"id": True}]}),
        ]
        for source, body in bad_cases:
            with self.subTest(source=source, body=body):
                with self.assertRaises(check.CheckError):
                    check.normalize_source(source, body)

    def test_unknown_enums_and_missing_fields_fail(self):
        for field, value in (("severity", "critical"), ("status", "Unknown"), ("incident_id", None)):
            with self.subTest(field=field):
                body = source_examples()["incidents"]
                body["incidents"][0][field] = value
                with self.assertRaises(check.CheckError):
                    check.normalize_source("incidents", body)

    def test_nullable_actor_is_required_and_validated(self):
        for body in ({"id": 1}, {"id": 1, "user_id": False}):
            with self.subTest(body=body):
                with self.assertRaises(check.CheckError):
                    check.normalize_source("logs", {"status": "success", "data": [body]})

    def test_naive_dates_fail_and_equivalent_offsets_match(self):
        with self.assertRaises(check.CheckError):
            check.utc_string("2026-10-19T10:00:00")
        self.assertEqual(check.utc_string("2026-10-19T10:00:00+03:00"), "2026-10-19T07:00:00Z")
        api = FixtureAPI()
        api.reports["activity"]["recent_activities"][0]["timestamp"] = "2026-10-19T10:02:00+03:00"
        check.run_checks(api, 1, lambda _: None)

    def test_recent_order_uses_actual_time_then_id_and_limits_ten(self):
        rows = [{"id": 1, "timestamp": "2026-10-19T00:00:00Z"},
                {"id": 2, "timestamp": "2026-10-19T00:00:00.001Z"}]
        self.assertEqual([r["id"] for r in check.recent(rows, "timestamp")], [2, 1])
        rows = [{"id": i, "timestamp": "2026-10-19T00:00:00Z"} for i in range(1, 13)]
        self.assertEqual([r["id"] for r in check.recent(rows, "timestamp")], list(range(12, 2, -1)))

    def test_empty_sources_have_zero_reports(self):
        bodies = {"users": {"status": "success", "data": []}, "assets": [],
                  "incidents": {"status": "success", "count": 0, "incidents": []},
                  "threats": [], "logs": {"status": "success", "data": []},
                  "vulnerabilities": {"status": "success", "count": 0, "vulnerabilities": []}}
        reports = check.expected_reports({key: check.normalize_source(key, value) for key, value in bodies.items()})
        self.assertEqual(reports["summary"], {"users": 0, "assets": 0, "open_incidents": 0, "critical_threats": 0})
        self.assertEqual(reports["activity"]["most_performed_actions"], [])

    def test_record_bounds_fail_instead_of_truncating(self):
        with patch.object(check, "MAX_RECORDS", 1):
            with self.assertRaisesRegex(check.CheckError, "record bound"):
                check.normalize_source("users", source_examples()["users"])


class ConfigurationAndHTTPTests(unittest.TestCase):
    def configuration(self):
        payload = base64.urlsafe_b64encode(b'{"sub":"1"}').decode().rstrip("=")
        # Deliberately unsigned fixture, only for parsing/configuration tests.
        return {"TEAM_ADMIN_TOKEN": "fixture." + payload + ".fixture", "TEAM_REPORTS_SERVICE_KEY": "k" * 32}

    def test_default_ports_prefixes_and_url_override(self):
        env = self.configuration()
        urls, _, _, subject = check.load_configuration(env)
        self.assertEqual(subject, 1)
        self.assertEqual(urls["logs"], "http://127.0.0.1:8005/api/natalio-hassoun")
        self.assertEqual(urls["notifications"], "http://127.0.0.1:8008")
        env["TEAM_USERS_URL"] = "http://users:8001/api/natalio-hassoun/"
        self.assertEqual(check.load_configuration(env)[0]["users"], "http://users:8001/api/natalio-hassoun")

    def test_invalid_configuration_has_no_secret_values_in_errors(self):
        env = self.configuration()
        for field, value in (("TEAM_ADMIN_TOKEN", "SECRET_INVALID_TOKEN"),
                             ("TEAM_REPORTS_SERVICE_KEY", "SHORT_SECRET"),
                             ("TEAM_USERS_URL", "http://name:PRIVATE_PASSWORD@localhost"),
                             ("TEAM_USERS_URL", "http://localhost?token=PRIVATE_TOKEN"),
                             ("TEAM_USERS_URL", "file:///PRIVATE_PATH")):
            with self.subTest(field=field, value=value):
                bad = {**env, field: value}
                with self.assertRaises(check.CheckError) as caught:
                    check.load_configuration(bad)
                self.assertNotIn(value, str(caught.exception))

    def test_missing_configuration_exits_two_without_network(self):
        with patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(check.main({}), 2)
        self.assertIn("CONFIGURATION", output.getvalue())

    def test_http_headers_prefix_timeout_and_no_body_output(self):
        urls, token, key, _ = check.load_configuration(self.configuration())
        api = check.LiveAPI(urls, token, key)
        headers = Message()
        headers["Content-Type"] = "application/json"
        response = unittest.mock.MagicMock()
        response.__enter__.return_value = response
        response.status, response.headers, response.read.return_value = 200, headers, b'{"status":"success"}'
        api.opener = unittest.mock.Mock()
        api.opener.open.return_value = response
        self.assertEqual(api.request("users", "/internal/identity/verify", method="POST"), {"status": "success"})
        request = api.opener.open.call_args.args[0]
        self.assertEqual(request.full_url, urls["users"] + "/internal/identity/verify")
        self.assertEqual(request.get_header("Authorization"), "Bearer " + token)
        self.assertEqual(request.get_header("X-service-name"), "reports")
        self.assertEqual(api.opener.open.call_args.kwargs["timeout"], 5)
        self.assertIsNone(check.NoRedirects().redirect_request(None, None, 302, "", {}, "http://other"))
        api.request("users", "/health", protected=False)
        self.assertIsNone(api.opener.open.call_args.args[0].get_header("Authorization"))

    def test_http_failure_is_sanitized(self):
        urls, token, key, _ = check.load_configuration(self.configuration())
        api = check.LiveAPI(urls, token, key)
        api.opener = unittest.mock.Mock()
        errors = [HTTPError("http://example", 401, "PRIVATE_REASON", {}, io.BytesIO(b"PRIVATE_BODY")),
                  URLError("PRIVATE_CONNECTION_DETAILS")]
        for error in errors:
            with self.subTest(error=type(error).__name__):
                api.opener.open.side_effect = error
                with self.assertRaises(check.CheckError) as caught:
                    api.request("users", "/users")
                self.assertNotIn("PRIVATE", str(caught.exception))

    def test_bad_http_type_json_and_size_are_rejected(self):
        urls, token, key, _ = check.load_configuration(self.configuration())
        for content_type, raw, bound in (("text/html", b"PRIVATE_HTML", 100),
                                         ("application/json", b"PRIVATE_INVALID_JSON", 100),
                                         ("application/json", b"x" * 9, 8)):
            with self.subTest(content_type=content_type, size=len(raw)):
                api = check.LiveAPI(urls, token, key)
                response = unittest.mock.MagicMock()
                response.__enter__.return_value = response
                response.status = 200
                response.headers = Message()
                response.headers["Content-Type"] = content_type
                response.read.return_value = raw
                api.opener = unittest.mock.Mock()
                api.opener.open.return_value = response
                with patch.object(check, "MAX_BYTES", bound):
                    with self.assertRaises(check.CheckError) as caught:
                        api.request("users", "/users")
                self.assertNotIn("PRIVATE", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
