import json
from datetime import datetime

import httpx
from pydantic import ValidationError

from services.chris_support.errors import ApiError
from services.chris_support.service_auth import service_headers

from .contracts import SOURCE_CONTRACTS, normalize_record, source_rows


class SourceClient:
    def __init__(self, settings, client: httpx.Client, token: str):
        self.settings = settings
        self.client = client
        self.token = token

    def fetch(self, source: str):
        path, model = SOURCE_CONTRACTS[source]
        url = getattr(self.settings, f"{source}_url") + path
        headers = {
            "Authorization": f"Bearer {self.token}", "Accept": "application/json",
            **service_headers(self.settings, "reports"),
        }
        try:
            with self.client.stream(
                "GET", url,
                headers=headers,
                timeout=self.settings.http_timeout_seconds, follow_redirects=False,
            ) as response:
                if response.status_code in {401, 403}:
                    raise ApiError(response.status_code, f"{source} service refused report access")
                if response.status_code == 429 or response.status_code >= 500:
                    raise ApiError(503, f"{source} service is unavailable")
                if response.status_code != 200:
                    raise ApiError(502, f"{source} service returned an unexpected status")
                content_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                if content_type != "application/json" and not content_type.endswith("+json"):
                    raise ApiError(502, f"{source} service did not return JSON")
                data = bytearray()
                for chunk in response.iter_bytes():
                    if len(data) + len(chunk) > self.settings.max_upstream_bytes:
                        raise ApiError(502, f"{source} response exceeds the configured size limit")
                    data.extend(chunk)
        except httpx.HTTPError:
            raise ApiError(503, f"{source} service is unavailable") from None
        try:
            payload = source_rows(source, json.loads(data))
            if len(payload) > self.settings.max_upstream_records:
                raise ValueError("Expected a complete array within configured bounds")
            timestamp_field = {"threats": "date_added", "audit": "timestamp"}.get(source)
            if timestamp_field:
                for item in payload:
                    if not isinstance(item, dict) or not isinstance(item.get(timestamp_field), str):
                        raise ValueError("Expected ISO timestamp strings")
                    # Pydantic also accepts epoch-number strings; the wire
                    # contract requires ISO text with an explicit timezone.
                    parsed = datetime.fromisoformat(item[timestamp_field].replace("Z", "+00:00"))
                    if parsed.tzinfo is None or parsed.utcoffset() is None:
                        raise ValueError("Expected timezone-aware timestamps")
            records = [model.model_validate(normalize_record(source, item)) for item in payload]
            if len({item.id for item in records}) != len(records):
                raise ValueError("Duplicate source identifiers")
        except (ValueError, TypeError, KeyError, OverflowError, RecursionError, ValidationError):
            raise ApiError(502, f"{source} service returned invalid report data") from None
        return records
