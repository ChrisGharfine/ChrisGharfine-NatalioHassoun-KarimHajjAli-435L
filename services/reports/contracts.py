from datetime import timezone
from enum import StrEnum
from typing import Annotated

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator

from services.assets.schemas import AssetStatus, AssetType
from services.chris_support.schemas import PositiveId, Severity, ShortText
from services.threats.schemas import ThreatRead


class SourceRecord(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: PositiveId


UserId = Annotated[int, Field(strict=True, gt=0, le=2_147_483_647)]


class UserRecord(SourceRecord):
    id: UserId


class IncidentStatus(StrEnum):
    OPEN = "open"
    UNDER_INVESTIGATION = "under_investigation"
    MITIGATED = "mitigated"
    RESOLVED = "resolved"
    CLOSED = "closed"


class VulnerabilityStatus(StrEnum):
    OPEN = "open"
    UNDER_INVESTIGATION = "under_investigation"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    CLOSED = "closed"


class IncidentRecord(SourceRecord):
    severity: Severity
    status: IncidentStatus


class AssetRecord(SourceRecord):
    asset_type: AssetType
    criticality: Severity
    status: AssetStatus


class VulnerabilityRecord(SourceRecord):
    severity: Severity
    status: VulnerabilityStatus


class AuditSeverity(StrEnum):
    INFORMATION = "information"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class ActivityRecord(SourceRecord):
    user_id: UserId | None
    action: ShortText
    timestamp: AwareDatetime
    severity: AuditSeverity
    related_service: ShortText

    @field_validator("action", "related_service")
    @classmethod
    def nonblank_text(cls, value):
        if not value.strip():
            raise ValueError("Activity text must not be blank")
        return value

    @field_validator("timestamp")
    @classmethod
    def utc_timestamp(cls, value):
        return value.astimezone(timezone.utc)


class ReportThreatRecord(ThreatRead):
    @field_validator("date_added")
    @classmethod
    def utc_timestamp(cls, value):
        return value.astimezone(timezone.utc)


# These exact wire values belong to the providers. They are deliberately mapped
# at the Reports boundary rather than changing Karim's public API vocabulary.
KARIM_SEVERITIES = {
    "Low": "low", "Medium": "medium", "High": "high", "Critical": "critical",
}
INCIDENT_STATES = {
    "Open": "open", "Under Investigation": "under_investigation",
    "Mitigated": "mitigated", "Resolved": "resolved", "Closed": "closed",
}
VULNERABILITY_STATES = {
    "Open": "open", "Under Investigation": "under_investigation",
    "In Progress": "in_progress", "Resolved": "resolved", "Closed": "closed",
}
LOG_SEVERITIES = {
    "Information": "information", "Warning": "warning",
    "Error": "error", "Critical": "critical",
}
PAGINATION_FIELDS = {
    "next", "next_page", "page", "pages", "total_pages", "offset", "limit",
    "cursor", "pagination", "has_more",
}


def source_rows(source: str, payload):
    """Extract only the complete-list envelope specified for this provider."""
    if source in {"users", "audit", "incidents", "vulnerabilities"}:
        if not isinstance(payload, dict) or payload.get("status") != "success":
            raise ValueError("Expected the provider's success envelope")
        if PAGINATION_FIELDS.intersection(payload):
            raise ValueError("Pagination is not part of the v1 complete-list contract")
        key = source if source in {"incidents", "vulnerabilities"} else "data"
        rows = payload.get(key)
    else:
        rows = payload
    if not isinstance(rows, list):
        raise ValueError("Expected the provider's complete array")
    if source in {"incidents", "vulnerabilities"}:
        if type(payload.get("count")) is not int or payload["count"] != len(rows):
            raise ValueError("The complete count must equal the array length")
    return rows


def normalize_record(source: str, row):
    """Normalize consumed fields without accepting an alternate wire contract."""
    if not isinstance(row, dict):
        raise ValueError("Expected an object record")
    item = row.copy()
    if source in {"incidents", "vulnerabilities"}:
        # Indexing is intentional: internal aliases are not alternate inputs.
        item["id"] = item[f"{'incident' if source == 'incidents' else 'vulnerability'}_id"]
        severity_field = "severity" if source == "incidents" else "severity_level"
        item["severity"] = KARIM_SEVERITIES[item[severity_field]]
        states = INCIDENT_STATES if source == "incidents" else VULNERABILITY_STATES
        item["status"] = states[item["status"]]
    elif source == "audit":
        item["severity"] = LOG_SEVERITIES[item["severity"]]
    return item


# Each adapter validates only the fields its report consumes, ignoring unrelated
# upstream fields (including user personal/account data).
SOURCE_CONTRACTS = {
    "users": ("/users", UserRecord),
    "assets": ("/assets", AssetRecord),
    "incidents": ("/incidents", IncidentRecord),
    "threats": ("/threats", ReportThreatRecord),
    "audit": ("/logs", ActivityRecord),
    "vulnerabilities": ("/vulnerabilities", VulnerabilityRecord),
}
