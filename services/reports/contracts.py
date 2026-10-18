from enum import StrEnum

from pydantic import AwareDatetime, BaseModel, ConfigDict

from services.assets.schemas import AssetStatus, AssetType
from services.chris_support.schemas import PositiveId, Severity, ShortText
from services.threats.schemas import ThreatRead


class SourceRecord(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: PositiveId


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
    user_id: PositiveId | None
    action: ShortText
    timestamp: AwareDatetime
    severity: AuditSeverity
    related_service: ShortText


# Each adapter validates only the fields its report consumes, ignoring unrelated
# upstream fields (including user personal/account data).
SOURCE_CONTRACTS = {
    "users": ("/users", SourceRecord),
    "assets": ("/assets", AssetRecord),
    "incidents": ("/incidents", IncidentRecord),
    "threats": ("/threats", ThreatRead),
    "audit": ("/logs", ActivityRecord),
    "vulnerabilities": ("/vulnerabilities", VulnerabilityRecord),
}
