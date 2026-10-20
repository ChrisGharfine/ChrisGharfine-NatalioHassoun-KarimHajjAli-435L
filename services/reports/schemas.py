from pydantic import BaseModel, Field

from services.chris_support.schemas import Severity
from services.threats.schemas import ThreatRead, ThreatType
from services.assets.schemas import AssetType

from .contracts import ActivityRecord, IncidentStatus, VulnerabilityStatus


class SummaryReport(BaseModel):
    users: int = Field(ge=0)
    assets: int = Field(ge=0)
    open_incidents: int = Field(ge=0)
    critical_threats: int = Field(ge=0)


class IncidentReport(BaseModel):
    total_incidents: int
    incidents_by_severity: dict[Severity, int]
    incidents_by_status: dict[IncidentStatus, int]


class AssetReport(BaseModel):
    total_assets: int
    critical_assets: int
    assets_by_type: dict[AssetType, int]


class ThreatReport(BaseModel):
    total_threats: int
    threats_by_severity: dict[Severity, int]
    threats_by_type: dict[ThreatType, int]
    recent_threats: list[ThreatRead]


class VulnerabilityReport(BaseModel):
    total_vulnerabilities: int
    vulnerabilities_by_severity: dict[Severity, int]
    vulnerabilities_by_status: dict[VulnerabilityStatus, int]
    critical_vulnerabilities: int


class ActionCount(BaseModel):
    action: str
    count: int


class ActivityReport(BaseModel):
    total_user_activities: int
    login_attempts: int
    failed_login_attempts: int
    most_performed_actions: list[ActionCount]
    recent_activities: list[ActivityRecord]
