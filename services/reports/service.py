from collections import Counter

from services.assets.schemas import AssetType
from services.chris_support.schemas import Severity
from services.threats.schemas import ThreatType

from .contracts import IncidentStatus, VulnerabilityStatus


def grouped(records, field, enumeration):
    counts = Counter(getattr(record, field) for record in records)
    return {value.value: counts[value] for value in enumeration}


class ReportService:
    def __init__(self, source_client, settings):
        self.sources = source_client
        self.settings = settings

    def summary(self):
        users = self.sources.fetch("users")
        assets = self.sources.fetch("assets")
        incidents = self.sources.fetch("incidents")
        threats = self.sources.fetch("threats")
        return {
            "users": len(users), "assets": len(assets),
            "open_incidents": sum(item.status == IncidentStatus.OPEN for item in incidents),
            "critical_threats": sum(item.severity == Severity.CRITICAL for item in threats),
        }

    def incidents(self):
        records = self.sources.fetch("incidents")
        return {
            "total_incidents": len(records),
            "incidents_by_severity": grouped(records, "severity", Severity),
            "incidents_by_status": grouped(records, "status", IncidentStatus),
        }

    def assets(self):
        records = self.sources.fetch("assets")
        return {
            "total_assets": len(records),
            "critical_assets": sum(item.criticality == Severity.CRITICAL for item in records),
            "assets_by_type": grouped(records, "asset_type", AssetType),
        }

    def threats(self):
        records = self.sources.fetch("threats")
        recent = sorted(records, key=lambda item: (item.date_added, item.id), reverse=True)
        return {
            "total_threats": len(records),
            "threats_by_severity": grouped(records, "severity", Severity),
            "threats_by_type": grouped(records, "threat_type", ThreatType),
            "recent_threats": recent[:self.settings.recent_limit],
        }

    def vulnerabilities(self):
        records = self.sources.fetch("vulnerabilities")
        return {
            "total_vulnerabilities": len(records),
            "vulnerabilities_by_severity": grouped(records, "severity", Severity),
            "vulnerabilities_by_status": grouped(records, "status", VulnerabilityStatus),
            "critical_vulnerabilities": sum(item.severity == Severity.CRITICAL for item in records),
        }

    def activity(self):
        records = self.sources.fetch("audit")
        actions = Counter(item.action for item in records)
        ranked = sorted(actions.items(), key=lambda item: (-item[1], item[0]))
        recent = sorted(records, key=lambda item: (item.timestamp, item.id), reverse=True)
        return {
            "total_user_activities": len(records),
            "login_attempts": actions[self.settings.login_success_action]
                              + actions[self.settings.login_failure_action],
            "failed_login_attempts": actions[self.settings.login_failure_action],
            "most_performed_actions": [
                {"action": action, "count": count}
                for action, count in ranked[:self.settings.recent_limit]
            ],
            "recent_activities": recent[:self.settings.recent_limit],
        }
