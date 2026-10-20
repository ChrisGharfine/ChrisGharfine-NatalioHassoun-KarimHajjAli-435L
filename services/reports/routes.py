from typing import Annotated

from fastapi import APIRouter, Depends, Request

from services.chris_support.auth import Principal, Role, allow

from .client import SourceClient
from .schemas import (
    ActivityReport, AssetReport, IncidentReport, SummaryReport,
    ThreatReport, VulnerabilityReport,
)
from .service import ReportService

router = APIRouter(prefix="/reports", tags=["reports"])


def report_service(
    request: Request,
    actor: Annotated[Principal, Depends(allow(Role.ADMIN, Role.AUDITOR))],
) -> ReportService:
    settings = request.app.state.settings
    return ReportService(SourceClient(settings, request.app.state.http_client, actor.token), settings)


Reports = Annotated[ReportService, Depends(report_service)]


@router.get("/summary", response_model=SummaryReport)
def summary_report(service: Reports):
    return service.summary()


@router.get("/incidents", response_model=IncidentReport)
def incident_report(service: Reports):
    return service.incidents()


@router.get("/assets", response_model=AssetReport)
def asset_report(service: Reports):
    return service.assets()


@router.get("/threats", response_model=ThreatReport)
def threat_report(service: Reports):
    return service.threats()


@router.get("/vulnerabilities", response_model=VulnerabilityReport)
def vulnerability_report(service: Reports):
    return service.vulnerabilities()


@router.get("/activity", response_model=ActivityReport)
def activity_report(service: Reports):
    return service.activity()
