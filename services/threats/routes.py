from typing import Annotated

from fastapi import APIRouter, Depends, Path, Query, Response
from sqlalchemy.orm import Session

from services.chris_support.auth import Principal, Role, allow
from services.chris_support.database import get_session

from .schemas import ThreatCreate, ThreatFilters, ThreatRead, ThreatUpdate
from .service import ThreatService

router = APIRouter(prefix="/threats", tags=["threats"])
Db = Annotated[Session, Depends(get_session)]
Id = Annotated[int, Path(gt=0, le=9_223_372_036_854_775_807)]
Admin = Annotated[Principal, Depends(allow(Role.ADMIN))]
Reader = Annotated[Principal, Depends(allow(Role.ADMIN, Role.ANALYST, Role.AUDITOR))]
Searcher = Annotated[Principal, Depends(allow(Role.ADMIN, Role.ANALYST))]


@router.post("", response_model=ThreatRead, status_code=201)
def create_threat(data: ThreatCreate, actor: Admin, session: Db):
    return ThreatService(session).create(data, actor)


@router.get("", response_model=list[ThreatRead])
def list_threats(actor: Reader, session: Db):
    return ThreatService(session).repository.all()


@router.get("/search", response_model=list[ThreatRead])
def search_threats(filters: Annotated[ThreatFilters, Query()], actor: Searcher, session: Db):
    return ThreatService(session).search(filters)


@router.get("/{id}", response_model=ThreatRead)
def get_threat(id: Id, actor: Reader, session: Db):
    return ThreatService(session).repository.get(id)


@router.put("/{id}", response_model=ThreatRead)
def update_threat(id: Id, data: ThreatUpdate, actor: Admin, session: Db):
    return ThreatService(session).update(id, data, actor)


@router.delete("/{id}", status_code=204)
def delete_threat(id: Id, actor: Admin, session: Db):
    ThreatService(session).delete(id, actor)
    return Response(status_code=204)
