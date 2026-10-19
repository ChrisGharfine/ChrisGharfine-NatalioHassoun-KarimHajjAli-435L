from typing import Annotated

from fastapi import APIRouter, Depends, Path, Query, Request, Response
from sqlalchemy.orm import Session

from services.chris_support.auth import Principal, Role, allow
from services.chris_support.database import get_session
from services.chris_support.identity import validate_asset_owner
from services.chris_support.service_auth import ServicePrincipal, allow_services

from .schemas import AssetCreate, AssetFilters, AssetRead, AssetReference, AssetReferenceResponse, AssetUpdate
from .service import AssetService

router = APIRouter(prefix="/assets", tags=["assets"])
internal_router = APIRouter(prefix="/internal/assets", tags=["internal-assets"])
Db = Annotated[Session, Depends(get_session)]
Id = Annotated[int, Path(gt=0, le=9_223_372_036_854_775_807)]
Admin = Annotated[Principal, Depends(allow(Role.ADMIN))]
Reader = Annotated[Principal, Depends(allow(Role.ADMIN, Role.AUDITOR))]
Searcher = Annotated[Principal, Depends(allow(Role.ADMIN, Role.ANALYST, Role.AUDITOR))]
ReferenceCaller = Annotated[ServicePrincipal, Depends(allow_services("incidents", "vulnerabilities"))]


def asset_service(request: Request, session: Db) -> AssetService:
    return AssetService(session, owner_validator=lambda owner_id: validate_asset_owner(
        request.app.state.http_client, request.app.state.settings, owner_id,
    ))


AssetBusiness = Annotated[AssetService, Depends(asset_service)]


@router.post("", response_model=AssetRead, status_code=201)
def create_asset(data: AssetCreate, actor: Admin, service: AssetBusiness):
    return service.create(data, actor)


@router.get("", response_model=list[AssetRead])
def list_assets(actor: Reader, session: Db):
    return AssetService(session).repository.all()


@router.get("/search", response_model=list[AssetRead])
def search_assets(filters: Annotated[AssetFilters, Query()], actor: Searcher, session: Db):
    return AssetService(session).search(filters)


@router.get("/{id}", response_model=AssetRead)
def get_asset(id: Id, actor: Searcher, session: Db):
    return AssetService(session).repository.get(id)


@router.put("/{id}", response_model=AssetRead)
def update_asset(id: Id, data: AssetUpdate, actor: Admin, service: AssetBusiness):
    return service.update(id, data, actor)


@router.delete("/{id}", status_code=204)
def delete_asset(id: Id, actor: Admin, session: Db):
    AssetService(session).delete(id, actor)
    return Response(status_code=204)


@internal_router.get("/{id}", response_model=AssetReferenceResponse)
def get_asset_reference(id: Id, caller: ReferenceCaller, session: Db):
    record = AssetService(session).repository.get(id)
    return AssetReferenceResponse(data=AssetReference.model_validate(record))
