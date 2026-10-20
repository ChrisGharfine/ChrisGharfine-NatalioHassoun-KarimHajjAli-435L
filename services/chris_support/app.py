from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from .audit import AuditOutbox
from .config import Settings
from .database import make_engine
from .errors import install_error_handlers


def create_app(service_name: str, *, settings: Settings | None = None,
               engine=None, http_client: httpx.Client | None = None) -> FastAPI:
    settings = settings or Settings()
    owned_engine = engine is None
    engine = engine if engine is not None else make_engine(settings.database_url)
    owned_client = http_client is None
    http_client = http_client if http_client is not None else httpx.Client(
        timeout=settings.http_timeout_seconds, follow_redirects=False, trust_env=False,
    )

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        yield
        if owned_client:
            http_client.close()
        if owned_engine:
            engine.dispose()

    app = FastAPI(
        title=f"{service_name.title()} Service - Chris Gharfine", version="1.1.0",
        lifespan=lifespan,
        description="Sprint I service implementing team-integration-v1.0.0 with the coordinated v1.1 named routes and errors.",
        openapi_url=settings.api_prefix + "/openapi.json", docs_url=settings.api_prefix + "/docs",
        redoc_url=settings.api_prefix + "/redoc",
        swagger_ui_oauth2_redirect_url=settings.api_prefix + "/docs/oauth2-redirect",
    )
    app.state.settings = settings
    app.state.service_name = service_name
    app.state.engine = engine
    app.state.session_factory = sessionmaker(bind=engine, expire_on_commit=False)
    app.state.http_client = http_client
    install_error_handlers(app)

    if service_name == "assets":
        from services.assets.routes import internal_router, router
        from services.assets.models import Asset as readiness_model
    elif service_name == "threats":
        from services.threats.routes import router
        from services.threats.models import Threat as readiness_model
    elif service_name == "reports":
        from services.reports.routes import router
        readiness_model = AuditOutbox
    else:
        raise ValueError("Unknown Chris service")
    app.include_router(router, prefix=settings.api_prefix)
    if service_name == "assets":
        app.include_router(internal_router, prefix=settings.api_prefix)

    @app.get(settings.api_prefix + "/health", tags=["operations"])
    def health():
        return {"status": "ok", "service": service_name}

    @app.get(settings.api_prefix + "/ready", tags=["operations"])
    def ready():
        with app.state.session_factory() as session:
            # Require the v1 delivery columns too, not just the pre-v1 table ID.
            session.execute(select(AuditOutbox).limit(0))
            session.execute(select(readiness_model.id).limit(0))
        return {"status": "ready", "service": service_name}

    return app
