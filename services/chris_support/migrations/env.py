import os

from alembic import context
from sqlalchemy import create_engine

from services.assets.models import Asset  # noqa: F401
from services.threats.models import Threat  # noqa: F401
from services.chris_support.audit import AuditOutbox  # noqa: F401
from services.chris_support.database import Base


def include_object(obj, name, type_, reflected, compare_to):
    if type_ == "table":
        return name in {"assets", "threats", "chris_audit_outbox"}
    return True


def run_migrations():
    # Migrations require only the database setting, not JWT or service credentials.
    url = os.environ.get("CHRIS_DATABASE_URL")
    if not url:
        raise RuntimeError("Set CHRIS_DATABASE_URL before running Chris's migrations")
    supplied_connection = context.config.attributes.get("connection")
    engine = supplied_connection.engine if supplied_connection is not None else create_engine(url, hide_parameters=True)
    if engine.dialect.name != "postgresql":
        raise RuntimeError("Chris's migrations require PostgreSQL")
    options = dict(
        target_metadata=Base.metadata, version_table="chris_alembic_version",
        include_object=include_object, compare_type=True,
    )
    try:
        if context.is_offline_mode():
            context.configure(url=url, literal_binds=True, **options)
            with context.begin_transaction():
                context.run_migrations()
        elif supplied_connection is not None:
            context.configure(connection=supplied_connection, **options)
            with context.begin_transaction():
                context.run_migrations()
        else:
            with engine.connect() as connection:
                context.configure(connection=connection, **options)
                with context.begin_transaction():
                    context.run_migrations()
    finally:
        if supplied_connection is None:
            engine.dispose()


run_migrations()
