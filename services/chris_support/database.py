from datetime import datetime, timezone

from fastapi import Request
from sqlalchemy import BigInteger, Column, MetaData, Table, create_engine
from sqlalchemy.orm import DeclarativeBase


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention={
        "ix": "ix_%(table_name)s_%(column_0_name)s",
        "uq": "uq_%(table_name)s_%(column_0_name)s",
        "ck": "ck_%(table_name)s_%(constraint_name)s",
        "fk": "fk_%(table_name)s_%(column_0_name)s",
        "pk": "pk_%(table_name)s",
    })


# Metadata reference only. Production migrations never create Natalio's Users table.
external_users = Table(
    "users", Base.metadata, Column("id", BigInteger, primary_key=True),
    info={"external": True},
)


def make_engine(database_url: str):
    return create_engine(database_url, pool_pre_ping=True, hide_parameters=True)


def get_session(request: Request):
    with request.app.state.session_factory() as session:
        yield session
