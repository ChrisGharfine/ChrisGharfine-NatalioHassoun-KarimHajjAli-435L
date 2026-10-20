from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .audit import enqueue
from .errors import ApiError


class Repository:
    def __init__(self, session: Session, model):
        self.session = session
        self.model = model

    def get(self, identifier: int):
        record = self.session.get(self.model, identifier)
        if record is None:
            raise ApiError(404, f"{self.model.__name__} not found")
        return record

    def all(self, *conditions):
        return list(self.session.scalars(
            select(self.model).where(*conditions).order_by(self.model.id)
        ))

    def save(self, record, *, actor, service: str, action: str):
        try:
            self.session.flush()
            enqueue(
                self.session, user_id=actor.user_id, service=service,
                action=f"{service}.{action}",
                description=f"{self.model.__name__} {record.id} {action}",
            )
            self.session.commit()
        except IntegrityError as error:
            self.session.rollback()
            sqlstate = getattr(error.orig, "sqlstate", None)
            if sqlstate == "23503" and service == "assets":
                if action == "deleted":
                    raise ApiError(409, "Asset is referenced by another record") from None
                raise ApiError(422, "Asset owner does not exist") from None
            if sqlstate == "23505" and service == "threats":
                raise ApiError(409, "Threat type and value already exist") from None
            raise ApiError(409, "Record conflicts with a database constraint") from None
        return record
