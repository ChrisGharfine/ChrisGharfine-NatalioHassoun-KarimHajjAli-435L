from services.chris_support.repository import Repository

from .models import Threat


class ThreatService:
    def __init__(self, session):
        self.repository = Repository(session, Threat)
        self.session = session

    def create(self, data, actor):
        record = Threat(**data.model_dump(mode="json"))
        self.session.add(record)
        return self.repository.save(record, actor=actor, service="threats", action="created")

    def update(self, identifier, data, actor):
        record = self.repository.get(identifier)
        for key, value in data.model_dump(mode="json", exclude_unset=True).items():
            setattr(record, key, value)
        return self.repository.save(record, actor=actor, service="threats", action="updated")

    def delete(self, identifier, actor):
        record = self.repository.get(identifier)
        self.session.delete(record)
        self.repository.save(record, actor=actor, service="threats", action="deleted")

    def search(self, filters):
        conditions = []
        for key, value in filters.model_dump(mode="json", exclude_none=True).items():
            column = getattr(Threat, key)
            if key in {"source", "threat_value"}:
                conditions.append(column.icontains(value, autoescape=True))
            else:
                conditions.append(column == value)
        return self.repository.all(*conditions)
