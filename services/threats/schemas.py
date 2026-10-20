import ipaddress
import re
from enum import StrEnum
from typing import Annotated

import idna
from pydantic import AwareDatetime, ConfigDict, StringConstraints, model_validator

from services.chris_support.schemas import (
    Description, InputModel, PositiveId, Severity, ShortText, UpdateModel,
)


class ThreatType(StrEnum):
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    FILE_HASH = "file_hash"
    MALWARE_SIGNATURE = "malware_signature"
    OTHER = "other"


ThreatValue = Annotated[str, StringConstraints(min_length=1, max_length=512)]


def normalize_indicator(kind: ThreatType, value: str) -> str:
    value = value.strip()
    if kind == ThreatType.IP_ADDRESS:
        if "%" in value:
            raise ValueError("Scoped IP addresses are not supported")
        return str(ipaddress.ip_address(value))
    if kind == ThreatType.DOMAIN:
        if value.endswith(".."):
            raise ValueError("Invalid domain indicator")
        try:
            value = idna.encode(value.removesuffix("."), uts46=True, std3_rules=True).decode().lower()
        except idna.IDNAError:
            raise ValueError("Invalid domain indicator") from None
        labels = value.split(".")
        if len(value) > 253 or len(labels) < 2 or labels[-1].isdigit():
            raise ValueError("A fully qualified domain is required")
        return value
    if kind == ThreatType.FILE_HASH:
        if len(value) not in {32, 40, 64, 128} or not re.fullmatch(r"[0-9a-fA-F]+", value):
            raise ValueError("Use an MD5, SHA-1, SHA-256, or SHA-512 hexadecimal digest")
        return value.lower()
    return value


class ThreatCreate(InputModel):
    threat_type: ThreatType
    threat_value: ThreatValue
    description: Description
    severity: Severity
    source: ShortText

    @model_validator(mode="after")
    def validate_indicator(self):
        self.threat_value = normalize_indicator(self.threat_type, self.threat_value)
        return self


class ThreatUpdate(UpdateModel):
    description: Description | None = None
    severity: Severity | None = None
    source: ShortText | None = None

    @model_validator(mode="after")
    def nonempty_update(self):
        return self.check_update(self)


class ThreatRead(ThreatCreate):
    model_config = ConfigDict(from_attributes=True, extra="ignore")
    id: PositiveId
    date_added: AwareDatetime


class ThreatFilters(InputModel):
    threat_type: ThreatType | None = None
    threat_value: ThreatValue | None = None
    severity: Severity | None = None
    source: ShortText | None = None

    @model_validator(mode="after")
    def require_criterion(self):
        if not any(value is not None for value in self.model_dump().values()):
            raise ValueError("Provide at least one threat search criterion")
        if self.threat_type is not None and self.threat_value is not None:
            self.threat_value = normalize_indicator(self.threat_type, self.threat_value)
        return self
