import re
from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


PositiveId = Annotated[int, Field(strict=True, gt=0, le=9_223_372_036_854_775_807)]
ShortText = Annotated[str, StringConstraints(min_length=1, max_length=200)]
Description = Annotated[str, StringConstraints(min_length=1, max_length=5000)]


class InputModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, validate_default=True)

    @field_validator("*", mode="before")
    @classmethod
    def reject_control_characters(cls, value):
        if isinstance(value, str) and re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", value):
            raise ValueError("Control characters are not allowed")
        return value


class UpdateModel(InputModel):
    @classmethod
    def check_update(cls, model, nullable: set[str] = frozenset()):
        if not model.model_fields_set:
            raise ValueError("Provide at least one field to update")
        for field in model.model_fields_set - nullable:
            if getattr(model, field) is None:
                raise ValueError(f"{field} cannot be null")
        return model
