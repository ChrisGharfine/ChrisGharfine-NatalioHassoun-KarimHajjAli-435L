from enum import StrEnum

from pydantic import ConfigDict, IPvAnyAddress, field_validator, model_validator

from services.chris_support.schemas import InputModel, PositiveId, Severity, ShortText, UpdateModel


class AssetType(StrEnum):
    SERVER = "server"
    WORKSTATION = "workstation"
    DATABASE = "database"
    APPLICATION = "application"
    NETWORK_DEVICE = "network_device"
    CLOUD_RESOURCE = "cloud_resource"


class AssetStatus(StrEnum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    UNDER_MAINTENANCE = "under_maintenance"


class IpValidation(InputModel):
    @field_validator("*", mode="before")
    @classmethod
    def require_text_ip(cls, value, info):
        if info.field_name == "ip_address" and value is not None and not isinstance(value, str):
            # ORM response validation also receives standard IP address objects.
            if not hasattr(value, "packed"):
                raise ValueError("IP addresses must use textual IPv4 or IPv6 notation")
        return value

    @field_validator("*", mode="after")
    @classmethod
    def reject_scoped_ip(cls, value):
        if getattr(value, "scope_id", None) is not None:
            raise ValueError("Scoped IP addresses are not supported")
        return value


class AssetCreate(IpValidation):
    name: ShortText
    asset_type: AssetType
    ip_address: IPvAnyAddress
    department: ShortText
    owner_id: PositiveId
    criticality: Severity
    operating_system: ShortText | None = None
    location: ShortText | None = None
    status: AssetStatus = AssetStatus.ACTIVE


class AssetUpdate(UpdateModel, IpValidation):
    name: ShortText | None = None
    asset_type: AssetType | None = None
    ip_address: IPvAnyAddress | None = None
    department: ShortText | None = None
    owner_id: PositiveId | None = None
    criticality: Severity | None = None
    operating_system: ShortText | None = None
    location: ShortText | None = None
    status: AssetStatus | None = None

    @model_validator(mode="after")
    def nonempty_update(self):
        return self.check_update(self, {"operating_system", "location"})


class AssetRead(AssetCreate):
    model_config = ConfigDict(from_attributes=True, extra="ignore")
    id: PositiveId


class AssetFilters(IpValidation):
    name: ShortText | None = None
    asset_type: AssetType | None = None
    ip_address: IPvAnyAddress | None = None
    department: ShortText | None = None
    criticality: Severity | None = None
    status: AssetStatus | None = None

    @model_validator(mode="after")
    def require_criterion(self):
        if not any(value is not None for value in self.model_dump().values()):
            raise ValueError("Provide at least one asset search criterion")
        return self
