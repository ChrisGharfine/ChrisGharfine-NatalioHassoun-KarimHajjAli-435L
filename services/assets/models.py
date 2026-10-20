from sqlalchemy import BigInteger, CheckConstraint, ForeignKey, Identity, String
from sqlalchemy.orm import Mapped, mapped_column

from services.chris_support.database import Base


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (
        CheckConstraint("length(trim(name)) > 0", name="name_not_blank"),
        CheckConstraint("length(trim(department)) > 0", name="department_not_blank"),
        CheckConstraint("owner_id > 0", name="positive_owner"),
        CheckConstraint("asset_type IN ('server','workstation','database','application',"
                        "'network_device','cloud_resource')", name="valid_type"),
        CheckConstraint("criticality IN ('low','medium','high','critical')", name="valid_criticality"),
        CheckConstraint("status IN ('active','inactive','under_maintenance')", name="valid_status"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    name: Mapped[str] = mapped_column(String(200), index=True)
    asset_type: Mapped[str] = mapped_column(String(30), index=True)
    ip_address: Mapped[str] = mapped_column(String(45), index=True)
    operating_system: Mapped[str | None] = mapped_column(String(200))
    department: Mapped[str] = mapped_column(String(200), index=True)
    owner_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("users.id", name="fk_assets_owner_id", ondelete="RESTRICT"), index=True,
    )
    location: Mapped[str | None] = mapped_column(String(200))
    criticality: Mapped[str] = mapped_column(String(20), index=True)
    status: Mapped[str] = mapped_column(String(30), default="active")
