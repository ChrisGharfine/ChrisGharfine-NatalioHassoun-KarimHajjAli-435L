"""Assets with a real foreign key to the team-owned users.id."""

from alembic import context, op
import sqlalchemy as sa

revision = "chris_0002"
down_revision = "chris_0001"
branch_labels = None
depends_on = None


def upgrade():
    if not context.is_offline_mode():
        inspector = sa.inspect(op.get_bind())
        if not inspector.has_table("users"):
            raise RuntimeError("Natalio's users table must be migrated before Chris's assets table")
        columns = {column["name"]: column for column in inspector.get_columns("users")}
        if "id" not in columns or not isinstance(columns["id"]["type"], sa.Integer):
            raise RuntimeError("The approved users.id contract requires an integer primary key")
        if inspector.get_pk_constraint("users")["constrained_columns"] != ["id"]:
            raise RuntimeError("The approved users.id contract requires a single-column primary key")
    op.create_table(
        "assets",
        sa.Column("id", sa.BigInteger(), sa.Identity(), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("asset_type", sa.String(30), nullable=False),
        sa.Column("ip_address", sa.String(45), nullable=False),
        sa.Column("operating_system", sa.String(200), nullable=True),
        sa.Column("department", sa.String(200), nullable=False),
        sa.Column("owner_id", sa.BigInteger(), nullable=False),
        sa.Column("location", sa.String(200), nullable=True),
        sa.Column("criticality", sa.String(20), nullable=False),
        sa.Column("status", sa.String(30), nullable=False),
        sa.ForeignKeyConstraint(["owner_id"], ["users.id"], name="fk_assets_owner_id", ondelete="RESTRICT"),
        sa.CheckConstraint("length(trim(name)) > 0", name=op.f("ck_assets_name_not_blank")),
        sa.CheckConstraint("length(trim(department)) > 0", name=op.f("ck_assets_department_not_blank")),
        sa.CheckConstraint("owner_id > 0", name=op.f("ck_assets_positive_owner")),
        sa.CheckConstraint("asset_type IN ('server','workstation','database','application','network_device','cloud_resource')",
                           name=op.f("ck_assets_valid_type")),
        sa.CheckConstraint("criticality IN ('low','medium','high','critical')", name=op.f("ck_assets_valid_criticality")),
        sa.CheckConstraint("status IN ('active','inactive','under_maintenance')", name=op.f("ck_assets_valid_status")),
    )
    for column in ("name", "asset_type", "ip_address", "department", "owner_id", "criticality"):
        op.create_index(f"ix_assets_{column}", "assets", [column])


def downgrade():
    op.drop_table("assets")
