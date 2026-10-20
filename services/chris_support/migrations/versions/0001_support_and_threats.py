"""Chris-owned audit outbox and threats, independent of external tables."""

from alembic import op
import sqlalchemy as sa

revision = "chris_0001"
down_revision = None
branch_labels = ("chris",)
depends_on = None


def upgrade():
    op.create_table(
        "chris_audit_outbox",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("user_id", sa.BigInteger(), nullable=True),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("related_service", sa.String(30), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.String(100), nullable=True),
        sa.CheckConstraint("attempts >= 0", name=op.f("ck_chris_audit_outbox_attempts_nonnegative")),
    )
    op.create_index("ix_chris_outbox_pending", "chris_audit_outbox", ["delivered_at", "next_attempt_at"])
    op.create_table(
        "threats",
        sa.Column("id", sa.BigInteger(), sa.Identity(), primary_key=True),
        sa.Column("threat_type", sa.String(30), nullable=False),
        sa.Column("threat_value", sa.String(512), nullable=False),
        sa.Column("description", sa.String(5000), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("source", sa.String(200), nullable=False),
        sa.Column("date_added", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("threat_type", "threat_value", name="uq_threats_type_value"),
        sa.CheckConstraint("threat_type IN ('ip_address','domain','file_hash','malware_signature','other')",
                           name=op.f("ck_threats_valid_type")),
        sa.CheckConstraint("severity IN ('low','medium','high','critical')", name=op.f("ck_threats_valid_severity")),
        sa.CheckConstraint("length(trim(threat_value)) > 0", name=op.f("ck_threats_value_not_blank")),
        sa.CheckConstraint("length(trim(description)) > 0", name=op.f("ck_threats_description_not_blank")),
        sa.CheckConstraint("length(trim(source)) > 0", name=op.f("ck_threats_source_not_blank")),
    )
    for column in ("threat_type", "severity", "source"):
        op.create_index(f"ix_threats_{column}", "threats", [column])


def downgrade():
    op.drop_table("threats")
    op.drop_table("chris_audit_outbox")
