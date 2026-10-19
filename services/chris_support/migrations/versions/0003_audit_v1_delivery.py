"""Freeze v1 audit payloads and retain permanent delivery failures visibly."""

from alembic import op
import sqlalchemy as sa

revision = "chris_0003"
down_revision = "chris_0002"
branch_labels = None
depends_on = None


def upgrade():
    # Additive only: preserve original events, pending work and stable UUIDs.
    op.add_column("chris_audit_outbox", sa.Column("failed_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("chris_audit_outbox", sa.Column("transport_payload", sa.JSON(), nullable=True))


def downgrade():
    op.drop_column("chris_audit_outbox", "transport_payload")
    op.drop_column("chris_audit_outbox", "failed_at")
