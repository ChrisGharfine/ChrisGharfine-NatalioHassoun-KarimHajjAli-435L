"""Ordered response actions with immutable execution snapshots."""

from flask import Blueprint, g
from sqlalchemy import select

from .app import success
from .models import ActionHistory, Playbook, ResponseAction
from .shared import validation as v
from .shared.audit import record_event
from .shared.auth import protected
from .shared.clients import call_users
from .shared.constants import ACTION_STATUSES, ADMIN, ANALYST, AUDITOR, SEVERITIES
from .shared.errors import APIError, missing

bp = Blueprint("playbooks", __name__)


def find_playbook(playbook_id):
    playbook = g.db.scalar(select(Playbook).where(Playbook.id == playbook_id, Playbook.deleted_at.is_(None)))
    if not playbook:
        missing("Playbook")
    return playbook


def validate_assignee(user_id):
    v.positive_id(user_id, "assigned_user_id", nullable=True)
    if user_id is not None:
        identity = call_users(f"/internal/users/{user_id}")
        if identity["deleted"] or identity["account_status"] != "active":
            v.invalid("assigned_user_id must refer to an active, non-deleted user.")


@bp.post("/playbooks")
@protected(ADMIN)
def create_playbook():
    fields = ("name", "description", "incident_category", "severity")
    data = v.body(fields, fields)
    playbook = Playbook(name=v.text(data["name"], "name"),
                        description=v.text(data["description"], "description", 4000),
                        incident_category=v.text(data["incident_category"], "incident_category", 100),
                        severity=v.choice(data["severity"], "severity", SEVERITIES),
                        created_by=g.actor["id"])
    g.db.add(playbook)
    g.db.flush()
    record_event(g.db, "playbook_created", f"Created playbook {playbook.id}.", g.actor["id"])
    return success(playbook.public(), 201, commit=True)


@bp.get("/playbooks")
@protected(ADMIN, ANALYST, AUDITOR)
def list_playbooks():
    return success([row.public() for row in g.db.scalars(
        select(Playbook).where(Playbook.deleted_at.is_(None)).order_by(Playbook.id))])


@bp.get("/playbooks/<int:playbook_id>")
@protected(ADMIN, ANALYST, AUDITOR)
def retrieve_playbook(playbook_id):
    result = find_playbook(playbook_id).public()
    actions = g.db.scalars(select(ResponseAction).where(ResponseAction.playbook_id == playbook_id)
                           .order_by(ResponseAction.step_number)).all()
    result["actions"] = []
    for action in actions:
        data = action.public()
        data["history"] = [row.public() for row in g.db.scalars(select(ActionHistory)
                           .where(ActionHistory.action_id == action.id).order_by(ActionHistory.id))]
        result["actions"].append(data)
    return success(result)


@bp.post("/playbooks/<int:playbook_id>/actions")
@protected(ADMIN, ANALYST)
def add_action(playbook_id):
    find_playbook(playbook_id)
    data = v.body(("description", "step_number", "assigned_user_id"), ("description", "step_number"))
    assigned_user_id = data.get("assigned_user_id")
    validate_assignee(assigned_user_id)
    action = ResponseAction(playbook_id=playbook_id, description=v.text(data["description"], "description", 4000),
                            step_number=v.positive_id(data["step_number"], "step_number"),
                            assigned_user_id=assigned_user_id, status="Pending")
    g.db.add(action)
    g.db.flush()
    g.db.add(ActionHistory(action_id=action.id, changed_by=g.actor["id"], previous=None, current=action.public()))
    record_event(g.db, "response_action_added", f"Added action {action.id} to playbook {playbook_id}.", g.actor["id"])
    return success(action.public(), 201, commit=True)


@bp.put("/actions/<int:action_id>/status")
@protected(ADMIN, ANALYST)
def update_action(action_id):
    data = v.body(("status", "assigned_user_id", "completion_date"))
    action = g.db.scalar(select(ResponseAction).where(ResponseAction.id == action_id).with_for_update())
    if not action:
        missing("Response action")
    find_playbook(action.playbook_id)
    previous = action.public()
    if "assigned_user_id" in data:
        validate_assignee(data["assigned_user_id"])
        action.assigned_user_id = data["assigned_user_id"]
    if "status" in data:
        action.status = v.choice(data["status"], "status", ACTION_STATUSES)
    # Policy choice: all transitions among the three statuses are allowed; every change is recorded.
    # Completing supplies a server timestamp by default. Reopening clears completion_date.
    if action.status == "Completed":
        if "completion_date" in data:
            supplied = v.timestamp(data["completion_date"], "completion_date")
            if supplied > v.utcnow():
                v.invalid("completion_date cannot be in the future.")
            action.completion_date = supplied
        elif previous["status"] != "Completed":
            action.completion_date = v.utcnow()
    else:
        if data.get("completion_date") is not None:
            v.invalid("completion_date is only allowed for a Completed action.")
        action.completion_date = None
    g.db.add(ActionHistory(action_id=action.id, changed_by=g.actor["id"],
                           previous=previous, current=action.public()))
    record_event(g.db, "response_action_updated", f"Updated action {action.id}.", g.actor["id"])
    return success(action.public(), commit=True)


@bp.delete("/playbooks/<int:playbook_id>")
@protected(ADMIN)
def delete_playbook(playbook_id):
    playbook = find_playbook(playbook_id)
    playbook.deleted_at = v.utcnow()
    record_event(g.db, "playbook_deleted", f"Deleted playbook {playbook_id}; retained action history.", g.actor["id"])
    return success({"id": playbook_id, "deleted": True, "deletion_mode": "soft"}, commit=True)
