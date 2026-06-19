from datetime import datetime, timedelta

from fastapi import APIRouter, Depends

from app.auth_utils import require_admin
from app.database import get_db
from app.schemas import AdminAnalytics, ContactRecord, UserResponse

router = APIRouter(prefix="/api/admin", tags=["admin"])


@router.get("/analytics", response_model=AdminAnalytics)
def analytics(_: UserResponse = Depends(require_admin)):
    week_ago = (datetime.now() - timedelta(days=7)).isoformat()
    with get_db() as db:
        total_users = db.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
        total_workouts = db.execute("SELECT COUNT(*) AS c FROM workout_logs").fetchone()["c"]
        total_plans = db.execute("SELECT COUNT(*) AS c FROM saved_plans").fetchone()["c"]
        total_ai = db.execute(
            "SELECT COUNT(*) AS c FROM chat_messages WHERE role = 'user'"
        ).fetchone()["c"]
        signups = db.execute(
            """SELECT COUNT(*) AS c FROM users
               WHERE created_at >= datetime('now', '-7 days') OR created_at IS NULL"""
        ).fetchone()["c"]
    return AdminAnalytics(
        total_users=total_users,
        total_workouts=total_workouts,
        total_plans=total_plans,
        total_ai_chats=total_ai,
        signups_last_7_days=signups,
    )


@router.get("/contacts", response_model=list[ContactRecord])
def list_contacts(_: UserResponse = Depends(require_admin)):
    with get_db() as db:
        rows = db.execute(
            "SELECT id, name, email, message, created_at FROM contacts ORDER BY id DESC LIMIT 200"
        ).fetchall()
    return [
        ContactRecord(
            id=r["id"],
            name=r["name"],
            email=r["email"],
            message=r["message"],
            created_at=r["created_at"],
        )
        for r in rows
    ]
