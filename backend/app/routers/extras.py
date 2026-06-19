import secrets

from fastapi import APIRouter, Depends, HTTPException

from app.auth_utils import get_current_user
from app.database import get_db
from app.schemas import ExportData, Favorite, FavoriteCreate, MessageResponse, UserResponse

router = APIRouter(tags=["extras"])


@router.get("/api/favorites", response_model=list[Favorite])
def list_favorites(current_user: UserResponse = Depends(get_current_user)):
    with get_db() as db:
        rows = db.execute(
            "SELECT id, item_type, item_id, created_at FROM favorites WHERE user_id = ? ORDER BY id DESC",
            (current_user.id,),
        ).fetchall()
    return [Favorite(id=r["id"], item_type=r["item_type"], item_id=r["item_id"], created_at=r["created_at"]) for r in rows]


@router.post("/api/favorites", response_model=Favorite)
def add_favorite(payload: FavoriteCreate, current_user: UserResponse = Depends(get_current_user)):
    try:
        with get_db() as db:
            cur = db.execute(
                "INSERT INTO favorites (user_id, item_type, item_id) VALUES (?, ?, ?)",
                (current_user.id, payload.item_type, payload.item_id),
            )
            db.commit()
            row = db.execute("SELECT * FROM favorites WHERE id = ?", (cur.lastrowid,)).fetchone()
        return Favorite(id=row["id"], item_type=row["item_type"], item_id=row["item_id"], created_at=row["created_at"])
    except Exception:
        raise HTTPException(status_code=400, detail="Already favorited")


@router.delete("/api/favorites/{item_type}/{item_id}", response_model=MessageResponse)
def remove_favorite(item_type: str, item_id: str, current_user: UserResponse = Depends(get_current_user)):
    with get_db() as db:
        db.execute(
            "DELETE FROM favorites WHERE user_id = ? AND item_type = ? AND item_id = ?",
            (current_user.id, item_type, item_id),
        )
        db.commit()
    return MessageResponse(message="Removed from favorites")


@router.get("/api/favorites/check/{item_type}/{item_id}")
def check_favorite(item_type: str, item_id: str, current_user: UserResponse = Depends(get_current_user)):
    with get_db() as db:
        row = db.execute(
            "SELECT 1 FROM favorites WHERE user_id = ? AND item_type = ? AND item_id = ?",
            (current_user.id, item_type, item_id),
        ).fetchone()
    return {"favorited": row is not None}


@router.post("/api/plans/{plan_id}/share")
def share_plan(plan_id: int, current_user: UserResponse = Depends(get_current_user)):
    token = secrets.token_urlsafe(16)
    with get_db() as db:
        plan = db.execute(
            "SELECT id FROM saved_plans WHERE id = ? AND user_id = ?",
            (plan_id, current_user.id),
        ).fetchone()
        if not plan:
            raise HTTPException(status_code=404, detail="Plan not found")
        existing = db.execute(
            "SELECT share_token FROM plan_shares WHERE plan_id = ?",
            (plan_id,),
        ).fetchone()
        if existing:
            token = existing["share_token"]
        else:
            db.execute(
                "INSERT INTO plan_shares (plan_id, user_id, share_token) VALUES (?, ?, ?)",
                (plan_id, current_user.id, token),
            )
            db.commit()
    return {"share_token": token, "share_url": f"/share/plan/{token}"}


@router.get("/api/notifications")
def list_notifications(current_user: UserResponse = Depends(get_current_user)):
    with get_db() as db:
        rows = db.execute(
            """SELECT id, type, title, body, read, created_at FROM notifications
               WHERE user_id = ? ORDER BY id DESC LIMIT 50""",
            (current_user.id,),
        ).fetchall()
    return [
        {
            "id": r["id"],
            "type": r["type"],
            "title": r["title"],
            "body": r["body"],
            "read": bool(r["read"]),
            "created_at": r["created_at"],
        }
        for r in rows
    ]


@router.post("/api/notifications/read-all")
def mark_all_read(current_user: UserResponse = Depends(get_current_user)):
    with get_db() as db:
        db.execute("UPDATE notifications SET read = 1 WHERE user_id = ?", (current_user.id,))
        db.commit()
    return {"message": "All marked read"}


@router.get("/api/export", response_model=ExportData)
def export_data(current_user: UserResponse = Depends(get_current_user)):
    with get_db() as db:
        profile = db.execute("SELECT * FROM user_profiles WHERE user_id = ?", (current_user.id,)).fetchone()
        workouts = db.execute(
            "SELECT * FROM workout_logs WHERE user_id = ? ORDER BY id DESC",
            (current_user.id,),
        ).fetchall()
        plans = db.execute(
            "SELECT id, title, plan_type, content, created_at FROM saved_plans WHERE user_id = ?",
            (current_user.id,),
        ).fetchall()
        metrics = db.execute(
            "SELECT * FROM body_metrics WHERE user_id = ? ORDER BY id DESC",
            (current_user.id,),
        ).fetchall()
        goals = db.execute("SELECT * FROM goals WHERE user_id = ?", (current_user.id,)).fetchall()
        badges = db.execute(
            "SELECT badge_id, earned_at FROM user_badges WHERE user_id = ?",
            (current_user.id,),
        ).fetchall()
    return ExportData(
        profile=dict(profile) if profile else None,
        workouts=[dict(w) for w in workouts],
        plans=[dict(p) for p in plans],
        metrics=[dict(m) for m in metrics],
        goals=[dict(g) for g in goals],
        badges=[dict(b) for b in badges],
    )
