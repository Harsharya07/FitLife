from fastapi import APIRouter, Depends, HTTPException

from app.auth_utils import get_current_user
from app.database import get_db
from app.schemas import MessageResponse, SavedPlan, SavedPlanCreate, SavedPlanUpdate, UserResponse

router = APIRouter(prefix="/api/plans", tags=["plans"])


def _row_to_plan(row) -> SavedPlan:
    return SavedPlan(
        id=row["id"],
        title=row["title"],
        plan_type=row["plan_type"],
        content=row["content"],
        created_at=row["created_at"],
    )


@router.get("", response_model=list[SavedPlan])
def list_plans(
    plan_type: str | None = None,
    current_user: UserResponse = Depends(get_current_user),
):
    with get_db() as db:
        if plan_type:
            rows = db.execute(
                """SELECT id, title, plan_type, content, created_at FROM saved_plans
                   WHERE user_id = ? AND plan_type = ? ORDER BY id DESC""",
                (current_user.id, plan_type),
            ).fetchall()
        else:
            rows = db.execute(
                """SELECT id, title, plan_type, content, created_at FROM saved_plans
                   WHERE user_id = ? ORDER BY id DESC""",
                (current_user.id,),
            ).fetchall()
    return [_row_to_plan(r) for r in rows]


@router.get("/{plan_id}", response_model=SavedPlan)
def get_plan(plan_id: int, current_user: UserResponse = Depends(get_current_user)):
    with get_db() as db:
        row = db.execute(
            """SELECT id, title, plan_type, content, created_at FROM saved_plans
               WHERE id = ? AND user_id = ?""",
            (plan_id, current_user.id),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Plan not found")
    return _row_to_plan(row)


@router.post("", response_model=SavedPlan)
def create_plan(payload: SavedPlanCreate, current_user: UserResponse = Depends(get_current_user)):
    with get_db() as db:
        cur = db.execute(
            """INSERT INTO saved_plans (user_id, title, plan_type, content)
               VALUES (?, ?, ?, ?)""",
            (current_user.id, payload.title, payload.plan_type, payload.content),
        )
        db.commit()
        plan_id = cur.lastrowid
        row = db.execute(
            "SELECT id, title, plan_type, content, created_at FROM saved_plans WHERE id = ?",
            (plan_id,),
        ).fetchone()
    return _row_to_plan(row)


@router.patch("/{plan_id}", response_model=SavedPlan)
def update_plan(
    plan_id: int,
    payload: SavedPlanUpdate,
    current_user: UserResponse = Depends(get_current_user),
):
    with get_db() as db:
        cur = db.execute(
            "UPDATE saved_plans SET title = ? WHERE id = ? AND user_id = ?",
            (payload.title, plan_id, current_user.id),
        )
        db.commit()
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Plan not found")
        row = db.execute(
            "SELECT id, title, plan_type, content, created_at FROM saved_plans WHERE id = ?",
            (plan_id,),
        ).fetchone()
    return _row_to_plan(row)


@router.delete("/{plan_id}", response_model=MessageResponse)
def delete_plan(plan_id: int, current_user: UserResponse = Depends(get_current_user)):
    with get_db() as db:
        cur = db.execute(
            "DELETE FROM saved_plans WHERE id = ? AND user_id = ?",
            (plan_id, current_user.id),
        )
        db.commit()
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Plan not found")
    return MessageResponse(message="Plan deleted")
