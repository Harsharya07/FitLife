from fastapi import APIRouter, HTTPException

from app.database import get_db
from app.schemas import PublicPlan

router = APIRouter(prefix="/api/public", tags=["public"])


@router.get("/plans/{token}", response_model=PublicPlan)
def get_shared_plan(token: str):
    with get_db() as db:
        row = db.execute(
            """SELECT p.title, p.plan_type, p.content, p.created_at
               FROM plan_shares s JOIN saved_plans p ON p.id = s.plan_id
               WHERE s.share_token = ?""",
            (token,),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Shared plan not found")
    return PublicPlan(
        title=row["title"],
        plan_type=row["plan_type"],
        content=row["content"],
        created_at=row["created_at"],
    )
