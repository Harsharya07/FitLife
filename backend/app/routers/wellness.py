from datetime import date, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException

from app.auth_utils import get_current_user
from app.database import get_db
from app.schemas import (
    BodyMetric,
    BodyMetricCreate,
    CalendarDay,
    Goal,
    GoalCreate,
    GoalUpdate,
    MessageResponse,
    UserResponse,
    WaterLogCreate,
    WaterToday,
)
from app.services.achievements import BADGES, check_goal_badge, check_water_badge

router = APIRouter(prefix="/api/wellness", tags=["wellness"])


@router.get("/metrics", response_model=list[BodyMetric])
def list_metrics(limit: int = 50, current_user: UserResponse = Depends(get_current_user)):
    with get_db() as db:
        rows = db.execute(
            """SELECT id, weight_kg, body_fat_pct, waist_cm, notes, logged_at
               FROM body_metrics WHERE user_id = ? ORDER BY id DESC LIMIT ?""",
            (current_user.id, limit),
        ).fetchall()
    return [
        BodyMetric(
            id=r["id"],
            weight_kg=r["weight_kg"],
            body_fat_pct=r["body_fat_pct"],
            waist_cm=r["waist_cm"],
            notes=r["notes"],
            logged_at=r["logged_at"],
        )
        for r in rows
    ]


@router.post("/metrics", response_model=BodyMetric)
def log_metric(payload: BodyMetricCreate, current_user: UserResponse = Depends(get_current_user)):
    data = payload.model_dump()
    with get_db() as db:
        cur = db.execute(
            """INSERT INTO body_metrics (user_id, weight_kg, body_fat_pct, waist_cm, notes)
               VALUES (?, ?, ?, ?, ?)""",
            (current_user.id, data["weight_kg"], data["body_fat_pct"], data["waist_cm"], data["notes"]),
        )
        if data["weight_kg"]:
            db.execute(
                """UPDATE user_profiles SET weight_kg = ?, updated_at = CURRENT_TIMESTAMP
                   WHERE user_id = ?""",
                (data["weight_kg"], current_user.id),
            )
        db.commit()
        row = db.execute("SELECT * FROM body_metrics WHERE id = ?", (cur.lastrowid,)).fetchone()
    return BodyMetric(
        id=row["id"],
        weight_kg=row["weight_kg"],
        body_fat_pct=row["body_fat_pct"],
        waist_cm=row["waist_cm"],
        notes=row["notes"],
        logged_at=row["logged_at"],
    )


@router.post("/water", response_model=WaterToday)
def log_water(payload: WaterLogCreate, current_user: UserResponse = Depends(get_current_user)):
    with get_db() as db:
        db.execute(
            "INSERT INTO water_logs (user_id, glasses) VALUES (?, ?)",
            (current_user.id, payload.glasses),
        )
        db.commit()
        today = date.today().isoformat()
        total = db.execute(
            "SELECT COALESCE(SUM(glasses), 0) AS g FROM water_logs WHERE user_id = ? AND DATE(logged_at) = ?",
            (current_user.id, today),
        ).fetchone()["g"]
    check_water_badge(current_user.id, total)
    return WaterToday(glasses=total)


@router.get("/water/today", response_model=WaterToday)
def water_today(current_user: UserResponse = Depends(get_current_user)):
    today = date.today().isoformat()
    with get_db() as db:
        total = db.execute(
            "SELECT COALESCE(SUM(glasses), 0) AS g FROM water_logs WHERE user_id = ? AND DATE(logged_at) = ?",
            (current_user.id, today),
        ).fetchone()["g"]
    return WaterToday(glasses=total)


@router.get("/goals", response_model=list[Goal])
def list_goals(current_user: UserResponse = Depends(get_current_user)):
    with get_db() as db:
        rows = db.execute(
            """SELECT id, title, goal_type, target_value, current_value, unit, deadline, completed, created_at
               FROM goals WHERE user_id = ? ORDER BY completed ASC, id DESC""",
            (current_user.id,),
        ).fetchall()
    return [
        Goal(
            id=r["id"],
            title=r["title"],
            goal_type=r["goal_type"],
            target_value=r["target_value"],
            current_value=r["current_value"],
            unit=r["unit"],
            deadline=r["deadline"],
            completed=bool(r["completed"]),
            created_at=r["created_at"],
        )
        for r in rows
    ]


@router.post("/goals", response_model=Goal)
def create_goal(payload: GoalCreate, current_user: UserResponse = Depends(get_current_user)):
    with get_db() as db:
        cur = db.execute(
            """INSERT INTO goals (user_id, title, goal_type, target_value, unit, deadline)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                current_user.id,
                payload.title,
                payload.goal_type,
                payload.target_value,
                payload.unit,
                payload.deadline,
            ),
        )
        db.commit()
        row = db.execute("SELECT * FROM goals WHERE id = ?", (cur.lastrowid,)).fetchone()
    check_goal_badge(current_user.id)
    return Goal(
        id=row["id"],
        title=row["title"],
        goal_type=row["goal_type"],
        target_value=row["target_value"],
        current_value=row["current_value"],
        unit=row["unit"],
        deadline=row["deadline"],
        completed=bool(row["completed"]),
        created_at=row["created_at"],
    )


@router.patch("/goals/{goal_id}", response_model=Goal)
def update_goal(goal_id: int, payload: GoalUpdate, current_user: UserResponse = Depends(get_current_user)):
    with get_db() as db:
        row = db.execute("SELECT * FROM goals WHERE id = ? AND user_id = ?", (goal_id, current_user.id)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Goal not found")
        current = payload.current_value if payload.current_value is not None else row["current_value"]
        completed = payload.completed if payload.completed is not None else (current >= row["target_value"])
        db.execute(
            "UPDATE goals SET current_value = ?, completed = ? WHERE id = ?",
            (current, 1 if completed else 0, goal_id),
        )
        if completed and not row["completed"]:
            db.execute(
                """INSERT INTO notifications (user_id, type, title, body)
                   VALUES (?, 'goal', ?, ?)""",
                (current_user.id, f"Goal achieved: {row['title']}", "Congratulations on hitting your target!"),
            )
        db.commit()
        row = db.execute("SELECT * FROM goals WHERE id = ?", (goal_id,)).fetchone()
    return Goal(
        id=row["id"],
        title=row["title"],
        goal_type=row["goal_type"],
        target_value=row["target_value"],
        current_value=row["current_value"],
        unit=row["unit"],
        deadline=row["deadline"],
        completed=bool(row["completed"]),
        created_at=row["created_at"],
    )


@router.delete("/goals/{goal_id}", response_model=MessageResponse)
def delete_goal(goal_id: int, current_user: UserResponse = Depends(get_current_user)):
    with get_db() as db:
        cur = db.execute("DELETE FROM goals WHERE id = ? AND user_id = ?", (goal_id, current_user.id))
        db.commit()
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Goal not found")
    return MessageResponse(message="Goal deleted")


@router.get("/badges", response_model=list[dict])
def list_badges(current_user: UserResponse = Depends(get_current_user)):
    with get_db() as db:
        earned = {
            r["badge_id"]: r["earned_at"]
            for r in db.execute(
                "SELECT badge_id, earned_at FROM user_badges WHERE user_id = ?",
                (current_user.id,),
            ).fetchall()
        }
    return [
        {
            "badge_id": bid,
            "title": meta["title"],
            "description": meta["desc"],
            "earned": bid in earned,
            "earned_at": earned.get(bid),
        }
        for bid, meta in BADGES.items()
    ]


@router.get("/calendar", response_model=list[CalendarDay])
def calendar(days: int = 30, current_user: UserResponse = Depends(get_current_user)):
    start = (date.today() - timedelta(days=days - 1)).isoformat()
    with get_db() as db:
        workout_rows = db.execute(
            """SELECT DATE(logged_at) AS d, COUNT(*) AS c FROM workout_logs
               WHERE user_id = ? AND DATE(logged_at) >= ? GROUP BY DATE(logged_at)""",
            (current_user.id, start),
        ).fetchall()
        water_rows = db.execute(
            """SELECT DATE(logged_at) AS d, SUM(glasses) AS g FROM water_logs
               WHERE user_id = ? AND DATE(logged_at) >= ? GROUP BY DATE(logged_at)""",
            (current_user.id, start),
        ).fetchall()
    w_map = {r["d"]: r["c"] for r in workout_rows}
    water_map = {r["d"]: r["g"] for r in water_rows}
    result = []
    for i in range(days):
        d = (date.today() - timedelta(days=days - 1 - i)).isoformat()
        result.append(CalendarDay(date=d, workouts=w_map.get(d, 0), water_glasses=water_map.get(d, 0)))
    return result
