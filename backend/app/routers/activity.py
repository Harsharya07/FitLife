from datetime import date, datetime, timedelta

from fastapi import APIRouter, Depends, Query

from app.auth_utils import get_current_user
from app.data.articles import ARTICLES
from app.data.blogs import BLOGS
from app.data.exercises import EXERCISE_CATEGORIES
from app.data.recipes import RECIPES
from app.database import get_db
from app.schemas import (
    ActivityFeedItem,
    DashboardStats,
    ExercisePR,
    MonthlyActivity,
    UserResponse,
    WeeklyActivity,
    WorkoutLog,
    WorkoutLogCreate,
)

from app.services.achievements import check_workout_badges

router = APIRouter(prefix="/api/activity", tags=["activity"])


def _row_to_log(row) -> WorkoutLog:
    return WorkoutLog(
        id=row["id"],
        exercise_id=row["exercise_id"],
        exercise_name=row["exercise_name"],
        sets=row["sets"],
        reps=row["reps"],
        weight_kg=row["weight_kg"],
        duration_min=row["duration_min"],
        notes=row["notes"],
        logged_at=row["logged_at"],
    )


def _compute_streak(log_dates: list[str]) -> int:
    if not log_dates:
        return 0

    unique_days = sorted({d[:10] for d in log_dates}, reverse=True)
    today = date.today()
    streak = 0
    expected = today

    for day_str in unique_days:
        day = date.fromisoformat(day_str)
        if day == expected or (streak == 0 and day == today - timedelta(days=1)):
            streak += 1
            expected = day - timedelta(days=1)
        elif streak == 0 and day == today:
            streak = 1
            expected = day - timedelta(days=1)
        else:
            break

    return streak


@router.get("/dashboard", response_model=DashboardStats)
def dashboard_stats(current_user: UserResponse = Depends(get_current_user)):
    week_start = (datetime.now() - timedelta(days=7)).isoformat()
    exercise_count = sum(len(c["exercises"]) for c in EXERCISE_CATEGORIES)

    with get_db() as db:
        total_workouts = db.execute(
            "SELECT COUNT(*) AS c FROM workout_logs WHERE user_id = ?",
            (current_user.id,),
        ).fetchone()["c"]
        workouts_this_week = db.execute(
            "SELECT COUNT(*) AS c FROM workout_logs WHERE user_id = ? AND logged_at >= ?",
            (current_user.id, week_start),
        ).fetchone()["c"]
        saved_plans = db.execute(
            "SELECT COUNT(*) AS c FROM saved_plans WHERE user_id = ?",
            (current_user.id,),
        ).fetchone()["c"]
        chat_messages = db.execute(
            "SELECT COUNT(*) AS c FROM chat_messages WHERE user_id = ? AND role = 'user'",
            (current_user.id,),
        ).fetchone()["c"]
        log_dates = [
            r["logged_at"]
            for r in db.execute(
                "SELECT DISTINCT logged_at FROM workout_logs WHERE user_id = ? ORDER BY logged_at DESC",
                (current_user.id,),
            ).fetchall()
        ]

    return DashboardStats(
        total_workouts=total_workouts,
        workouts_this_week=workouts_this_week,
        current_streak=_compute_streak(log_dates),
        saved_plans=saved_plans,
        chat_messages=chat_messages,
        content_totals={
            "exercises": exercise_count,
            "recipes": len(RECIPES),
            "articles": len(ARTICLES),
            "blogs": len(BLOGS),
        },
    )


@router.get("/weekly", response_model=list[WeeklyActivity])
def weekly_activity(current_user: UserResponse = Depends(get_current_user)):
    start = (date.today() - timedelta(days=6)).isoformat()
    with get_db() as db:
        rows = db.execute(
            """SELECT DATE(logged_at) AS day, COUNT(*) AS count
               FROM workout_logs
               WHERE user_id = ? AND DATE(logged_at) >= ?
               GROUP BY DATE(logged_at)
               ORDER BY day ASC""",
            (current_user.id, start),
        ).fetchall()

    counts = {r["day"]: r["count"] for r in rows}
    result = []
    for i in range(7):
        d = date.today() - timedelta(days=6 - i)
        key = d.isoformat()
        result.append(WeeklyActivity(date=key, count=counts.get(key, 0)))
    return result


@router.get("/workouts", response_model=list[WorkoutLog])
def list_workouts(
    limit: int = Query(50, ge=1, le=200),
    current_user: UserResponse = Depends(get_current_user),
):
    with get_db() as db:
        rows = db.execute(
            """SELECT id, exercise_id, exercise_name, sets, reps, weight_kg, duration_min, notes, logged_at
               FROM workout_logs WHERE user_id = ? ORDER BY id DESC LIMIT ?""",
            (current_user.id, limit),
        ).fetchall()
    return [_row_to_log(r) for r in rows]


@router.post("/workouts", response_model=WorkoutLog)
def log_workout(payload: WorkoutLogCreate, current_user: UserResponse = Depends(get_current_user)):
    data = payload.model_dump()
    with get_db() as db:
        cur = db.execute(
            """INSERT INTO workout_logs
               (user_id, exercise_id, exercise_name, sets, reps, weight_kg, duration_min, notes)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                current_user.id,
                data["exercise_id"],
                data["exercise_name"],
                data["sets"],
                data["reps"],
                data["weight_kg"],
                data["duration_min"],
                data["notes"],
            ),
        )
        db.commit()
        row = db.execute(
            """SELECT id, exercise_id, exercise_name, sets, reps, weight_kg, duration_min, notes, logged_at
               FROM workout_logs WHERE id = ?""",
            (cur.lastrowid,),
        ).fetchone()
        total = db.execute(
            "SELECT COUNT(*) AS c FROM workout_logs WHERE user_id = ?",
            (current_user.id,),
        ).fetchone()["c"]
        log_dates = [
            r["logged_at"]
            for r in db.execute(
                "SELECT DISTINCT logged_at FROM workout_logs WHERE user_id = ? ORDER BY logged_at DESC",
                (current_user.id,),
            ).fetchall()
        ]
    streak = _compute_streak(log_dates)
    check_workout_badges(current_user.id, total, streak)
    return _row_to_log(row)


@router.get("/workouts/exercise/{exercise_id}/count")
def exercise_log_count(exercise_id: str, current_user: UserResponse = Depends(get_current_user)):
    with get_db() as db:
        count = db.execute(
            "SELECT COUNT(*) AS c FROM workout_logs WHERE user_id = ? AND exercise_id = ?",
            (current_user.id, exercise_id),
        ).fetchone()["c"]
    return {"exercise_id": exercise_id, "count": count}


@router.get("/feed", response_model=list[ActivityFeedItem])
def activity_feed(
    limit: int = Query(15, ge=1, le=50),
    current_user: UserResponse = Depends(get_current_user),
):
    with get_db() as db:
        workouts = db.execute(
            """SELECT id, exercise_name, sets, reps, logged_at FROM workout_logs
               WHERE user_id = ? ORDER BY id DESC LIMIT ?""",
            (current_user.id, limit),
        ).fetchall()
        plans = db.execute(
            """SELECT id, title, plan_type, created_at FROM saved_plans
               WHERE user_id = ? ORDER BY id DESC LIMIT ?""",
            (current_user.id, limit),
        ).fetchall()

    items: list[ActivityFeedItem] = []
    for w in workouts:
        detail = f"{w['sets'] or '—'}×{w['reps'] or '—'} reps" if w["sets"] or w["reps"] else "Workout logged"
        items.append(
            ActivityFeedItem(
                id=w["id"],
                type="workout",
                title=w["exercise_name"],
                subtitle=detail,
                created_at=w["logged_at"],
            )
        )
    for p in plans:
        items.append(
            ActivityFeedItem(
                id=p["id"],
                type="plan",
                title=p["title"],
                subtitle=p["plan_type"].replace("-", " ").title(),
                created_at=p["created_at"],
            )
        )

    items.sort(key=lambda x: x.created_at, reverse=True)
    return items[:limit]


@router.get("/prs", response_model=list[ExercisePR])
def exercise_prs(current_user: UserResponse = Depends(get_current_user)):
    with get_db() as db:
        rows = db.execute(
            """SELECT exercise_id, exercise_name,
                      MAX(sets) AS best_sets,
                      MAX(reps) AS best_reps,
                      MAX(weight_kg) AS best_weight_kg,
                      COUNT(*) AS total_sessions
               FROM workout_logs
               WHERE user_id = ?
               GROUP BY exercise_id
               ORDER BY total_sessions DESC
               LIMIT 20""",
            (current_user.id,),
        ).fetchall()

    return [
        ExercisePR(
            exercise_id=r["exercise_id"],
            exercise_name=r["exercise_name"],
            best_sets=r["best_sets"],
            best_reps=r["best_reps"],
            best_weight_kg=r["best_weight_kg"],
            total_sessions=r["total_sessions"],
        )
        for r in rows
    ]


@router.get("/monthly", response_model=list[MonthlyActivity])
def monthly_activity(current_user: UserResponse = Depends(get_current_user)):
    start = (date.today() - timedelta(days=29)).isoformat()
    with get_db() as db:
        rows = db.execute(
            """SELECT DATE(logged_at) AS day, COUNT(*) AS count
               FROM workout_logs
               WHERE user_id = ? AND DATE(logged_at) >= ?
               GROUP BY DATE(logged_at)
               ORDER BY day ASC""",
            (current_user.id, start),
        ).fetchall()

    counts = {r["day"]: r["count"] for r in rows}
    result = []
    for i in range(30):
        d = date.today() - timedelta(days=29 - i)
        key = d.isoformat()
        result.append(MonthlyActivity(date=key, count=counts.get(key, 0)))
    return result
