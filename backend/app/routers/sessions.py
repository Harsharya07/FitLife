import secrets

from fastapi import APIRouter, Depends, HTTPException

from app.auth_utils import get_current_user
from app.database import get_db
from app.routers.activity import _compute_streak
from app.schemas import (
    MessageResponse,
    SessionExerciseLog,
    SessionStart,
    UserResponse,
    WorkoutLog,
    WorkoutSession,
)
from app.services.achievements import check_workout_badges

router = APIRouter(prefix="/api/sessions", tags=["sessions"])


def _session_row(row, exercise_count: int = 0) -> WorkoutSession:
    return WorkoutSession(
        id=row["id"],
        name=row["name"],
        status=row["status"],
        started_at=row["started_at"],
        ended_at=row["ended_at"],
        notes=row["notes"],
        exercise_count=exercise_count,
    )


@router.post("/start", response_model=WorkoutSession)
def start_session(payload: SessionStart, current_user: UserResponse = Depends(get_current_user)):
    with get_db() as db:
        active = db.execute(
            "SELECT id FROM workout_sessions WHERE user_id = ? AND status = 'active'",
            (current_user.id,),
        ).fetchone()
        if active:
            raise HTTPException(status_code=400, detail="Finish your active session first")
        cur = db.execute(
            "INSERT INTO workout_sessions (user_id, name, status) VALUES (?, ?, 'active')",
            (current_user.id, payload.name),
        )
        db.commit()
        row = db.execute("SELECT * FROM workout_sessions WHERE id = ?", (cur.lastrowid,)).fetchone()
    return _session_row(row)


@router.get("/active", response_model=WorkoutSession | None)
def active_session(current_user: UserResponse = Depends(get_current_user)):
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM workout_sessions WHERE user_id = ? AND status = 'active' ORDER BY id DESC LIMIT 1",
            (current_user.id,),
        ).fetchone()
        if not row:
            return None
        count = db.execute(
            "SELECT COUNT(*) AS c FROM workout_logs WHERE session_id = ?",
            (row["id"],),
        ).fetchone()["c"]
    return _session_row(row, count)


@router.get("", response_model=list[WorkoutSession])
def list_sessions(limit: int = 20, current_user: UserResponse = Depends(get_current_user)):
    with get_db() as db:
        rows = db.execute(
            """SELECT s.*, (SELECT COUNT(*) FROM workout_logs w WHERE w.session_id = s.id) AS ec
               FROM workout_sessions s WHERE s.user_id = ? AND s.status = 'completed'
               ORDER BY s.id DESC LIMIT ?""",
            (current_user.id, limit),
        ).fetchall()
    return [_session_row(r, r["ec"]) for r in rows]


@router.post("/{session_id}/log", response_model=WorkoutLog)
def log_in_session(
    session_id: int,
    payload: SessionExerciseLog,
    current_user: UserResponse = Depends(get_current_user),
):
    data = payload.model_dump()
    with get_db() as db:
        session = db.execute(
            "SELECT * FROM workout_sessions WHERE id = ? AND user_id = ? AND status = 'active'",
            (session_id, current_user.id),
        ).fetchone()
        if not session:
            raise HTTPException(status_code=404, detail="Active session not found")
        cur = db.execute(
            """INSERT INTO workout_logs
               (user_id, exercise_id, exercise_name, sets, reps, weight_kg, duration_min, notes, session_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                current_user.id,
                data["exercise_id"],
                data["exercise_name"],
                data["sets"],
                data["reps"],
                data["weight_kg"],
                data["duration_min"],
                data["notes"],
                session_id,
            ),
        )
        db.commit()
        row = db.execute(
            """SELECT id, exercise_id, exercise_name, sets, reps, weight_kg, duration_min, notes, logged_at
               FROM workout_logs WHERE id = ?""",
            (cur.lastrowid,),
        ).fetchone()
    return WorkoutLog(**dict(row))


@router.post("/{session_id}/finish", response_model=WorkoutSession)
def finish_session(session_id: int, current_user: UserResponse = Depends(get_current_user)):
    with get_db() as db:
        session = db.execute(
            "SELECT * FROM workout_sessions WHERE id = ? AND user_id = ? AND status = 'active'",
            (session_id, current_user.id),
        ).fetchone()
        if not session:
            raise HTTPException(status_code=404, detail="Active session not found")
        db.execute(
            "UPDATE workout_sessions SET status = 'completed', ended_at = CURRENT_TIMESTAMP WHERE id = ?",
            (session_id,),
        )
        db.commit()
        count = db.execute(
            "SELECT COUNT(*) AS c FROM workout_logs WHERE session_id = ?",
            (session_id,),
        ).fetchone()["c"]
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
        row = db.execute("SELECT * FROM workout_sessions WHERE id = ?", (session_id,)).fetchone()
    streak = _compute_streak(log_dates)
    check_workout_badges(current_user.id, total, streak)
    return _session_row(row, count)


@router.delete("/{session_id}", response_model=MessageResponse)
def cancel_session(session_id: int, current_user: UserResponse = Depends(get_current_user)):
    with get_db() as db:
        cur = db.execute(
            "DELETE FROM workout_sessions WHERE id = ? AND user_id = ? AND status = 'active'",
            (session_id, current_user.id),
        )
        db.commit()
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Active session not found")
    return MessageResponse(message="Session cancelled")
