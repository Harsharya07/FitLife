"""Award badges and create notifications when milestones are hit."""

import logging

from app.database import get_db

logger = logging.getLogger("fitlife.achievements")

BADGES = {
    "first_workout": {"title": "First Step", "desc": "Logged your first workout"},
    "ten_workouts": {"title": "Dedicated", "desc": "Logged 10 workouts"},
    "streak_3": {"title": "On Fire", "desc": "3-day workout streak"},
    "streak_7": {"title": "Week Warrior", "desc": "7-day workout streak"},
    "streak_30": {"title": "Unstoppable", "desc": "30-day workout streak"},
    "profile_complete": {"title": "Profile Pro", "desc": "Completed fitness profile"},
    "first_plan": {"title": "Planner", "desc": "Saved your first AI plan"},
    "water_8": {"title": "Hydrated", "desc": "Drank 8 glasses of water in one day"},
    "first_goal": {"title": "Goal Setter", "desc": "Created your first goal"},
}


def _award(user_id: int, badge_id: str) -> bool:
    if badge_id not in BADGES:
        return False
    meta = BADGES[badge_id]
    try:
        with get_db() as db:
            db.execute(
                "INSERT INTO user_badges (user_id, badge_id) VALUES (?, ?)",
                (user_id, badge_id),
            )
            db.execute(
                """INSERT INTO notifications (user_id, type, title, body)
                   VALUES (?, 'badge', ?, ?)""",
                (user_id, f"Badge unlocked: {meta['title']}", meta["desc"]),
            )
            db.commit()
        return True
    except Exception:
        return False


def _has_badge(user_id: int, badge_id: str) -> bool:
    with get_db() as db:
        row = db.execute(
            "SELECT 1 FROM user_badges WHERE user_id = ? AND badge_id = ?",
            (user_id, badge_id),
        ).fetchone()
    return row is not None


def check_workout_badges(user_id: int, total_workouts: int, streak: int) -> list[str]:
    awarded = []
    if total_workouts >= 1 and not _has_badge(user_id, "first_workout"):
        if _award(user_id, "first_workout"):
            awarded.append("first_workout")
    if total_workouts >= 10 and not _has_badge(user_id, "ten_workouts"):
        if _award(user_id, "ten_workouts"):
            awarded.append("ten_workouts")
    for days, bid in [(3, "streak_3"), (7, "streak_7"), (30, "streak_30")]:
        if streak >= days and not _has_badge(user_id, bid):
            if _award(user_id, bid):
                awarded.append(bid)
    return awarded


def check_plan_badge(user_id: int) -> None:
    if not _has_badge(user_id, "first_plan"):
        _award(user_id, "first_plan")


def check_profile_badge(user_id: int) -> None:
    if not _has_badge(user_id, "profile_complete"):
        _award(user_id, "profile_complete")


def check_goal_badge(user_id: int) -> None:
    if not _has_badge(user_id, "first_goal"):
        _award(user_id, "first_goal")


def check_water_badge(user_id: int, glasses_today: int) -> None:
    if glasses_today >= 8 and not _has_badge(user_id, "water_8"):
        _award(user_id, "water_8")
