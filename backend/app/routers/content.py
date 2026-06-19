from fastapi import APIRouter, Depends, Query

from app.auth_utils import get_current_user
from app.data.articles import ARTICLES
from app.data.blogs import BLOGS
from app.data.exercises import EXERCISE_CATEGORIES
from app.data.recipes import RECIPES
from app.database import get_db
from app.schemas import Article, Blog, ExerciseCategory, Recipe, UserResponse

router = APIRouter(prefix="/api/content", tags=["content"])

EXERCISE_VIDEOS: dict[str, str] = {
    "push-ups": "https://www.youtube.com/embed/IODxDxX7oi4",
    "dumbbell-chest-press": "https://www.youtube.com/embed/DMUxX1TbhLI",
    "squats": "https://www.youtube.com/embed/aclHkVaku9U",
    "deadlift": "https://www.youtube.com/embed/op9kls8BaE8",
    "plank": "https://www.youtube.com/embed/ASdvN_XEl_c",
    "lunges": "https://www.youtube.com/embed/QOVaHwm-Q6U",
    "pull-ups": "https://www.youtube.com/embed/eGo4IYlbE5g",
    "burpees": "https://www.youtube.com/embed/JZQA08NXPo8",
}


def _enrich_exercises():
    result = []
    for cat in EXERCISE_CATEGORIES:
        exercises = []
        for ex in cat["exercises"]:
            enriched = {**ex, "video_url": EXERCISE_VIDEOS.get(ex["id"])}
            exercises.append(enriched)
        result.append({**cat, "exercises": exercises})
    return result


@router.get("/exercises", response_model=list[ExerciseCategory])
def get_exercises(_: UserResponse = Depends(get_current_user)):
    return _enrich_exercises()


@router.get("/articles", response_model=list[Article])
def get_articles(
    q: str | None = Query(None),
    category: str | None = Query(None),
    _: UserResponse = Depends(get_current_user),
):
    results = ARTICLES
    if category and category.lower() != "all":
        results = [a for a in results if category in a["categories"]]
    if q:
        query = q.lower()
        results = [
            a
            for a in results
            if query in a["title"].lower() or query in a["excerpt"].lower()
        ]
    return results


@router.get("/blogs", response_model=list[Blog])
def get_blogs(
    category: str | None = Query(None),
    _: UserResponse = Depends(get_current_user),
):
    if category and category.lower() != "all":
        return [b for b in BLOGS if b["category"].lower() == category.lower()]
    return BLOGS


@router.get("/recipes", response_model=list[Recipe])
def get_recipes(_: UserResponse = Depends(get_current_user)):
    return RECIPES


@router.get("/blogs/{blog_id}/reactions")
def blog_reactions(blog_id: str, current_user: UserResponse = Depends(get_current_user)):
    with get_db() as db:
        count = db.execute(
            "SELECT COUNT(*) AS c FROM blog_reactions WHERE blog_id = ?",
            (blog_id,),
        ).fetchone()["c"]
        reacted = db.execute(
            "SELECT 1 FROM blog_reactions WHERE blog_id = ? AND user_id = ?",
            (blog_id, current_user.id),
        ).fetchone()
    return {"blog_id": blog_id, "count": count, "user_reacted": reacted is not None}


@router.post("/blogs/{blog_id}/react")
def react_blog(blog_id: str, current_user: UserResponse = Depends(get_current_user)):
    with get_db() as db:
        try:
            db.execute(
                "INSERT INTO blog_reactions (user_id, blog_id) VALUES (?, ?)",
                (current_user.id, blog_id),
            )
            db.commit()
        except Exception:
            db.execute(
                "DELETE FROM blog_reactions WHERE user_id = ? AND blog_id = ?",
                (current_user.id, blog_id),
            )
            db.commit()
        count = db.execute(
            "SELECT COUNT(*) AS c FROM blog_reactions WHERE blog_id = ?",
            (blog_id,),
        ).fetchone()["c"]
        reacted = db.execute(
            "SELECT 1 FROM blog_reactions WHERE blog_id = ? AND user_id = ?",
            (blog_id, current_user.id),
        ).fetchone()
    return {"blog_id": blog_id, "count": count, "user_reacted": reacted is not None}
