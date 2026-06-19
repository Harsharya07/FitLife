import json

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse

from app.auth_utils import get_current_user
from app.config import settings
from app.database import get_db
from app.rate_limit import check_rate_limit
from app.schemas import (
    AiGenerateResponse,
    AiStatusResponse,
    ChatMessage,
    ChatMessageRequest,
    ChatResponse,
    GenerateRequest,
    MessageResponse,
    UserProfile,
    UserResponse,
)
from app.services.llm import build_profile_context, generate_ai_response, stream_ai_response
from app.services.rag import build_rag_context, recipe_list_for_prompt
from app.services.achievements import check_plan_badge, check_profile_badge

router = APIRouter(prefix="/api/ai", tags=["ai"])

PLAN_TITLES = {
    "diet-plan": "Diet Plan",
    "diet-chart": "Weekly Diet Chart",
    "workout-plan": "Workout Routine",
}


def _row_to_profile(row) -> UserProfile | None:
    if not row:
        return None
    return UserProfile(
        age=row["age"],
        gender=row["gender"],
        height_cm=row["height_cm"],
        weight_kg=row["weight_kg"],
        goal=row["goal"],
        activity_level=row["activity_level"],
        dietary_preference=row["dietary_preference"],
        allergies=row["allergies"],
        health_conditions=row["health_conditions"],
        target_calories=row["target_calories"],
        workout_days_per_week=row["workout_days_per_week"],
        experience_level=row["experience_level"],
    )


def _profile_dict(row) -> dict | None:
    if not row:
        return None
    return {
        "age": row["age"],
        "gender": row["gender"],
        "height_cm": row["height_cm"],
        "weight_kg": row["weight_kg"],
        "goal": row["goal"],
        "activity_level": row["activity_level"],
        "dietary_preference": row["dietary_preference"],
        "allergies": row["allergies"],
        "health_conditions": row["health_conditions"],
        "target_calories": row["target_calories"],
        "workout_days_per_week": row["workout_days_per_week"],
        "experience_level": row["experience_level"],
    }


def _get_profile_row(user_id: int):
    with get_db() as db:
        return db.execute("SELECT * FROM user_profiles WHERE user_id = ?", (user_id,)).fetchone()


def _save_plan(user_id: int, plan_type: str, content: str) -> int:
    title = f"{PLAN_TITLES.get(plan_type, 'Plan')} — {settings.llm_provider}"
    with get_db() as db:
        cur = db.execute(
            "INSERT INTO saved_plans (user_id, title, plan_type, content) VALUES (?, ?, ?, ?)",
            (user_id, title, plan_type, content),
        )
        db.commit()
    plan_id = cur.lastrowid or 0
    check_plan_badge(user_id)
    return plan_id


@router.get("/status", response_model=AiStatusResponse)
def ai_status(_: UserResponse = Depends(get_current_user)):
    model = settings.ai_model_name
    return AiStatusResponse(
        configured=settings.ai_configured,
        provider=settings.llm_provider,
        model=model,
    )


@router.get("/profile", response_model=UserProfile | None)
def get_profile(current_user: UserResponse = Depends(get_current_user)):
    row = _get_profile_row(current_user.id)
    return _row_to_profile(row)


@router.put("/profile", response_model=UserProfile)
def save_profile(payload: UserProfile, current_user: UserResponse = Depends(get_current_user)):
    data = payload.model_dump()
    with get_db() as db:
        db.execute(
            """INSERT INTO user_profiles (
                user_id, age, gender, height_cm, weight_kg, goal, activity_level,
                dietary_preference, allergies, health_conditions, target_calories,
                workout_days_per_week, experience_level, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(user_id) DO UPDATE SET
                age=excluded.age, gender=excluded.gender, height_cm=excluded.height_cm,
                weight_kg=excluded.weight_kg, goal=excluded.goal,
                activity_level=excluded.activity_level,
                dietary_preference=excluded.dietary_preference,
                allergies=excluded.allergies, health_conditions=excluded.health_conditions,
                target_calories=excluded.target_calories,
                workout_days_per_week=excluded.workout_days_per_week,
                experience_level=excluded.experience_level,
                updated_at=CURRENT_TIMESTAMP
            """,
            (
                current_user.id,
                data["age"],
                data["gender"],
                data["height_cm"],
                data["weight_kg"],
                data["goal"],
                data["activity_level"],
                data["dietary_preference"],
                data["allergies"],
                data["health_conditions"],
                data["target_calories"],
                data["workout_days_per_week"],
                data["experience_level"],
            ),
        )
        db.commit()
    check_profile_badge(current_user.id)
    return payload


@router.get("/chat/history", response_model=list[ChatMessage])
def chat_history(current_user: UserResponse = Depends(get_current_user)):
    with get_db() as db:
        rows = db.execute(
            """SELECT id, role, content, created_at FROM chat_messages
               WHERE user_id = ? ORDER BY id ASC LIMIT 50""",
            (current_user.id,),
        ).fetchall()
    return [
        ChatMessage(
            id=r["id"],
            role=r["role"],
            content=r["content"],
            created_at=r["created_at"],
        )
        for r in rows
    ]


@router.delete("/chat/history", response_model=MessageResponse)
def clear_chat(current_user: UserResponse = Depends(get_current_user)):
    with get_db() as db:
        db.execute("DELETE FROM chat_messages WHERE user_id = ?", (current_user.id,))
        db.commit()
    return MessageResponse(message="Chat history cleared")


async def _prepare_chat(payload: ChatMessageRequest, user_id: int):
    profile_row = _get_profile_row(user_id)
    profile_ctx = build_profile_context(_profile_dict(profile_row))

    with get_db() as db:
        db.execute(
            "INSERT INTO chat_messages (user_id, role, content) VALUES (?, 'user', ?)",
            (user_id, payload.message),
        )
        db.commit()
        history_rows = db.execute(
            """SELECT role, content FROM chat_messages WHERE user_id = ?
               ORDER BY id DESC LIMIT 10""",
            (user_id,),
        ).fetchall()

    history = [{"role": r["role"], "content": r["content"]} for r in reversed(history_rows[:-1])]
    rag_ctx = build_rag_context(payload.message)
    prompt = f"{profile_ctx}\n\n{rag_ctx}\n\nUser question: {payload.message}".strip()
    return prompt, history


@router.post("/chat", response_model=ChatResponse)
async def chat(
    payload: ChatMessageRequest,
    request: Request,
    current_user: UserResponse = Depends(get_current_user),
):
    check_rate_limit(request, current_user.id)
    prompt, history = await _prepare_chat(payload, current_user.id)
    reply = await generate_ai_response(prompt, history=history)

    with get_db() as db:
        cur = db.execute(
            "INSERT INTO chat_messages (user_id, role, content) VALUES (?, 'assistant', ?)",
            (current_user.id, reply),
        )
        db.commit()
        msg_id = cur.lastrowid

    return ChatResponse(reply=reply, message_id=msg_id or 0)


@router.post("/chat/stream")
async def chat_stream(
    payload: ChatMessageRequest,
    request: Request,
    current_user: UserResponse = Depends(get_current_user),
):
    check_rate_limit(request, current_user.id)
    prompt, history = await _prepare_chat(payload, current_user.id)

    async def event_generator():
        full_reply = ""
        try:
            async for chunk in stream_ai_response(prompt, history=history):
                full_reply += chunk
                yield f"data: {json.dumps({'type': 'chunk', 'content': chunk})}\n\n"
        except HTTPException as exc:
            yield f"data: {json.dumps({'type': 'error', 'content': exc.detail})}\n\n"
            return
        except Exception as exc:
            yield f"data: {json.dumps({'type': 'error', 'content': str(exc)})}\n\n"
            return

        with get_db() as db:
            cur = db.execute(
                "INSERT INTO chat_messages (user_id, role, content) VALUES (?, 'assistant', ?)",
                (current_user.id, full_reply),
            )
            db.commit()
            msg_id = cur.lastrowid or 0

        yield f"data: {json.dumps({'type': 'done', 'message_id': msg_id})}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@router.post("/generate/diet-plan", response_model=AiGenerateResponse)
async def generate_diet_plan(
    payload: GenerateRequest,
    request: Request,
    current_user: UserResponse = Depends(get_current_user),
):
    check_rate_limit(request, current_user.id)
    profile_row = _get_profile_row(current_user.id)
    profile_ctx = build_profile_context(_profile_dict(profile_row))
    notes = payload.extra_notes or "None"
    prompt = f"""{profile_ctx}

{recipe_list_for_prompt()}

Create a personalized {payload.days}-day diet plan for this user.
Prefer recipes from the FitLife library above when they fit dietary preferences.
Extra notes: {notes}

Include:
1. Daily calorie & macro targets (protein/carbs/fats)
2. Day-by-day meal plan (breakfast, lunch, dinner, snacks)
3. Portion sizes and prep tips
4. Hydration guidance
5. Grocery list summary

Use clear markdown with headings and bullet lists."""

    content = await generate_ai_response(prompt)
    plan_id = _save_plan(current_user.id, "diet-plan", content)
    return AiGenerateResponse(content=content, type="diet-plan", plan_id=plan_id)


@router.post("/generate/diet-chart", response_model=AiGenerateResponse)
async def generate_diet_chart(
    payload: GenerateRequest,
    request: Request,
    current_user: UserResponse = Depends(get_current_user),
):
    check_rate_limit(request, current_user.id)
    profile_row = _get_profile_row(current_user.id)
    profile_ctx = build_profile_context(_profile_dict(profile_row))
    notes = payload.extra_notes or "None"
    prompt = f"""{profile_ctx}

Create a weekly diet chart (table format in markdown) for {payload.days} days.
Extra notes: {notes}

Include a markdown table with columns: Day | Breakfast | Lunch | Dinner | Snacks | Approx Calories
Add a brief intro with total daily calorie target and macro split.
Keep meals practical and aligned with dietary preferences."""

    content = await generate_ai_response(prompt)
    plan_id = _save_plan(current_user.id, "diet-chart", content)
    return AiGenerateResponse(content=content, type="diet-chart", plan_id=plan_id)


@router.post("/generate/workout-plan", response_model=AiGenerateResponse)
async def generate_workout_plan(
    payload: GenerateRequest,
    request: Request,
    current_user: UserResponse = Depends(get_current_user),
):
    check_rate_limit(request, current_user.id)
    profile_row = _get_profile_row(current_user.id)
    profile_ctx = build_profile_context(_profile_dict(profile_row))
    notes = payload.extra_notes or "None"
    days = profile_row["workout_days_per_week"] if profile_row and profile_row["workout_days_per_week"] else payload.days
    prompt = f"""{profile_ctx}

Create a personalized {days}-day per week workout routine for this user.
Extra notes: {notes}

Include:
1. Weekly schedule overview
2. Each session: warmup, exercises (sets/reps/rest), cooldown
3. Progressive overload tips
4. Rest day recommendations
5. Equipment alternatives (home vs gym)

Use markdown with clear headings. Match difficulty to experience level."""

    content = await generate_ai_response(prompt)
    plan_id = _save_plan(current_user.id, "workout-plan", content)
    return AiGenerateResponse(content=content, type="workout-plan", plan_id=plan_id)


@router.post("/digest")
async def weekly_digest(
    request: Request,
    current_user: UserResponse = Depends(get_current_user),
):
    check_rate_limit(request, current_user.id)
    with get_db() as db:
        workouts = db.execute(
            "SELECT COUNT(*) AS c FROM workout_logs WHERE user_id = ? AND logged_at >= datetime('now', '-7 days')",
            (current_user.id,),
        ).fetchone()["c"]
        chats = db.execute(
            "SELECT COUNT(*) AS c FROM chat_messages WHERE user_id = ? AND role = 'user' AND created_at >= datetime('now', '-7 days')",
            (current_user.id,),
        ).fetchone()["c"]
        profile_row = _get_profile_row(current_user.id)

    profile_ctx = build_profile_context(_profile_dict(profile_row))
    prompt = f"""{profile_ctx}

Generate a motivating weekly fitness digest for this user.
Stats: {workouts} workouts logged, {chats} AI coach conversations this week.

Include:
1. Brief summary of the week
2. What went well
3. One focus area for next week
4. Specific actionable tip

Keep it under 300 words, use markdown."""

    content = await generate_ai_response(prompt)
    with get_db() as db:
        db.execute(
            """INSERT INTO notifications (user_id, type, title, body)
               VALUES (?, 'digest', 'Your Weekly Digest', ?)""",
            (current_user.id, content[:500]),
        )
        db.commit()
    return {"content": content}
