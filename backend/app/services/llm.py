import json
from collections.abc import AsyncIterator

import httpx
from fastapi import HTTPException

from app.config import settings

FITNESS_SYSTEM = """You are FitLife AI Coach — a friendly, expert fitness and nutrition assistant.
Give practical, safe, evidence-based advice. Use markdown for structure (headings, lists, bold).
Always remind users to consult a doctor for medical conditions. Be concise but thorough.
Never invent dangerous advice. Tailor responses to the user's profile when provided."""


def _ensure_configured():
    if not settings.ai_configured:
        raise HTTPException(
            status_code=503,
            detail=(
                "AI is not configured. Add GEMINI_API_KEY or OPENAI_API_KEY to your .env file "
                "and set LLM_PROVIDER=gemini or openai."
            ),
        )


def _build_gemini_contents(user_prompt: str, history: list[dict] | None):
    contents = []
    if history:
        for msg in history[-10:]:
            role = "user" if msg["role"] == "user" else "model"
            contents.append({"role": role, "parts": [{"text": msg["content"]}]})
    contents.append({"role": "user", "parts": [{"text": user_prompt}]})
    return contents


async def _call_gemini(system: str, user_prompt: str, history: list[dict] | None = None) -> str:
    url = (
        f"https://generativelanguage.googleapis.com/v1beta/models/"
        f"{settings.gemini_model}:generateContent?key={settings.gemini_api_key}"
    )
    payload = {
        "systemInstruction": {"parts": [{"text": system}]},
        "contents": _build_gemini_contents(user_prompt, history),
        "generationConfig": {"temperature": 0.7, "maxOutputTokens": 4096},
    }

    async with httpx.AsyncClient(timeout=90.0) as client:
        resp = await client.post(url, json=payload)
        if resp.status_code != 200:
            detail = resp.text[:500]
            raise HTTPException(status_code=502, detail=f"Gemini API error: {detail}")
        data = resp.json()
        try:
            return data["candidates"][0]["content"]["parts"][0]["text"]
        except (KeyError, IndexError):
            raise HTTPException(status_code=502, detail="Unexpected Gemini response format")


async def _stream_gemini(system: str, user_prompt: str, history: list[dict] | None = None) -> AsyncIterator[str]:
    url = (
        f"https://generativelanguage.googleapis.com/v1beta/models/"
        f"{settings.gemini_model}:streamGenerateContent?alt=sse&key={settings.gemini_api_key}"
    )
    payload = {
        "systemInstruction": {"parts": [{"text": system}]},
        "contents": _build_gemini_contents(user_prompt, history),
        "generationConfig": {"temperature": 0.7, "maxOutputTokens": 4096},
    }

    async with httpx.AsyncClient(timeout=90.0) as client:
        async with client.stream("POST", url, json=payload) as resp:
            if resp.status_code != 200:
                body = (await resp.aread()).decode()[:500]
                raise HTTPException(status_code=502, detail=f"Gemini API error: {body}")

            async for line in resp.aiter_lines():
                if not line.startswith("data: "):
                    continue
                raw = line[6:].strip()
                if not raw or raw == "[DONE]":
                    continue
                try:
                    data = json.loads(raw)
                    parts = data.get("candidates", [{}])[0].get("content", {}).get("parts", [])
                    for part in parts:
                        text = part.get("text", "")
                        if text:
                            yield text
                except json.JSONDecodeError:
                    continue


async def _call_openai(system: str, user_prompt: str, history: list[dict] | None = None) -> str:
    messages = [{"role": "system", "content": system}]
    if history:
        for msg in history[-10:]:
            messages.append({"role": msg["role"], "content": msg["content"]})
    messages.append({"role": "user", "content": user_prompt})

    headers = {
        "Authorization": f"Bearer {settings.openai_api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": settings.openai_model,
        "messages": messages,
        "temperature": 0.7,
        "max_tokens": 4096,
    }

    async with httpx.AsyncClient(timeout=90.0) as client:
        resp = await client.post(
            f"{settings.openai_base_url.rstrip('/')}/chat/completions",
            headers=headers,
            json=payload,
        )
        if resp.status_code != 200:
            raise HTTPException(status_code=502, detail=f"OpenAI API error: {resp.text[:500]}")
        data = resp.json()
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError):
            raise HTTPException(status_code=502, detail="Unexpected OpenAI response format")


async def _stream_openai(system: str, user_prompt: str, history: list[dict] | None = None) -> AsyncIterator[str]:
    messages = [{"role": "system", "content": system}]
    if history:
        for msg in history[-10:]:
            messages.append({"role": msg["role"], "content": msg["content"]})
    messages.append({"role": "user", "content": user_prompt})

    headers = {
        "Authorization": f"Bearer {settings.openai_api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": settings.openai_model,
        "messages": messages,
        "temperature": 0.7,
        "max_tokens": 4096,
        "stream": True,
    }

    async with httpx.AsyncClient(timeout=90.0) as client:
        async with client.stream(
            "POST",
            f"{settings.openai_base_url.rstrip('/')}/chat/completions",
            headers=headers,
            json=payload,
        ) as resp:
            if resp.status_code != 200:
                body = (await resp.aread()).decode()[:500]
                raise HTTPException(status_code=502, detail=f"OpenAI API error: {body}")

            async for line in resp.aiter_lines():
                if not line.startswith("data: "):
                    continue
                raw = line[6:].strip()
                if not raw or raw == "[DONE]":
                    continue
                try:
                    data = json.loads(raw)
                    delta = data["choices"][0].get("delta", {})
                    text = delta.get("content", "")
                    if text:
                        yield text
                except (json.JSONDecodeError, KeyError, IndexError):
                    continue


async def generate_ai_response(
    user_prompt: str,
    system: str = FITNESS_SYSTEM,
    history: list[dict] | None = None,
) -> str:
    _ensure_configured()
    if settings.llm_provider == "openai":
        return await _call_openai(system, user_prompt, history)
    return await _call_gemini(system, user_prompt, history)


async def stream_ai_response(
    user_prompt: str,
    system: str = FITNESS_SYSTEM,
    history: list[dict] | None = None,
) -> AsyncIterator[str]:
    _ensure_configured()
    if settings.llm_provider == "openai":
        async for chunk in _stream_openai(system, user_prompt, history):
            yield chunk
    else:
        async for chunk in _stream_gemini(system, user_prompt, history):
            yield chunk


def build_profile_context(profile: dict | None) -> str:
    if not profile:
        return "No user profile saved yet."
    lines = ["User profile:"]
    field_labels = {
        "age": "Age",
        "gender": "Gender",
        "height_cm": "Height (cm)",
        "weight_kg": "Weight (kg)",
        "goal": "Fitness goal",
        "activity_level": "Activity level",
        "dietary_preference": "Diet",
        "allergies": "Allergies",
        "health_conditions": "Health conditions",
        "target_calories": "Target calories/day",
        "workout_days_per_week": "Workout days/week",
        "experience_level": "Experience level",
    }
    for key, label in field_labels.items():
        val = profile.get(key)
        if val:
            lines.append(f"- {label}: {val}")
    return "\n".join(lines)
