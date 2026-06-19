import time
from collections import defaultdict, deque
from threading import Lock

from fastapi import HTTPException, Request

from app.config import settings

_lock = Lock()
_buckets: dict[str, deque[float]] = defaultdict(deque)


def _client_key(request: Request, user_id: int | None) -> str:
    if user_id is not None:
        return f"user:{user_id}"
    forwarded = request.headers.get("x-forwarded-for")
    ip = forwarded.split(",")[0].strip() if forwarded else (request.client.host if request.client else "unknown")
    return f"ip:{ip}"


def check_rate_limit(request: Request, user_id: int | None = None) -> None:
    key = _client_key(request, user_id)
    now = time.time()
    window = settings.ai_rate_limit_window_seconds
    limit = settings.ai_rate_limit_requests

    with _lock:
        bucket = _buckets[key]
        while bucket and bucket[0] <= now - window:
            bucket.popleft()
        if len(bucket) >= limit:
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded. Max {limit} AI requests per {window}s.",
            )
        bucket.append(now)
