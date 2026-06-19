import logging
import time
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.config import settings
from app.database import init_db
from app.routers import activity, admin, ai, auth, contact, content, extras, plans, public, sessions, wellness

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("fitlife")

app = FastAPI(title="FitLife API", version="4.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    elapsed_ms = (time.perf_counter() - start) * 1000
    logger.info("%s %s → %s (%.1fms)", request.method, request.url.path, response.status_code, elapsed_ms)
    return response


app.include_router(auth.router)
app.include_router(contact.router)
app.include_router(content.router)
app.include_router(ai.router)
app.include_router(plans.router)
app.include_router(activity.router)
app.include_router(admin.router)
app.include_router(wellness.router)
app.include_router(sessions.router)
app.include_router(extras.router)
app.include_router(public.router)

_IMAGES_DIR = Path(__file__).resolve().parent.parent.parent / "frontend" / "public" / "images"
if _IMAGES_DIR.is_dir():
    app.mount("/images", StaticFiles(directory=_IMAGES_DIR), name="images")


@app.on_event("startup")
def on_startup():
    init_db()
    logger.info("FitLife API started (provider=%s, ai=%s)", settings.llm_provider, settings.ai_configured)


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "app": "FitLife API",
        "version": "4.0.0",
        "ai_configured": settings.ai_configured,
    }
