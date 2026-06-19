import logging
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status

from app.auth_utils import (
    create_access_token,
    create_refresh_token,
    get_current_user,
    hash_password,
    hash_token,
    revoke_refresh_token,
    store_refresh_token,
    validate_refresh_token,
    verify_password,
)
from app.config import settings
from app.database import get_db
from app.schemas import (
    ForgotPasswordRequest,
    ForgotPasswordResponse,
    MessageResponse,
    RefreshRequest,
    ResetPasswordRequest,
    Token,
    UserCreate,
    UserLogin,
    UserResponse,
)

logger = logging.getLogger("fitlife")

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/signup", response_model=MessageResponse)
def signup(payload: UserCreate):
    if payload.password != payload.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")

    hashed = hash_password(payload.password)
    is_admin = 1 if payload.username.lower() == settings.admin_username.lower() else 0
    try:
        with get_db() as db:
            db.execute(
                "INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
                (payload.username, hashed, is_admin),
            )
            db.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Username already exists")

    return MessageResponse(message="Account created successfully! Please login.")


def _issue_tokens(user_id: int, username: str, is_admin: bool) -> Token:
    access = create_access_token(user_id, username, is_admin)
    refresh = create_refresh_token()
    store_refresh_token(user_id, refresh)
    return Token(access_token=access, refresh_token=refresh)


@router.post("/login", response_model=Token)
def login(payload: UserLogin):
    with get_db() as db:
        user = db.execute(
            "SELECT id, username, password, is_admin FROM users WHERE username = ?",
            (payload.username,),
        ).fetchone()

    if not user or not verify_password(payload.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    return _issue_tokens(user["id"], user["username"], bool(user["is_admin"]))


@router.post("/refresh", response_model=Token)
def refresh(payload: RefreshRequest):
    user = validate_refresh_token(payload.refresh_token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    revoke_refresh_token(payload.refresh_token)
    return _issue_tokens(user.id, user.username, user.is_admin)


@router.get("/me", response_model=UserResponse)
def me(current_user: UserResponse = Depends(get_current_user)):
    return current_user


@router.post("/logout", response_model=MessageResponse)
def logout(payload: RefreshRequest, _: UserResponse = Depends(get_current_user)):
    revoke_refresh_token(payload.refresh_token)
    return MessageResponse(message="Logged out successfully")


@router.post("/forgot-password", response_model=ForgotPasswordResponse)
def forgot_password(payload: ForgotPasswordRequest):
    with get_db() as db:
        user = db.execute("SELECT id FROM users WHERE username = ?", (payload.username,)).fetchone()
    if not user:
        return ForgotPasswordResponse(message="If the account exists, a reset link was generated.")

    token = secrets.token_urlsafe(32)
    expires = datetime.now(timezone.utc) + timedelta(hours=1)
    with get_db() as db:
        db.execute(
            "INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)",
            (user["id"], hash_token(token), expires.isoformat()),
        )
        db.commit()
    logger.info("Password reset token for %s: %s", payload.username, token)
    return ForgotPasswordResponse(
        message="Reset token generated. In production this would be emailed.",
        reset_token=token,
    )


@router.post("/reset-password", response_model=MessageResponse)
def reset_password(payload: ResetPasswordRequest):
    if payload.new_password != payload.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")

    token_hash = hash_token(payload.token)
    with get_db() as db:
        row = db.execute(
            """SELECT user_id, expires_at, used FROM password_reset_tokens WHERE token_hash = ?""",
            (token_hash,),
        ).fetchone()
        if not row or row["used"]:
            raise HTTPException(status_code=400, detail="Invalid or used reset token")
        expires = datetime.fromisoformat(row["expires_at"])
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if expires < datetime.now(timezone.utc):
            raise HTTPException(status_code=400, detail="Reset token expired")

        hashed = hash_password(payload.new_password)
        db.execute("UPDATE users SET password = ? WHERE id = ?", (hashed, row["user_id"]))
        db.execute("UPDATE password_reset_tokens SET used = 1 WHERE token_hash = ?", (token_hash,))
        db.commit()
    return MessageResponse(message="Password reset successfully. You can now login.")
