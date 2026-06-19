from fastapi import APIRouter, Depends

from app.auth_utils import get_current_user
from app.database import get_db
from app.schemas import ContactCreate, MessageResponse, UserResponse

router = APIRouter(prefix="/api/contact", tags=["contact"])


@router.post("", response_model=MessageResponse)
def submit_contact(
    payload: ContactCreate,
    _: UserResponse = Depends(get_current_user),
):
    with get_db() as db:
        db.execute(
            "INSERT INTO contacts (name, email, message) VALUES (?, ?, ?)",
            (payload.name, payload.email, payload.message),
        )
        db.commit()
    return MessageResponse(message="Message sent successfully!")
