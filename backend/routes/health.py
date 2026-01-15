from fastapi import APIRouter
from datetime import datetime
from models import HealthResponse
from config import settings

router = APIRouter(tags=["Health"])


@router.get("/health", response_model=HealthResponse)
async def health():
    return HealthResponse(
        status="ok",
        version=settings.VERSION,
        timestamp=datetime.utcnow(),
    )
