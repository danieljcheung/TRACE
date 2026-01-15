from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class VerifySendResponse(BaseModel):
    success: bool
    masked_email: str
    expires_in: int
    message: str


class VerifyConfirmResponse(BaseModel):
    success: bool
    scan_token: Optional[str] = None
    message: str


class ErrorResponse(BaseModel):
    success: bool = False
    error: str
    retry_after: Optional[int] = None


class HealthResponse(BaseModel):
    status: str
    version: str
    timestamp: datetime
