import secrets
import time
from fastapi import APIRouter, Request, HTTPException

from models import (
    VerifySendRequest, VerifySendResponse,
    VerifyConfirmRequest, VerifyConfirmResponse,
)
from security import verification_store, verify_request_limiter, verify_attempt_limiter
from services import email_service
from config import settings

router = APIRouter(prefix="/verify", tags=["Verification"])

# Token store: token -> (email, expiry)
_scan_tokens: dict[str, tuple[str, float]] = {}


def _mask_email(email: str) -> str:
    local, domain = email.split('@')
    if len(local) <= 2:
        return f"{local[0]}***@{domain}"
    return f"{local[0]}***{local[-1]}@{domain}"


def _get_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


@router.post("/send", response_model=VerifySendResponse)
async def send_code(request: Request, body: VerifySendRequest):
    ip = _get_ip(request)

    allowed, retry = verify_request_limiter.is_allowed(
        key=ip,
        max_requests=settings.RATE_LIMIT_VERIFY_PER_HOUR,
        window_seconds=3600,
    )
    if not allowed:
        raise HTTPException(429, {"success": False, "error": "Too many requests", "retry_after": retry})

    code = verification_store.create(body.email)
    success, error = await email_service.send_verification(body.email, code)

    if not success:
        raise HTTPException(500, {"success": False, "error": error or "Failed to send"})

    return VerifySendResponse(
        success=True,
        masked_email=_mask_email(body.email),
        expires_in=settings.VERIFICATION_CODE_EXPIRY_SECONDS,
        message="Code sent",
    )


@router.post("/confirm", response_model=VerifyConfirmResponse)
async def confirm_code(request: Request, body: VerifyConfirmRequest):
    ip = _get_ip(request)
    rate_key = f"{ip}:{body.email}"

    allowed, retry = verify_attempt_limiter.is_allowed(
        key=rate_key,
        max_requests=settings.VERIFICATION_MAX_ATTEMPTS,
        window_seconds=settings.VERIFICATION_CODE_EXPIRY_SECONDS,
        apply_lockout=True,
        lockout_seconds=settings.VERIFICATION_LOCKOUT_SECONDS,
    )
    if not allowed:
        raise HTTPException(429, {"success": False, "error": "Too many attempts", "retry_after": retry})

    success, error = verification_store.verify(body.email, body.code)
    if not success:
        raise HTTPException(400, {"success": False, "error": error})

    # Generate scan token
    token = secrets.token_hex(32)
    _scan_tokens[token] = (body.email, time.time() + 600)  # 10 min expiry

    # Cleanup old tokens
    now = time.time()
    for k in [k for k, (_, exp) in _scan_tokens.items() if exp < now]:
        del _scan_tokens[k]

    verify_attempt_limiter.reset(rate_key)

    return VerifyConfirmResponse(
        success=True,
        scan_token=token,
        message="Verified. Token valid for 10 minutes.",
    )


def validate_scan_token(token: str) -> tuple[bool, str]:
    """Validate and consume scan token. Returns (valid, email_or_error)."""
    if token not in _scan_tokens:
        return False, "Invalid token"

    email, expiry = _scan_tokens[token]
    if time.time() > expiry:
        del _scan_tokens[token]
        return False, "Token expired"

    del _scan_tokens[token]  # One-time use
    return True, email
