import secrets
import hashlib
import time
from typing import Optional
from dataclasses import dataclass
from threading import Lock
from config import settings


@dataclass
class VerificationRecord:
    code_hash: str
    salt: str
    email_hash: str
    created_at: float
    expires_at: float
    attempts: int = 0
    used: bool = False


class VerificationStore:
    def __init__(self):
        self._store: dict[str, VerificationRecord] = {}
        self._lock = Lock()

    def _hash_email(self, email: str) -> str:
        return hashlib.sha256(email.lower().encode()).hexdigest()

    def _hash_code(self, code: str, salt: str) -> str:
        return hashlib.sha256(f"{salt}{code}".encode()).hexdigest()

    def _cleanup(self):
        now = time.time()
        with self._lock:
            expired = [
                k for k, v in self._store.items()
                if v.expires_at < now or v.used
            ]
            for k in expired:
                del self._store[k]

    def create(self, email: str) -> str:
        """Create code. Returns plaintext code to send via email."""
        self._cleanup()

        email_hash = self._hash_email(email)
        code = ''.join(str(secrets.randbelow(10)) for _ in range(settings.VERIFICATION_CODE_LENGTH))
        salt = secrets.token_hex(16)

        now = time.time()
        record = VerificationRecord(
            code_hash=self._hash_code(code, salt),
            salt=salt,
            email_hash=email_hash,
            created_at=now,
            expires_at=now + settings.VERIFICATION_CODE_EXPIRY_SECONDS,
        )

        with self._lock:
            # Remove any existing for this email
            self._store = {k: v for k, v in self._store.items() if v.email_hash != email_hash}
            self._store[email_hash] = record

        return code

    def verify(self, email: str, code: str) -> tuple[bool, Optional[str]]:
        """Verify code. Returns (success, error_message)."""
        self._cleanup()

        email_hash = self._hash_email(email)
        now = time.time()

        with self._lock:
            if email_hash not in self._store:
                return False, "No verification pending"

            record = self._store[email_hash]

            if record.used:
                return False, "Code already used"

            if record.expires_at < now:
                del self._store[email_hash]
                return False, "Code expired"

            if record.attempts >= settings.VERIFICATION_MAX_ATTEMPTS:
                del self._store[email_hash]
                return False, "Too many attempts"

            record.attempts += 1

            if self._hash_code(code, record.salt) != record.code_hash:
                remaining = settings.VERIFICATION_MAX_ATTEMPTS - record.attempts
                return False, f"Invalid code. {remaining} attempts left"

            record.used = True
            return True, None

    def get_expiry(self, email: str) -> Optional[int]:
        email_hash = self._hash_email(email)
        with self._lock:
            record = self._store.get(email_hash)
            if not record or record.used:
                return None
            return max(0, int(record.expires_at - time.time()))


verification_store = VerificationStore()
