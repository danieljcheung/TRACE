import time
import hashlib
from typing import Optional
from dataclasses import dataclass, field
from threading import Lock


@dataclass
class RateLimitEntry:
    timestamps: list[float] = field(default_factory=list)
    lockout_until: Optional[float] = None


class RateLimiter:
    def __init__(self):
        self._store: dict[str, RateLimitEntry] = {}
        self._lock = Lock()
        self._last_cleanup = time.time()

    def _hash_key(self, key: str) -> str:
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def _cleanup(self):
        now = time.time()
        if now - self._last_cleanup < 300:
            return
        with self._lock:
            expired = [
                k for k, v in self._store.items()
                if not v.timestamps and (not v.lockout_until or v.lockout_until < now)
            ]
            for k in expired:
                del self._store[k]
            self._last_cleanup = now

    def is_allowed(
        self,
        key: str,
        max_requests: int,
        window_seconds: int,
        apply_lockout: bool = False,
        lockout_seconds: int = 900,
    ) -> tuple[bool, Optional[int]]:
        """Returns (allowed, retry_after_seconds)"""
        self._cleanup()
        hashed = self._hash_key(key)
        now = time.time()

        with self._lock:
            if hashed not in self._store:
                self._store[hashed] = RateLimitEntry()

            entry = self._store[hashed]

            # Check lockout
            if entry.lockout_until and entry.lockout_until > now:
                return False, int(entry.lockout_until - now)
            elif entry.lockout_until:
                entry.lockout_until = None

            # Filter to window
            window_start = now - window_seconds
            entry.timestamps = [t for t in entry.timestamps if t > window_start]

            # Check limit
            if len(entry.timestamps) < max_requests:
                entry.timestamps.append(now)
                return True, None

            # Exceeded
            if apply_lockout:
                entry.lockout_until = now + lockout_seconds
                return False, lockout_seconds

            oldest = min(entry.timestamps)
            retry_after = int((oldest + window_seconds) - now) + 1
            return False, retry_after

    def reset(self, key: str):
        hashed = self._hash_key(key)
        with self._lock:
            if hashed in self._store:
                del self._store[hashed]


# Global instances
verify_request_limiter = RateLimiter()
verify_attempt_limiter = RateLimiter()
scan_limiter = RateLimiter()
