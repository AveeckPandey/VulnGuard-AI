"""
VulnGuard AI - In-Memory TTL Cache
Provides thread-safe caching with expiration policies for threat intelligence feeds.
"""
import time
import threading
from typing import Any, Optional, Dict, Tuple


class TTLCache:
    """Thread-safe in-memory cache with per-item TTL expiration."""

    def __init__(self, default_ttl_seconds: float = 3600.0):
        self._default_ttl = default_ttl_seconds
        self._cache: Dict[str, Tuple[Any, float]] = {}  # key -> (value, expire_timestamp)
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            if key not in self._cache:
                return None
            value, expires_at = self._cache[key]
            if time.time() > expires_at:
                del self._cache[key]
                return None
            return value

    def set(self, key: str, value: Any, ttl_seconds: Optional[float] = None) -> None:
        ttl = ttl_seconds if ttl_seconds is not None else self._default_ttl
        expires_at = time.time() + ttl
        with self._lock:
            self._cache[key] = (value, expires_at)

    def contains(self, key: str) -> bool:
        return self.get(key) is not None

    def delete(self, key: str) -> None:
        with self._lock:
            self._cache.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()

    def size(self) -> int:
        with self._lock:
            # Clean expired on size check
            now = time.time()
            expired_keys = [k for k, (_, exp) in self._cache.items() if now > exp]
            for k in expired_keys:
                del self._cache[k]
            return len(self._cache)


# Global singletons for threat intelligence caching
nvd_cache = TTLCache(default_ttl_seconds=12 * 3600.0)    # 12 hours
epss_cache = TTLCache(default_ttl_seconds=24 * 3600.0)   # 24 hours
cisa_cache = TTLCache(default_ttl_seconds=6 * 3600.0)    # 6 hours
