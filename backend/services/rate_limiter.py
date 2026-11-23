"""
VulnGuard AI - Async Rate Limiter
Enforces sliding window rate limits and provides exponential backoff with jitter.
"""
import asyncio
import time
import random
from collections import deque
from backend.core.logging import logger


class SlidingWindowRateLimiter:
    """Async sliding window rate limiter ensuring requests do not exceed max_calls per period_seconds."""

    def __init__(self, max_calls: int, period_seconds: float):
        self.max_calls = max_calls
        self.period_seconds = period_seconds
        self.timestamps: deque = deque()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            # Evict timestamps older than the window
            while self.timestamps and (now - self.timestamps[0]) > self.period_seconds:
                self.timestamps.popleft()

            if len(self.timestamps) >= self.max_calls:
                # Sleep until the oldest call in the window expires
                sleep_time = self.period_seconds - (now - self.timestamps[0]) + 0.05
                if sleep_time > 0:
                    logger.debug(f"Rate limit reached ({self.max_calls}/{self.period_seconds}s). Throttling for {sleep_time:.2f}s")
                    await asyncio.sleep(sleep_time)
                # Re-clean after waking up
                now = time.monotonic()
                while self.timestamps and (now - self.timestamps[0]) > self.period_seconds:
                    self.timestamps.popleft()

            self.timestamps.append(time.monotonic())


def calculate_backoff_with_jitter(attempt: int, base_delay: float = 1.0, max_delay: float = 16.0) -> float:
    """Calculates exponential backoff with full jitter to avoid thundering herd."""
    exp_delay = min(max_delay, base_delay * (2 ** attempt))
    jitter = random.uniform(0, exp_delay)
    return jitter
