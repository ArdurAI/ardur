"""Token bucket rate limiter for the Ardur proxy and hub."""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass


@dataclass
class _Bucket:
    tokens: float
    last_update: float


class RateLimiter:
    """In-memory token bucket rate limiter, per-key, thread-safe.

    Configurable via environment variables:
      ARDUR_RATE_LIMIT_RPS   — sustained requests per second (default 100)
      ARDUR_RATE_LIMIT_BURST — max burst size (default 200)
    """

    def __init__(
        self,
        rate: float | None = None,
        burst: int | None = None,
        bucket_ttl_s: float = 120.0,
        cleanup_interval_s: float = 60.0,
    ):
        self._rate = rate or float(os.environ.get("ARDUR_RATE_LIMIT_RPS", "100"))
        self._burst = burst or int(os.environ.get("ARDUR_RATE_LIMIT_BURST", "200"))
        self._bucket_ttl = bucket_ttl_s
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.Lock()
        self._cleanup_stop = threading.Event()
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop,
            args=(cleanup_interval_s,),
            daemon=True,
        )
        self._cleanup_thread.start()

    def allow(self, key: str) -> bool:
        """Atomically check and consume a token for *key*.  Returns True if allowed."""
        now = time.monotonic()
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = _Bucket(tokens=self._burst, last_update=now)
                self._buckets[key] = bucket

            elapsed = now - bucket.last_update
            bucket.tokens = min(self._burst, bucket.tokens + elapsed * self._rate)
            bucket.last_update = now

            if bucket.tokens >= 1.0:
                bucket.tokens -= 1.0
                return True
            return False

    def _cleanup_loop(self, interval_s: float) -> None:
        while not self._cleanup_stop.wait(interval_s):
            now = time.monotonic()
            with self._lock:
                stale = [k for k, b in self._buckets.items() if now - b.last_update > self._bucket_ttl]
                for k in stale:
                    del self._buckets[k]

    def stop(self) -> None:
        self._cleanup_stop.set()
