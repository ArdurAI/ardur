"""Prometheus-compatible metrics for the Ardur proxy and hub.

No external dependencies — generates Prometheus text format directly.
All metrics are namespaced with ``ardur_`` and are thread-safe.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict


class _Counter:
    def __init__(self, name: str, help_text: str, labels: tuple[str, ...] = ()):
        self.name = name
        self.help = help_text
        self.labels = labels
        self._data: dict[tuple[str, ...], int] = defaultdict(int)
        self._lock = threading.Lock()

    def inc(self, **label_values: str) -> None:
        key = tuple(label_values.get(label, "") for label in self.labels)
        with self._lock:
            self._data[key] += 1

    def render(self) -> str:
        lines = [f"# HELP {self.name} {self.help}", f"# TYPE {self.name} counter"]
        with self._lock:
            for labels, val in sorted(self._data.items()):
                label_str = ",".join(f'{k}="{v}"' for k, v in zip(self.labels, labels))
                lines.append(f"{self.name}{{{label_str}}} {val}")
        return "\n".join(lines) + "\n"


class _Gauge:
    def __init__(self, name: str, help_text: str):
        self.name = name
        self.help = help_text
        self._value: float = 0.0
        self._lock = threading.Lock()

    def set(self, value: float) -> None:
        with self._lock:
            self._value = value

    def inc(self, delta: float = 1.0) -> None:
        with self._lock:
            self._value += delta

    def dec(self, delta: float = 1.0) -> None:
        with self._lock:
            self._value -= delta

    def render(self) -> str:
        lines = [f"# HELP {self.name} {self.help}", f"# TYPE {self.name} gauge"]
        with self._lock:
            lines.append(f"{self.name} {self._value}")
        return "\n".join(lines) + "\n"


class _Histogram:
    def __init__(self, name: str, help_text: str, buckets: tuple[float, ...] | None = None):
        self.name = name
        self.help = help_text
        self.buckets = buckets or (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)
        self._sum = 0.0
        self._count = 0
        self._bucket_counts: dict[float, int] = defaultdict(int)
        self._lock = threading.Lock()

    def observe(self, value: float) -> None:
        with self._lock:
            self._sum += value
            self._count += 1
            for b in self.buckets:
                if value <= b:
                    self._bucket_counts[b] += 1

    def render(self) -> str:
        lines = [f"# HELP {self.name} {self.help}", f"# TYPE {self.name} histogram"]
        with self._lock:
            cum = 0
            for b in self.buckets:
                cum += self._bucket_counts.get(b, 0)
                lines.append(f'{self.name}_bucket{{le="{b}"}} {cum}')
            lines.append(f'{self.name}_bucket{{le="+Inf"}} {self._count}')
            lines.append(f"{self.name}_sum {self._sum}")
            lines.append(f"{self.name}_count {self._count}")
        return "\n".join(lines) + "\n"


class ArdurMetrics:
    def __init__(self):
        self.requests_total = _Counter("ardur_requests_total", "Total HTTP requests", ("method", "path", "status"))
        self.evaluations_total = _Counter("ardur_evaluations_total", "Tool-call evaluations by decision", ("decision",))
        self.errors_total = _Counter("ardur_errors_total", "Errors by type", ("error_type",))
        self.active_sessions = _Gauge("ardur_active_sessions", "Currently active governed sessions")
        self.kill_switch_active = _Gauge("ardur_kill_switch_active", "1 if kill switch is active")
        self.request_duration_seconds = _Histogram("ardur_request_duration_seconds", "Request duration in seconds")
        self.evaluation_duration_seconds = _Histogram("ardur_evaluation_duration_seconds", "Evaluation duration in seconds")
        self._startup_time = time.time()

    def render(self) -> str:
        parts = [
            self.requests_total.render(),
            self.evaluations_total.render(),
            self.errors_total.render(),
            self.active_sessions.render(),
            self.kill_switch_active.render(),
            self.request_duration_seconds.render(),
            self.evaluation_duration_seconds.render(),
        ]
        uptime = time.time() - self._startup_time
        parts.append(f"# HELP ardur_uptime_seconds Proxy uptime in seconds\n# TYPE ardur_uptime_seconds gauge\nardur_uptime_seconds {uptime:.3f}\n")
        return "\n".join(parts)


# Package-level singleton
metrics = ArdurMetrics()
