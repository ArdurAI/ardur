"""Concrete PolicyBackend implementations.

Optional backends remain importable only when their runtime dependencies are
available. NativeBackend is always importable.
"""

import logging

_logger = logging.getLogger(__name__)

from vibap.backends.forbid_rules import (
    ForbidRulesBackend,
    register as register_forbid_rules,
)
from vibap.backends.native import NativeBackend

__all__ = [
    "ForbidRulesBackend",
    "NativeBackend",
    "register_forbid_rules",
]

try:
    from vibap.backends.cedar import CedarBackend, register as register_cedar
except ModuleNotFoundError as exc:  # pragma: no cover - dependency-gated import
    CedarBackend = None  # type: ignore[assignment]

    def register_cedar(_missing: ModuleNotFoundError = exc) -> None:
        _logger.warning(
            "Cedar backend unavailable: cedarpy not installed. "
            "Install with: pip install ardur[cedar] or pip install cedarpy>=4.0"
        )
        raise RuntimeError(
            "cedar backend unavailable: missing optional dependency cedarpy>=4.0. "
            "Install with: pip install ardur[cedar]"
        ) from _missing
else:
    __all__.extend(["CedarBackend", "register_cedar"])
