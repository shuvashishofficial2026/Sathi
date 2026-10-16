"""Small shared helpers: ids, canonical JSON, timestamps, a sandbox clock."""

from __future__ import annotations

import json
import secrets
from datetime import UTC, datetime, timedelta
from decimal import Decimal


def new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(5)}"


def _default(o):
    if isinstance(o, Decimal):
        return str(o)
    if isinstance(o, datetime):
        return iso(o)
    raise TypeError(f"not JSON serializable: {type(o).__name__}")


def dumps(obj) -> str:
    """Canonical JSON: sorted keys, no whitespace, Decimals as strings."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=_default)


def loads(s: str | None):
    return json.loads(s) if s else {}


def iso(dt: datetime) -> str:
    return dt.astimezone(UTC).isoformat(timespec="seconds")


def parse_dt(s: str) -> datetime:
    return datetime.fromisoformat(s)


class Clock:
    """Sandbox clock: real time plus an offset, or frozen (for tests).

    The demo can move time forward (cooling-off periods, quote expiry, mandate
    expiry) without waiting.
    """

    def __init__(self, start: datetime | None = None, frozen: bool = False):
        self._frozen = frozen
        self._start = start or datetime.now(UTC)
        self._real_start = datetime.now(UTC)
        self._offset = timedelta()

    def now(self) -> datetime:
        if self._frozen:
            return self._start + self._offset
        return self._start + (datetime.now(UTC) - self._real_start) + self._offset

    def advance(self, **kwargs) -> datetime:
        self._offset += timedelta(**kwargs)
        return self.now()
