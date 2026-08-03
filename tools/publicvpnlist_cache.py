"""Pure PublicVPNList cache predicates shared by the manager and ``en``.

This module deliberately has no network, service, proxy, or thread side effects.
"""

from __future__ import annotations

import math
import re
import time
from pathlib import Path
from typing import Any


ALLOWED_COUNTRIES = frozenset({"PH", "US", "FR", "GB", "ID", "FI", "DE", "TW", "AU", "NL"})
DEFAULT_STALE_PROFILE_SECONDS = 7 * 24 * 3600


def resolve_vpngate_data_dir(raw_value: Any, install_dir: Any) -> Path:
    """Resolve the data directory with one rule for the manager and ``en``."""

    install_path = Path(install_dir).expanduser().resolve()
    raw = str(raw_value or "").strip()
    if not raw:
        return (install_path / "vpngate_data").resolve()
    path = Path(raw).expanduser()
    if not path.is_absolute():
        path = install_path / path
    return path.resolve()


def stale_profile_seconds(value: Any, default: int = DEFAULT_STALE_PROFILE_SECONDS) -> int:
    try:
        parsed = int(str(value or ""))
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default


def looks_like_openvpn_config(text: Any) -> bool:
    if not isinstance(text, str) or not text.strip():
        return False
    lower = text.lower()
    has_remote = re.search(r"(?m)^\s*remote\s+\S+\s+\d+", lower) is not None
    has_tunnel = re.search(r"(?m)^\s*dev\s+(tun|tap)\b", lower) is not None
    has_proto = re.search(r"(?m)^\s*proto\s+(tcp|udp)\b", lower) is not None
    has_cert = "<ca>" in lower or "-----begin certificate-----" in lower
    return has_remote and has_cert and ("client" in lower[:1200] or (has_tunnel and has_proto))


def profile_is_usable(
    profile: Any,
    now: float | None = None,
    stale_seconds: int = DEFAULT_STALE_PROFILE_SECONDS,
) -> bool:
    if not isinstance(profile, dict):
        return False
    country = str(profile.get("country_short") or "").strip().upper()
    if country not in ALLOWED_COUNTRIES:
        return False
    if not looks_like_openvpn_config(profile.get("config_text")):
        return False
    timestamp = profile.get("last_seen_at")
    if timestamp in (None, "", 0):
        timestamp = profile.get("config_validated_at")
    try:
        timestamp_value = float(timestamp)
    except (TypeError, ValueError):
        return False
    if not math.isfinite(timestamp_value) or timestamp_value <= 0:
        return False
    current = time.time() if now is None else now
    return current - timestamp_value < stale_profile_seconds


def cache_profile_summary(
    cache: Any,
    now: float | None = None,
    stale_seconds: int = DEFAULT_STALE_PROFILE_SECONDS,
) -> tuple[int, int]:
    """Return ``(record_count, usable_count)`` using the cache-only predicate."""

    if not isinstance(cache, dict):
        return 0, 0
    profiles = cache.get("profiles")
    if not isinstance(profiles, dict):
        return 0, 0
    count = sum(1 for profile in profiles.values() if isinstance(profile, dict))
    usable = sum(
        1
        for profile in profiles.values()
        if profile_is_usable(profile, now=now, stale_seconds=stale_seconds)
    )
    return count, usable
