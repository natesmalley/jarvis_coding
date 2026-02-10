#!/usr/bin/env python3
"""Generator utilities for mock data.

Provides common functions for weighted random selection, pagination,
and dynamic field generation for event generators.
"""

from __future__ import annotations

import copy
import random
import secrets
import string
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, TypeVar

T = TypeVar("T")


@dataclass
class PaginationResult:
    """Result of pagination operation."""

    items: list[dict[str, Any]]
    has_next_page: bool
    next_offset: int
    total_count: int


def generate_uuid() -> str:
    """Generate a random UUID string."""
    return str(uuid.uuid4())


def generate_uuid_hex() -> str:
    """Generate a UUID without dashes (hex format)."""
    return uuid.uuid4().hex


def generate_ip() -> str:
    """Generate a random IP address."""
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def generate_private_ip() -> str:
    """Generate a random private IP address (10.x.x.x range)."""
    return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def generate_email(domain: str = "example.com") -> str:
    """Generate a random email address."""
    username = "".join(random.choices(string.ascii_lowercase, k=8))
    return f"{username}@{domain}"


def generate_hostname() -> str:
    """Generate a random hostname."""
    prefix = random.choice(["web", "api", "app", "srv", "host", "node"])
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=4))
    domain = random.choice(["example.com", "test.local", "internal.net"])
    return f"{prefix}-{suffix}.{domain}"


def generate_country_code() -> str:
    """Generate a random country code."""
    return random.choice(["US", "GB", "DE", "FR", "JP", "AU", "CA", "IN", "BR", "CN", "RU", "KR"])


def generate_city() -> str:
    """Generate a random city name."""
    return random.choice([
        "New York", "San Francisco", "Chicago", "Austin", "Denver",
        "London", "Berlin", "Paris", "Tokyo", "Sydney", "Toronto",
        "Mumbai", "São Paulo", "Shanghai", "Moscow", "Seoul"
    ])


def generate_user_agent() -> str:
    """Generate a random user agent string."""
    return random.choice([
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    ])


def random_timestamp_between(start_time: datetime, end_time: datetime) -> datetime:
    """Generate a random timestamp between two dates."""
    delta = end_time - start_time
    random_seconds = random.random() * delta.total_seconds()
    return start_time + timedelta(seconds=random_seconds)


def random_timestamp_epoch(start_epoch: int, end_epoch: int) -> int:
    """Generate a random epoch timestamp between two epochs."""
    return random.randint(start_epoch, end_epoch)


def random_iso_timestamp(start_time: datetime, end_time: datetime) -> str:
    """Generate a random ISO format timestamp between two dates."""
    return random_timestamp_between(start_time, end_time).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def weighted_choice(items: dict[str, tuple[Any, float]]) -> Any:
    """Select an item based on weighted probability.

    Args:
        items: Dict mapping key to (item, weight) tuples.
               Weights should sum to 1.0 (or close to it).

    Returns:
        Selected item based on weighted random selection.
    """
    r = random.random()
    cumulative = 0.0
    for _key, (item, weight) in items.items():
        cumulative += weight
        if r < cumulative:
            return item
    # Return last item if we somehow exceed (floating point edge case)
    return list(items.values())[-1][0]


def weighted_choice_from_dict(templates: dict[str, Any], weights: dict[str, float]) -> Any:
    """Select a template based on weighted probability.

    Args:
        templates: Dict mapping key to template objects.
        weights: Dict mapping same keys to weight values (should sum to 1.0).

    Returns:
        Selected template based on weighted random selection.
    """
    keys = list(weights.keys())
    weight_values = [weights[k] for k in keys]
    selected_key = random.choices(keys, weights=weight_values, k=1)[0]
    return templates[selected_key]


def paginate(
    items: list[dict[str, Any]],
    limit: int = 100,
    offset: int = 0,
) -> PaginationResult:
    """Paginate a list of items.

    Args:
        items: Full list of items to paginate.
        limit: Maximum number of items per page.
        offset: Starting index.

    Returns:
        PaginationResult with paginated items and metadata.
    """
    total_count = len(items)
    end_index = min(offset + limit, total_count)
    paginated_items = items[offset:end_index]
    has_next_page = end_index < total_count
    next_offset = end_index if has_next_page else 0

    return PaginationResult(
        items=paginated_items,
        has_next_page=has_next_page,
        next_offset=next_offset,
        total_count=total_count,
    )


def deep_copy_with_updates(template: dict[str, Any], updates: dict[str, Any]) -> dict[str, Any]:
    """Create a deep copy of template and apply updates.

    Handles nested dict updates.
    """
    result = copy.deepcopy(template)
    for key, value in updates.items():
        if isinstance(value, dict) and key in result and isinstance(result[key], dict):
            result[key].update(value)
        else:
            result[key] = value
    return result


def generate_token(length: int = 32) -> str:
    """Generate a random hex token."""
    return secrets.token_hex(length)


def get_time_range(
    start_time: int | str | None = None,
    end_time: int | str | None = None,
    default_range_minutes: int = 120,
) -> tuple[datetime, datetime]:
    """Parse time range from query parameters.

    Args:
        start_time: Start time as epoch (int) or ISO string.
        end_time: End time as epoch (int) or ISO string.
        default_range_minutes: Default range if start_time not provided.

    Returns:
        Tuple of (start_datetime, end_datetime).
    """
    now = datetime.now(timezone.utc)

    if end_time is None:
        end_dt = now
    elif isinstance(end_time, int):
        end_dt = datetime.fromtimestamp(end_time, tz=timezone.utc)
    else:
        end_dt = datetime.fromisoformat(str(end_time).replace("Z", "+00:00"))

    if start_time is None:
        start_dt = end_dt - timedelta(minutes=default_range_minutes)
    elif isinstance(start_time, int):
        start_dt = datetime.fromtimestamp(start_time, tz=timezone.utc)
    else:
        start_dt = datetime.fromisoformat(str(start_time).replace("Z", "+00:00"))

    return start_dt, end_dt


def now_utc() -> datetime:
    """Get current UTC datetime."""
    return datetime.now(timezone.utc)


def now_iso() -> str:
    """Get current UTC time as ISO string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def now_epoch() -> int:
    """Get current UTC time as epoch seconds."""
    return int(datetime.now(timezone.utc).timestamp())


def generate_md5() -> str:
    """Generate a random MD5-like hash."""
    return secrets.token_hex(16)


def generate_sha256() -> str:
    """Generate a random SHA256-like hash."""
    return secrets.token_hex(32)


def generate_mac_address() -> str:
    """Generate a random MAC address."""
    return ":".join(f"{random.randint(0, 255):02x}" for _ in range(6))


if __name__ == "__main__":  # pragma: no cover
    # Simple demo
    print(f"UUID: {generate_uuid()}")
    print(f"IP: {generate_ip()}")
    print(f"Email: {generate_email()}")
    print(f"Hostname: {generate_hostname()}")
    print(f"ISO Timestamp: {now_iso()}")
