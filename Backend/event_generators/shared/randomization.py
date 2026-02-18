#!/usr/bin/env python3
"""
Randomization Service for Event Generators & Scenarios
=======================================================

Centralized randomization for IPs, names, and other fields.
Provides a RandomizationContext that caches assignments so the same
entity (e.g., a username) gets consistent values across all events
within a single run.

Usage:
    from shared.randomization import Randomizer

    r = Randomizer(seed=42)                       # reproducible
    r = Randomizer()                               # fully random

    # IPs
    r.internal_ip()                                # random from default private ranges
    r.internal_ip(cidr="10.50.0.0/16")            # constrained to a subnet
    r.external_ip()                                # random public IP (no reserved)

    # Names
    r.person()                                     # -> {"first": "Sara", "last": "Mitchell", ...}
    r.person(domain="starfleet.corp")              # email uses that domain

    # Consistent assignments via context
    r.assign("jeanluc", "ip", r.internal_ip)       # first call generates, subsequent return cached
    r.get("jeanluc", "ip")                         # retrieve without generating
"""

from __future__ import annotations

import ipaddress
import random
from dataclasses import dataclass, field
from typing import Any, Callable, Optional


# ---------------------------------------------------------------------------
# Default CIDR ranges
# ---------------------------------------------------------------------------

DEFAULT_INTERNAL_CIDRS = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
]

# Public ranges to sample from (major allocations, avoids reserved blocks)
_PUBLIC_RANGES = [
    ("100.128.0.0", "126.255.255.255"),
    ("198.20.0.0", "198.51.99.255"),
    ("198.51.101.0", "203.0.112.255"),
    ("203.0.114.0", "223.255.255.255"),
]

# ---------------------------------------------------------------------------
# Name pools
# ---------------------------------------------------------------------------

FIRST_NAMES = [
    "James", "Mary", "Robert", "Patricia", "John", "Jennifer", "Michael",
    "Linda", "David", "Elizabeth", "William", "Barbara", "Richard", "Susan",
    "Joseph", "Jessica", "Thomas", "Sarah", "Christopher", "Karen",
    "Charles", "Lisa", "Daniel", "Nancy", "Matthew", "Betty", "Anthony",
    "Margaret", "Mark", "Sandra", "Donald", "Ashley", "Steven", "Kimberly",
    "Paul", "Emily", "Andrew", "Donna", "Joshua", "Michelle", "Kenneth",
    "Carol", "Kevin", "Amanda", "Brian", "Dorothy", "George", "Melissa",
    "Timothy", "Deborah", "Ronald", "Stephanie", "Edward", "Rebecca",
    "Jason", "Sharon", "Jeffrey", "Laura", "Ryan", "Cynthia",
    "Jacob", "Kathleen", "Gary", "Amy", "Nicholas", "Angela", "Eric",
    "Shirley", "Jonathan", "Anna", "Stephen", "Brenda", "Larry", "Pamela",
    "Justin", "Emma", "Scott", "Nicole", "Brandon", "Helen", "Benjamin",
    "Samantha", "Samuel", "Katherine", "Raymond", "Christine", "Gregory",
    "Debra", "Frank", "Rachel", "Alexander", "Carolyn", "Patrick", "Janet",
    "Jack", "Catherine", "Dennis", "Maria", "Jerry", "Heather", "Tyler",
    "Diane",
]

LAST_NAMES = [
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller",
    "Davis", "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez",
    "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Jackson", "Martin",
    "Lee", "Perez", "Thompson", "White", "Harris", "Sanchez", "Clark",
    "Ramirez", "Lewis", "Robinson", "Walker", "Young", "Allen", "King",
    "Wright", "Scott", "Torres", "Nguyen", "Hill", "Flores", "Green",
    "Adams", "Nelson", "Baker", "Hall", "Rivera", "Campbell", "Mitchell",
    "Carter", "Roberts", "Gomez", "Phillips", "Evans", "Turner", "Diaz",
    "Parker", "Cruz", "Edwards", "Collins", "Reyes", "Stewart", "Morris",
    "Morales", "Murphy", "Cook", "Rogers", "Gutierrez", "Ortiz", "Morgan",
    "Cooper", "Peterson", "Bailey", "Reed", "Kelly", "Howard", "Ramos",
    "Kim", "Cox", "Ward", "Richardson", "Watson", "Brooks", "Chavez",
    "Wood", "James", "Bennett", "Gray", "Mendoza", "Ruiz", "Hughes",
    "Price", "Alvarez", "Castillo", "Sanders", "Patel", "Myers", "Long",
    "Ross", "Foster", "Jimenez",
]

DEPARTMENTS = [
    "Engineering", "Security", "Finance", "Human Resources", "IT",
    "Operations", "Marketing", "Sales", "Legal", "Executive",
    "Research", "Support", "Product", "Data Science", "DevOps",
]

ROLES = [
    "Analyst", "Engineer", "Manager", "Director", "Specialist",
    "Administrator", "Coordinator", "Lead", "Architect", "Consultant",
]

LOCATIONS = [
    ("New York", "New York", "US"),
    ("San Francisco", "California", "US"),
    ("Austin", "Texas", "US"),
    ("Chicago", "Illinois", "US"),
    ("Denver", "Colorado", "US"),
    ("Seattle", "Washington", "US"),
    ("Boston", "Massachusetts", "US"),
    ("Los Angeles", "California", "US"),
    ("Atlanta", "Georgia", "US"),
    ("Dallas", "Texas", "US"),
    ("London", "England", "GB"),
    ("Berlin", "Brandenburg", "DE"),
    ("Paris", "Île-de-France", "FR"),
    ("Tokyo", "Tokyo", "JP"),
    ("Sydney", "New South Wales", "AU"),
    ("Toronto", "Ontario", "CA"),
    ("Mumbai", "Maharashtra", "IN"),
]


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class PersonInfo:
    """Generated person identity."""
    first_name: str
    last_name: str
    email: str
    username: str
    display_name: str
    department: str
    role: str
    location: tuple[str, str, str]  # (city, state, country_code)

    def to_dict(self) -> dict[str, Any]:
        city, state, country = self.location
        return {
            "first_name": self.first_name,
            "last_name": self.last_name,
            "email": self.email,
            "username": self.username,
            "display_name": self.display_name,
            "department": self.department,
            "role": self.role,
            "city": city,
            "state": state,
            "country": country,
        }


# ---------------------------------------------------------------------------
# Randomizer
# ---------------------------------------------------------------------------

class Randomizer:
    """Centralized randomization service with optional seed and context caching."""

    def __init__(
        self,
        seed: Optional[int] = None,
        ip_uniqueness_rate: float = 0.10,
        ip_pool_max_size: int = 10_000,
    ):
        self._rng = random.Random(seed)
        self._context: dict[str, dict[str, Any]] = {}
        self._internal_networks: list[ipaddress.IPv4Network] = [
            ipaddress.IPv4Network(cidr) for cidr in DEFAULT_INTERNAL_CIDRS
        ]
        self._used_names: set[str] = set()
        self._ip_uniqueness_rate = max(0.0, min(1.0, float(ip_uniqueness_rate)))
        self._ip_pool_max_size = max(0, int(ip_pool_max_size))
        self._ip_pools: dict[tuple[str, str], list[str]] = {}

    # ------------------------------------------------------------------
    # IP generation
    # ------------------------------------------------------------------

    def internal_ip(self, cidr: Optional[str] = None) -> str:
        """Generate a random private/internal IP address.

        Args:
            cidr: Optional CIDR string to constrain the range.
                  e.g. "10.50.0.0/16", "192.168.1.0/24"
                  If None, picks randomly from the three standard
                  private ranges.
        """
        network = ipaddress.IPv4Network(cidr, strict=False) if cidr else self._rng.choice(self._internal_networks)
        pool_key = ("internal", str(network))
        pool = self._ip_pools.get(pool_key, [])

        if pool and self._rng.random() >= self._ip_uniqueness_rate:
            return self._rng.choice(pool)

        num = network.num_addresses
        if num <= 2:
            ip_str = str(network.network_address)
        else:
            offset = self._rng.randint(1, num - 2)
            ip_str = str(network.network_address + offset)

        if self._ip_pool_max_size > 0:
            if len(pool) < self._ip_pool_max_size:
                if ip_str not in pool:
                    pool.append(ip_str)
                    self._ip_pools[pool_key] = pool
        return ip_str

    def external_ip(self) -> str:
        """Generate a random public/external IP address.

        Avoids all private, reserved, loopback, link-local,
        and documentation ranges.
        """
        pool_key = ("external", "default")
        pool = self._ip_pools.get(pool_key, [])

        if pool and self._rng.random() >= self._ip_uniqueness_rate:
            return self._rng.choice(pool)

        while True:
            start_str, end_str = self._rng.choice(_PUBLIC_RANGES)
            start_int = int(ipaddress.IPv4Address(start_str))
            end_int = int(ipaddress.IPv4Address(end_str))
            ip_int = self._rng.randint(start_int, end_int)
            addr = ipaddress.IPv4Address(ip_int)
            if not (addr.is_private or addr.is_reserved or addr.is_loopback):
                ip_str = str(addr)
                break

        if self._ip_pool_max_size > 0:
            if len(pool) < self._ip_pool_max_size:
                if ip_str not in pool:
                    pool.append(ip_str)
                    self._ip_pools[pool_key] = pool

        return ip_str

    def ip(self, internal: bool = True, cidr: Optional[str] = None) -> str:
        """Generate an IP — convenience wrapper.

        Args:
            internal: True for private, False for public.
            cidr: Only used when internal=True.
        """
        if internal:
            return self.internal_ip(cidr=cidr)
        return self.external_ip()

    # ------------------------------------------------------------------
    # Name generation
    # ------------------------------------------------------------------

    def person(
        self,
        domain: str = "company.com",
        department: Optional[str] = None,
        role: Optional[str] = None,
        location: Optional[tuple[str, str, str]] = None,
        unique: bool = True,
    ) -> PersonInfo:
        """Generate a random person identity.

        Args:
            domain: Email domain.
            department: Force a specific department, or random.
            role: Force a specific role, or random.
            location: Force (city, state, country) tuple, or random.
            unique: If True, avoids repeating the same first+last combo
                    within this Randomizer instance.
        """
        max_attempts = 200
        for _ in range(max_attempts):
            first = self._rng.choice(FIRST_NAMES)
            last = self._rng.choice(LAST_NAMES)
            key = f"{first.lower()}.{last.lower()}"
            if not unique or key not in self._used_names:
                break
        else:
            # Exhausted attempts — allow duplicates
            first = self._rng.choice(FIRST_NAMES)
            last = self._rng.choice(LAST_NAMES)
            key = f"{first.lower()}.{last.lower()}"

        self._used_names.add(key)

        username = f"{first.lower()}.{last.lower()}"
        email = f"{username}@{domain}"
        display_name = f"{first} {last}"
        dept = department or self._rng.choice(DEPARTMENTS)
        r = role or self._rng.choice(ROLES)
        loc = location or self._rng.choice(LOCATIONS)

        return PersonInfo(
            first_name=first,
            last_name=last,
            email=email,
            username=username,
            display_name=display_name,
            department=dept,
            role=r,
            location=loc,
        )

    def first_name(self) -> str:
        """Generate a random first name."""
        return self._rng.choice(FIRST_NAMES)

    def last_name(self) -> str:
        """Generate a random last name."""
        return self._rng.choice(LAST_NAMES)

    def email(self, first: Optional[str] = None, last: Optional[str] = None,
              domain: str = "company.com") -> str:
        """Generate an email address from name parts."""
        f = (first or self._rng.choice(FIRST_NAMES)).lower()
        l = (last or self._rng.choice(LAST_NAMES)).lower()
        return f"{f}.{l}@{domain}"

    def username(self, first: Optional[str] = None,
                 last: Optional[str] = None) -> str:
        """Generate a username from name parts."""
        f = (first or self._rng.choice(FIRST_NAMES)).lower()
        l = (last or self._rng.choice(LAST_NAMES)).lower()
        return f"{f}.{l}"

    # ------------------------------------------------------------------
    # Context / assignment caching
    # ------------------------------------------------------------------

    def assign(self, entity: str, field_name: str,
               generator: Callable[..., Any], *args: Any,
               **kwargs: Any) -> Any:
        """Assign a value to an entity+field, caching the result.

        If the entity+field already has a cached value, return it.
        Otherwise call generator(*args, **kwargs), cache, and return.

        Args:
            entity: Identifier for the entity (e.g. "jeanluc", "victim").
            field_name: Name of the field (e.g. "ip", "name").
            generator: Callable that produces the value.
            *args, **kwargs: Passed to generator on first call.

        Returns:
            The cached or newly generated value.
        """
        if entity not in self._context:
            self._context[entity] = {}

        if field_name not in self._context[entity]:
            self._context[entity][field_name] = generator(*args, **kwargs)

        return self._context[entity][field_name]

    def get(self, entity: str, field_name: str,
            default: Any = None) -> Any:
        """Retrieve a previously assigned value.

        Returns default if not found.
        """
        return self._context.get(entity, {}).get(field_name, default)

    def set(self, entity: str, field_name: str, value: Any) -> None:
        """Manually set a cached value for an entity+field."""
        if entity not in self._context:
            self._context[entity] = {}
        self._context[entity][field_name] = value

    def context_snapshot(self) -> dict[str, dict[str, Any]]:
        """Return a copy of the full context for debugging/logging."""
        return {k: dict(v) for k, v in self._context.items()}

    def reset(self) -> None:
        """Clear all cached assignments and used names."""
        self._context.clear()
        self._used_names.clear()
