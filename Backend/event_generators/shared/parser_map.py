"""Lightweight loader for sourcetype mappings from the parsers tree.

Builds a map of product name -> sourcetype using directory names:
- community: community-<name>-latest
- marketplace: marketplace-<name>-latest

Falls back gracefully if folders are missing.
"""
from __future__ import annotations

import os
from typing import Dict, Iterable


def _scan_root(root: str, subdirs: Iterable[str]) -> Dict[str, str]:
    mapping: Dict[str, str] = {}
    for sub in subdirs:
        base = os.path.join(root, sub)
        if not os.path.isdir(base):
            continue
        try:
            for entry in os.listdir(base):
                if not entry.endswith("-latest"):
                    continue
                name = entry[:-len("-latest")]
                product = name  # product key matches folder prefix
                sourcetype = f"{sub}-{entry}"
                mapping[product] = sourcetype
        except Exception:
            # Non-fatal; just skip unreadable directories
            continue
    return mapping


def load_sourcetypes(parsers_dir: str) -> Dict[str, str]:
    """Load sourcetype mapping by scanning known parser locations.

    Args:
        parsers_dir: Path to the repository `parsers` directory.

    Returns:
        Dict mapping product (e.g., "paloalto_firewall") to sourcetype
        (e.g., "community-paloaltofirewall-latest").
    """
    if not os.path.isdir(parsers_dir):
        return {}

    # Known parser groups to scan. Include *_new variants if present.
    subdirs = []
    for name in (
        "community",
        "marketplace",
        "community_new",
        "sentinelone",  # marketplace and official bundles under sentinelone/
    ):
        if os.path.isdir(os.path.join(parsers_dir, name)):
            subdirs.append(name)

    mapping = _scan_root(parsers_dir, subdirs)
    return mapping
