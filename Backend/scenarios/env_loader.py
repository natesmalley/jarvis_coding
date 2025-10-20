#!/usr/bin/env python3
"""
Simple .env loader to populate os.environ without external deps.
Parses KEY=VALUE lines, ignoring comments and blanks.
"""

import os
from pathlib import Path


def _parse_line(line: str):
    line = line.strip()
    if not line or line.startswith("#"):
        return None, None
    if line.lower().startswith("export "):
        line = line[len("export "):]
    if "=" not in line:
        return None, None
    key, val = line.split("=", 1)
    key = key.strip()
    val = val.strip().strip('"').strip("'")
    return key, val


def load_env_if_present(env_path: str = ".env") -> None:
    path = Path(env_path)
    if not path.is_file():
        return
    try:
        with path.open("r") as f:
            for raw in f:
                k, v = _parse_line(raw)
                if k and v and k not in os.environ:
                    os.environ[k] = v
    except Exception:
        # Fail silently; scripts still can rely on existing environment
        pass

