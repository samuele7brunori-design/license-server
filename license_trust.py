"""Pinned public trust anchors for TapeSense license leases.

Public keys are safe to distribute.  Production builds must populate this map
and the packaging pipeline must reject an empty map.  Development can inject
keys through TAPESENSE_LICENSE_PUBLIC_KEYS_JSON; frozen builds deliberately
ignore that environment variable so a local user cannot replace trust roots.
"""
from __future__ import annotations

import json
import os
import sys


EMBEDDED_LICENSE_PUBLIC_KEYS: dict[str, str] = {
    "license-signing-2026-02": "bIZPkd7BArPdqB7OthT345V3o9DsE4qTQOhvK5e9-bY",
}


def get_trusted_license_public_keys() -> dict[str, str]:
    keys = dict(EMBEDDED_LICENSE_PUBLIC_KEYS)
    if not getattr(sys, "frozen", False):
        raw = os.environ.get("TAPESENSE_LICENSE_PUBLIC_KEYS_JSON", "")
        if raw:
            parsed = json.loads(raw)
            if not isinstance(parsed, dict) or not all(
                isinstance(key, str) and isinstance(value, str)
                for key, value in parsed.items()
            ):
                raise RuntimeError("TAPESENSE_LICENSE_PUBLIC_KEYS_JSON non valido")
            keys.update(parsed)
    return keys
