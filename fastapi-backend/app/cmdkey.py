"""Stable short id for a command text, so identical commands can be grouped
and linked to (/api/commands/groups/{key}) without putting attacker text in a URL."""
import hashlib

KEY_PATTERN = r"^[0-9a-f]{24}$"


def cmd_key(text: str) -> str:
    return hashlib.sha256((text or "").strip().encode("utf-8", "replace")).hexdigest()[:24]
