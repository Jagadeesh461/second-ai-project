"""Detection keyword to RemitTeam resolution.

The keyword rules live in ``static/remit_team_mapping.json`` so they can be
updated without touching the code.
"""

import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[1]
MAPPING_PATH = BASE_DIR / "static" / "remit_team_mapping.json"
DEFAULT_REMIT_TEAM = "Other"

_cache: dict[str, str] | None = None


def load_mapping(path: Path | None = None, refresh: bool = False) -> dict[str, str]:
    """Return the keyword mapping with lower-cased keywords."""
    global _cache
    if path is None and _cache is not None and not refresh:
        return _cache
    source = path or MAPPING_PATH
    if not source.exists():
        mapping: dict[str, str] = {}
    else:
        raw = json.loads(source.read_text(encoding="utf-8"))
        mapping = {str(keyword).strip().lower(): str(team).strip() for keyword, team in raw.items() if str(keyword).strip()}
    if path is None:
        _cache = mapping
    return mapping


def resolve_remit_team(detection: str, mapping: dict[str, str] | None = None) -> str:
    """Match ``detection`` against the keyword rules, case-insensitively.

    When several keywords match, the longest (most specific) keyword wins.
    """
    rules = load_mapping() if mapping is None else mapping
    text = (detection or "").strip().lower()
    if not text:
        return DEFAULT_REMIT_TEAM
    matches = [keyword for keyword in rules if keyword and keyword in text]
    if not matches:
        return DEFAULT_REMIT_TEAM
    best = max(matches, key=len)
    return rules[best] or DEFAULT_REMIT_TEAM
