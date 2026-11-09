"""RemitTeam to Group resolution.

The mapping lives in ``static/group_mapping.json`` so it can be updated
without touching the code. Any ``RemitTeam`` value not present in the
mapping falls back to ``DEFAULT_GROUP``.
"""

import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[1]
MAPPING_PATH = BASE_DIR / "static" / "group_mapping.json"
DEFAULT_GROUP = "Suncorp Group"

_cache: dict[str, str] | None = None


def load_mapping(path: Path | None = None, refresh: bool = False) -> dict[str, str]:
    """Return the RemitTeam -> Group mapping with lower-cased keys."""
    global _cache
    if path is None and _cache is not None and not refresh:
        return _cache
    source = path or MAPPING_PATH
    if not source.exists():
        mapping: dict[str, str] = {}
    else:
        raw = json.loads(source.read_text(encoding="utf-8"))
        mapping = {str(team).strip().lower(): str(group).strip() for team, group in raw.items() if str(team).strip()}
    if path is None:
        _cache = mapping
    return mapping


def resolve_group(remit_team: str, mapping: dict[str, str] | None = None) -> str:
    """Resolve ``remit_team`` to its Group, defaulting to ``Suncorp Group``."""
    rules = load_mapping() if mapping is None else mapping
    text = (remit_team or "").strip().lower()
    if not text:
        return DEFAULT_GROUP
    return rules.get(text) or DEFAULT_GROUP
