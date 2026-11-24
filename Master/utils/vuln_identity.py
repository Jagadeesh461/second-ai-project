"""Derived vulnerability identity columns used by processed reports."""

import re


# Values treated as "not populated" for CVE / VendorReference.
BLANK_IDENTIFIERS = {"", "n/a", "na", "null", "none", "unknown", "-"}
UNKNOWN_VULN_NAME = "Unknown"
EXPLOIT_PATTERN = re.compile(r"exploit|active", re.IGNORECASE)
# A keyword preceded by a negation in the same phrase ("No Known Exploit",
# "Not Actively Exploited") does not count as an exploit.
NEGATED_PATTERN = re.compile(r"\b(no|not|non|none|without)\b[^,;|]*?(exploit|active)", re.IGNORECASE)
PHRASE_SEPARATORS = re.compile(r"[,;|\n]+")


def is_exploit(threat_intel: str | None) -> bool:
    """True when any ThreatIntel phrase mentions "Exploit" or "Active" (case-insensitive)
    without being negated, so "Exploit Available" is TRUE and "No Known Exploit" is FALSE."""
    for phrase in PHRASE_SEPARATORS.split(threat_intel or ""):
        if EXPLOIT_PATTERN.search(phrase) and not NEGATED_PATTERN.search(phrase):
            return True
    return False


def _populated(value: str | None) -> str:
    text = (value or "").strip()
    return "" if text.lower() in BLANK_IDENTIFIERS else text


def unique_vuln_name(cve: str | None, vendor_reference: str | None) -> str:
    """COALESCE(CVE, VendorReference); "Unknown" only when both are blank."""
    return _populated(cve) or _populated(vendor_reference) or UNKNOWN_VULN_NAME


def vuln_count_key(server_name: str | None, app_space_name: str | None, unique_name: str | None) -> str:
    """VULN COUNT = ServerName + AppSpaceName + Unique Vuln Name."""
    return f"{server_name or ''}{app_space_name or ''}{unique_name or ''}"


def vul_key(
    app_space_id: str | None,
    app_space_name: str | None,
    server_name: str | None,
    environment: str | None,
    qid: str | None,
) -> str:
    """Stable weekly identity: AppSpaceId||AppSpaceName||ServerName||Environment||QID."""
    return "||".join((app_space_id or "", app_space_name or "", server_name or "", environment or "", qid or ""))


def record_unique_vuln_name(record) -> str:
    """Unique Vuln Name of a Vulnerability, derived from CVE/Vendor when not yet set."""
    return getattr(record, "unique_vuln_name", "") or unique_vuln_name(getattr(record, "cve", ""), getattr(record, "vendor", ""))
