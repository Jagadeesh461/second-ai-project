from datetime import date, timedelta


SLA_DAYS = {"Critical": 7, "High": 30, "Medium": 60, "Low": 90}
AGING_BUCKETS = ("0-7 Days", "8-30 Days", "31-60 Days", "61-90 Days", "91-180 Days", "181-365 Days", "365+ Days")


def normalize_severity(value: str) -> str:
    normalized = value.strip().lower()
    for severity in SLA_DAYS:
        if normalized == severity.lower():
            return severity
    if normalized in {"sev1", "p1"}:
        return "Critical"
    if normalized in {"sev2", "p2"}:
        return "High"
    if normalized in {"sev3", "p3"}:
        return "Medium"
    if normalized in {"sev4", "p4"}:
        return "Low"
    if normalized in {"4", "5"}:
        return "Critical"
    if normalized == "3":
        return "High"
    if normalized == "2":
        return "Medium"
    if normalized == "1":
        return "Low"
    return "Unknown"


def normalize_status(value: str) -> str:
    normalized = value.strip().lower().replace("_", " ")
    if normalized in {"in progress", "in-progress", "working", "open - in progress"}:
        return "In Progress"
    if normalized in {"resolved", "fixed", "remediated"}:
        return "Resolved"
    if normalized in {"closed", "close"}:
        return "Closed"
    return "Open"


def aging_bucket(age_days: int) -> str:
    if age_days <= 7:
        return "0-7 Days"
    if age_days <= 30:
        return "8-30 Days"
    if age_days <= 60:
        return "31-60 Days"
    if age_days <= 90:
        return "61-90 Days"
    if age_days <= 180:
        return "91-180 Days"
    if age_days <= 365:
        return "181-365 Days"
    return "365+ Days"


def calculate_sla(first_detected: date | None, severity: str, status: str, resolution_date: date | None, today: date) -> dict:
    duration = SLA_DAYS.get(severity, 0)
    due_date = first_detected + timedelta(days=duration) if first_detected and duration else None
    evaluation_date = resolution_date if status in {"Resolved", "Closed"} and resolution_date else today
    overdue = bool(due_date and evaluation_date > due_date and status not in {"Resolved", "Closed"})
    breached = bool(due_date and evaluation_date > due_date)
    delta = (due_date - evaluation_date).days if due_date else 0
    return {
        "sla_days": duration,
        "sla_due_date": due_date,
        "sla_breached": breached,
        "overdue": overdue,
        "days_remaining": max(delta, 0),
        "days_overdue": max(-delta, 0),
    }