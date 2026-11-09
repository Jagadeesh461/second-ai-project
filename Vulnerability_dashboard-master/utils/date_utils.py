from datetime import date, datetime


DATE_FORMATS = (
    "%Y-%m-%d", "%m/%d/%Y", "%m/%d/%y", "%d/%m/%Y", "%d-%m-%Y", "%d-%b-%Y",
    "%Y/%m/%d", "%b %d, %Y", "%B %d, %Y",
)


def parse_date(value: str | None) -> date | None:
    if not value or value.strip().upper() in {"N/A", "NA", "NULL", "NONE", "-"}:
        return None
    text = value.strip()
    for fmt in DATE_FORMATS:
        try:
            return datetime.strptime(text, fmt).date()
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).date()
    except ValueError:
        return None


def parse_number(value: str | None) -> float | None:
    if not value or value.strip().upper() in {"N/A", "NA", "NULL", "NONE", "-"}:
        return None
    try:
        return float(value.replace(",", "").strip())
    except (ValueError, AttributeError):
        return None


def parse_bool(value: str | None) -> bool | None:
    if not value or value.strip().upper() in {"N/A", "NA", "NULL", "NONE", "-"}:
        return None
    return value.strip().lower() in {"yes", "y", "true", "1", "required", "breached"}