"""Date/time helpers.

Article 14 deadlines are legal deadlines, so time handling is deliberately
strict: every instant is timezone-aware, 24 h means 24 clock hours (weekends
and public holidays do not pause the clock), and "one month" is a calendar
month.
"""

from __future__ import annotations

import calendar
from datetime import date, datetime, timedelta, timezone

from cra_toolkit.errors import ToolkitError
from cra_toolkit.i18n import get_language, t


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def now_local() -> datetime:
    """Current time as an aware datetime in the machine's timezone (for display)."""
    return datetime.now(timezone.utc).astimezone()


def parse_datetime(text: str) -> tuple[datetime, bool]:
    """Parse an ISO 8601 timestamp.

    Returns ``(value, assumed_local)``. A timestamp without UTC offset is
    interpreted in the machine's local timezone and flagged, so the caller can
    tell the user which assumption was made.
    """
    raw = text.strip()
    if raw[-1:] in ("Z", "z"):
        raw = raw[:-1] + "+00:00"
    if len(raw) <= 10:
        raise ToolkitError(t("err.datetime_needs_time", value=text))
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise ToolkitError(t("err.bad_datetime", value=text)) from exc
    if parsed.tzinfo is None:
        return parsed.astimezone(), True
    return parsed, False


def parse_date(text: str) -> date:
    try:
        return date.fromisoformat(text.strip())
    except ValueError as exc:
        raise ToolkitError(t("err.bad_date", value=text)) from exc


def to_iso(value: datetime) -> str:
    return value.isoformat(timespec="seconds")


def from_iso(text: str) -> datetime:
    """Read back a timestamp that was written by :func:`to_iso`."""
    return datetime.fromisoformat(text)


def add_months(value: datetime, months: int) -> datetime:
    """Add calendar months, clamping the day (31 Jan + 1 month = 28/29 Feb)."""
    index = value.month - 1 + months
    year = value.year + index // 12
    month = index % 12 + 1
    day = min(value.day, calendar.monthrange(year, month)[1])
    return value.replace(year=year, month=month, day=day)


def utc_offset_label(value: datetime) -> str:
    offset = value.utcoffset() or timedelta(0)
    minutes = int(offset.total_seconds() // 60)
    sign = "+" if minutes >= 0 else "-"
    hours, mins = divmod(abs(minutes), 60)
    return f"UTC{sign}{hours:02d}:{mins:02d}"


def format_datetime(value: datetime) -> str:
    """Human-readable timestamp including its UTC offset."""
    pattern = "%d.%m.%Y %H:%M" if get_language() == "de" else "%Y-%m-%d %H:%M"
    return f"{value.strftime(pattern)} ({utc_offset_label(value)})"


def format_date(value: date) -> str:
    return value.strftime("%d.%m.%Y" if get_language() == "de" else "%Y-%m-%d")


def format_duration(delta: timedelta) -> str:
    """Format the absolute length of ``delta`` as days/hours/minutes."""
    total_minutes = int(abs(delta.total_seconds()) // 60)
    days, rest = divmod(total_minutes, 24 * 60)
    hours, minutes = divmod(rest, 60)
    if days:
        return t("time.days_hours", days=days, hours=hours)
    if hours:
        return t("time.hours_minutes", hours=hours, minutes=minutes)
    return t("time.minutes", minutes=minutes)
