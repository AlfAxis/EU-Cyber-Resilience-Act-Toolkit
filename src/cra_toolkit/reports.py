"""Article 14 reporting: cases, deadlines and report drafts.

A *case* records one actively exploited vulnerability (Art. 14(1)-(2)) or one
severe incident (Art. 14(3)-(4)) from the moment the manufacturer became aware
of it. Deadlines are derived from the case:

=================  ==============================  ==============================
Stage              Actively exploited vulnerability  Severe incident
=================  ==============================  ==============================
early warning      24 h after awareness              24 h after awareness
notification       72 h after awareness              72 h after awareness
final report       14 days after a corrective or     1 month after the incident
                   mitigating measure is available   notification was submitted
=================  ==============================  ==============================

The toolkit only *drafts* reports; submission happens on the single reporting
platform (Art. 16) and is recorded here with ``report filed``.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cra_toolkit.errors import ToolkitError
from cra_toolkit.i18n import has, t
from cra_toolkit.register import Product
from cra_toolkit.store import read_json, slugify, write_json
from cra_toolkit.timeutil import add_months, format_datetime, from_iso, to_iso

KINDS = ("vulnerability", "incident")
STAGES = ("early-warning", "notification", "final-report")

#: Free-text case fields that feed the drafts, editable via ``report open/update``.
TEXT_FIELDS = (
    "component",
    "summary",
    "exploitation",
    "actor",
    "measures_taken",
    "user_measures",
    "sensitivity",
    "severity",
    "impact",
    "update_details",
    "root_cause",
    "malicious_suspected",
)

# Which case fields each draft contains, in order. ``product_info`` and
# ``member_states`` are computed from the register.
_DRAFT_FIELDS: dict[tuple[str, str], tuple[str, ...]] = {
    ("vulnerability", "early-warning"): ("summary", "component", "member_states"),
    ("incident", "early-warning"): ("summary", "malicious_suspected", "member_states"),
    ("vulnerability", "notification"): (
        "product_info",
        "summary",
        "exploitation",
        "measures_taken",
        "user_measures",
        "sensitivity",
    ),
    ("incident", "notification"): (
        "product_info",
        "summary",
        "severity",
        "measures_taken",
        "user_measures",
        "sensitivity",
    ),
    ("vulnerability", "final-report"): ("summary", "severity", "impact", "actor", "update_details"),
    ("incident", "final-report"): ("summary", "severity", "impact", "root_cause", "measures_taken"),
}


@dataclass
class Case:
    id: str
    kind: str
    product_id: str
    reference: str
    aware_at: str
    fix_available_at: str | None = None
    component: str | None = None
    summary: str | None = None
    exploitation: str | None = None
    actor: str | None = None
    measures_taken: str | None = None
    user_measures: str | None = None
    sensitivity: str | None = None
    severity: str | None = None
    impact: str | None = None
    update_details: str | None = None
    root_cause: str | None = None
    malicious_suspected: str | None = None
    filings: dict[str, dict[str, str | None]] = field(default_factory=dict)
    created_at: str = ""
    updated_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Case:
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass(frozen=True)
class Deadline:
    stage: str
    due: datetime | None
    basis: (
        str  # awareness | fix_available | pending_fix | notification_filed | pending_notification
    )
    filed_at: datetime | None
    filing_reference: str | None

    def state(self, now: datetime) -> str:
        """``filed`` | ``filed_late`` | ``pending`` | ``overdue`` | ``open``."""
        if self.filed_at is not None:
            if self.due is not None and self.filed_at > self.due:
                return "filed_late"
            return "filed"
        if self.due is None:
            return "pending"
        return "overdue" if now > self.due else "open"


def _filing(case: Case, stage: str) -> tuple[datetime | None, str | None]:
    entry = case.filings.get(stage) or {}
    filed = entry.get("filed_at")
    return (from_iso(filed) if filed else None, entry.get("reference"))


def compute_deadlines(case: Case) -> list[Deadline]:
    aware = from_iso(case.aware_at)
    early_at, early_ref = _filing(case, "early-warning")
    notif_at, notif_ref = _filing(case, "notification")
    final_at, final_ref = _filing(case, "final-report")

    if case.kind == "vulnerability":
        if case.fix_available_at:
            final_due: datetime | None = from_iso(case.fix_available_at) + timedelta(days=14)
            basis = "fix_available"
        else:
            final_due, basis = None, "pending_fix"
    elif notif_at is not None:
        final_due, basis = add_months(notif_at, 1), "notification_filed"
    else:
        final_due, basis = None, "pending_notification"

    return [
        Deadline("early-warning", aware + timedelta(hours=24), "awareness", early_at, early_ref),
        Deadline("notification", aware + timedelta(hours=72), "awareness", notif_at, notif_ref),
        Deadline("final-report", final_due, basis, final_at, final_ref),
    ]


# ------------------------------------------------------------------- storage


class CaseStore:
    def __init__(self, directory: Path) -> None:
        self.directory = directory

    def _path(self, case_id: str) -> Path:
        return self.directory / f"{case_id}.json"

    def list(self) -> list[Case]:
        if not self.directory.is_dir():
            return []
        cases = [Case.from_dict(read_json(p)) for p in sorted(self.directory.glob("*.json"))]
        return sorted(cases, key=lambda c: (from_iso(c.aware_at), c.id))

    def get(self, case_id: str) -> Case:
        path = self._path(case_id)
        if not path.is_file():
            known = ", ".join(c.id for c in self.list()) or t("note.none")
            raise ToolkitError(t("err.unknown_case", id=case_id, known=known))
        return Case.from_dict(read_json(path))

    def save(self, case: Case) -> None:
        case.updated_at = to_iso(datetime.now(timezone.utc))
        write_json(self._path(case.id), case.to_dict())

    def new_id(self, aware: datetime, reference: str) -> str:
        base = f"{aware.astimezone(timezone.utc):%Y-%m-%d}-{slugify(reference)}"
        candidate, counter = base, 1
        while self._path(candidate).exists():
            counter += 1
            candidate = f"{base}-{counter}"
        return candidate


def mark_filed(case: Case, stage: str, at: datetime, reference: str | None) -> None:
    case.filings[stage] = {"filed_at": to_iso(at), "reference": reference}


# ---------------------------------------------------------------- draft text


@dataclass(frozen=True)
class Draft:
    text: str
    missing: list[str]


def _label(name: str, kind: str) -> str:
    specific = f"field.{name}.{kind}"
    return t(specific if has(specific) else f"field.{name}")


def _describe_deadline(deadline: Deadline) -> str:
    if deadline.due is not None:
        return f"{format_datetime(deadline.due)} — {t(f'basis.{deadline.basis}')}"
    return t(f"basis.{deadline.basis}")


def render_draft(case: Case, product: Product, stage: str) -> Draft:
    """Render the Markdown draft for ``stage``; unknown facts become visible placeholders."""
    if stage not in STAGES:
        raise ToolkitError(t("err.unknown_stage", stage=stage))
    placeholder = t("draft.placeholder")
    missing: list[str] = []
    deadline = next(d for d in compute_deadlines(case) if d.stage == stage)
    aware = from_iso(case.aware_at)

    def value_of(name: str) -> str:
        if name == "product_info":
            classification = (
                t(f"class.{product.classification}") if product.classification else placeholder
            )
            return "\n".join(
                [
                    f"- {t('draft.product')}: {product.name}",
                    f"- {t('draft.version')}: {product.version}",
                    f"- {t('draft.type')}: {product.product_type}",
                    f"- {t('draft.classification')}: {classification}",
                ]
            )
        if name == "member_states":
            return ", ".join(product.markets) or placeholder
        return str(getattr(case, name) or "").strip() or placeholder

    legal = t(f"legal.{case.kind}.{stage}")
    lines = [
        f"# {t(f'draft.title.{case.kind}.{stage}')}",
        "",
        f"> **{t('draft.banner')}**",
        f"> {t('draft.disclaimer')}",
        "",
        f"| {t('draft.field')} | {t('draft.entry')} |",
        "|---|---|",
        f"| {t('draft.manufacturer')} | {product.manufacturer.name} |",
        f"| {t('draft.product')} / {t('draft.version')} | {product.name} / {product.version} |",
        f"| {t('draft.reference')} | {case.reference} |",
        f"| {t('draft.aware_at')} | {format_datetime(aware)} |",
        f"| {t('draft.deadline')} | {_describe_deadline(deadline)} |",
        f"| {t('draft.legal_basis')} | {legal} |",
        f"| {t('draft.case_id')} | `{case.id}` |",
        "",
    ]
    for name in _DRAFT_FIELDS[(case.kind, stage)]:
        value = value_of(name)
        label = _label(name, case.kind)
        if placeholder in value:
            missing.append(label)
        lines += [f"## {label}", "", value, ""]

    lines += [f"## {t('draft.notes')}", ""]
    lines += [f"- {t(key)}" for key in _notes(case.kind, stage)]
    lines.append("")
    return Draft("\n".join(lines), missing)


def _notes(kind: str, stage: str) -> list[str]:
    notes = ["note.not_filed", "note.platform"]
    if stage in ("notification", "final-report"):
        notes.append("note.unless_provided")
    if kind == "vulnerability" and stage == "final-report":
        notes.append("note.final_after_fix")
    if kind == "incident" and stage == "final-report":
        notes.append("note.final_after_notification")
    notes += ["note.inform_users", "note.legal_determination"]
    return notes
