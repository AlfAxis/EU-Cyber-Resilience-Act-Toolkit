"""``status``: deadline countdown for open Article 14 cases plus register completeness."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from cra_toolkit.i18n import t
from cra_toolkit.register import (
    Check,
    Product,
    Register,
    advisories,
    check_product,
    recommendations,
)
from cra_toolkit.reports import STAGES, Case, CaseStore, Deadline, compute_deadlines
from cra_toolkit.store import DataDir
from cra_toolkit.timeutil import format_datetime, format_duration, to_iso


@dataclass
class CaseStatus:
    case: Case
    rows: list[tuple[Deadline, str]]


@dataclass
class ProductStatus:
    product: Product
    checks: list[Check]
    recommended: list[Check]
    notes: list[str]

    @property
    def done(self) -> int:
        return sum(1 for check in self.checks if check.ok)

    @property
    def total(self) -> int:
        return len(self.checks)

    @property
    def complete(self) -> bool:
        return self.done == self.total


@dataclass
class Status:
    now: datetime
    cases: list[CaseStatus]
    products: list[ProductStatus]

    @property
    def overdue(self) -> int:
        return sum(1 for cs in self.cases for _, state in cs.rows if state == "overdue")

    @property
    def incomplete_products(self) -> int:
        return sum(1 for ps in self.products if not ps.complete)


def build_status(data_dir: DataDir, now: datetime) -> Status:
    cases = [
        CaseStatus(case, [(d, d.state(now)) for d in compute_deadlines(case)])
        for case in CaseStore(data_dir.cases_dir).list()
    ]
    register = Register.load(data_dir.register_file)
    products = [
        ProductStatus(
            product,
            check_product(product),
            recommendations(product),
            advisories(product, now.date()),
        )
        for product in sorted(register.products.values(), key=lambda p: p.id)
    ]
    return Status(now, cases, products)


def _state_text(deadline: Deadline, state: str, now: datetime) -> str:
    due = format_datetime(deadline.due) if deadline.due else ""
    if state == "filed":
        assert deadline.filed_at is not None
        return t("state.filed", at=format_datetime(deadline.filed_at))
    if state == "filed_late":
        assert deadline.filed_at is not None
        return t("state.filed_late", at=format_datetime(deadline.filed_at), due=due)
    if state == "overdue":
        assert deadline.due is not None
        return t("state.overdue", span=format_duration(now - deadline.due), due=due)
    if state == "open":
        assert deadline.due is not None
        return t("state.open", due=due, span=format_duration(deadline.due - now))
    return t(f"basis.{deadline.basis}")


def render_status(status: Status) -> str:
    lines = [t("status.title", now=format_datetime(status.now)), ""]

    lines.append(t("status.cases_heading", overdue=status.overdue))
    if not status.cases:
        lines.append(f"  {t('status.no_cases')}")
    for cs in status.cases:
        lines.append(f"  {cs.case.id}  [{cs.case.product_id}]  {cs.case.reference}")
        for deadline, state in cs.rows:
            label = t(f"stage.{deadline.stage}")
            lines.append(f"    {label:<18} {_state_text(deadline, state, status.now)}")
    lines.append("")

    lines.append(t("status.register_heading", incomplete=status.incomplete_products))
    if not status.products:
        lines.append(f"  {t('status.no_products')}")
    for ps in status.products:
        percent = round(100 * ps.done / ps.total) if ps.total else 100
        lines.append(
            f"  {ps.product.id}  {ps.product.name} {ps.product.version} — "
            f"{t('status.completeness', done=ps.done, total=ps.total, percent=percent)}"
        )
        for tag, group in (("status.missing", ps.checks), ("status.recommended", ps.recommended)):
            for check in group:
                if not check.ok:
                    what, cite = t(f"check.{check.name}"), t(f"ref.{check.reference}")
                    lines.append(f"    [{t(tag)}] {what} ({cite})")
        lines.extend(f"    {t('status.hint')}: {note}" for note in ps.notes)
    return "\n".join(lines) + "\n"


def status_to_dict(status: Status) -> dict[str, Any]:
    return {
        "generated_at": to_iso(status.now),
        "overdue_deadlines": status.overdue,
        "incomplete_products": status.incomplete_products,
        "cases": [
            {
                "id": cs.case.id,
                "product": cs.case.product_id,
                "reference": cs.case.reference,
                "kind": cs.case.kind,
                "deadlines": [
                    {
                        "stage": deadline.stage,
                        "due": to_iso(deadline.due) if deadline.due else None,
                        "basis": deadline.basis,
                        "state": state,
                        "filed_at": to_iso(deadline.filed_at) if deadline.filed_at else None,
                    }
                    for deadline, state in cs.rows
                ],
            }
            for cs in status.cases
        ],
        "products": [
            {
                "id": ps.product.id,
                "completeness": {"done": ps.done, "total": ps.total},
                "missing": [c.name for c in ps.checks if not c.ok],
                "recommended_missing": [c.name for c in ps.recommended if not c.ok],
            }
            for ps in status.products
        ],
    }


__all__ = ["STAGES", "Status", "build_status", "render_status", "status_to_dict"]
