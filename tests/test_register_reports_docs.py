from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pytest

from cra_toolkit.docs import render_annex_ii
from cra_toolkit.errors import ToolkitError
from cra_toolkit.i18n import set_language
from cra_toolkit.register import (
    EU_MEMBER_STATES,
    Manufacturer,
    Product,
    Register,
    advisories,
    check_product,
    default_product_id,
    parse_markets,
)
from cra_toolkit.reports import (
    Case,
    CaseStore,
    Deadline,
    compute_deadlines,
    mark_filed,
    render_draft,
)
from cra_toolkit.status import build_status, render_status
from cra_toolkit.store import DataDir
from cra_toolkit.timeutil import add_months, parse_datetime

CEST = timezone(timedelta(hours=2))


def full_product(**overrides: object) -> Product:
    product = Product(
        id="edge-gateway-2-1-0",
        name="Edge Gateway",
        version="2.1.0",
        manufacturer=Manufacturer(
            "Muster GmbH",
            "Musterstraße 1, 10115 Berlin",
            "psirt@muster.example",
            "https://muster.example",
        ),
        product_type="firmware",
        classification="important-class-1",
        vulnerability_contact="security@muster.example",
        cvd_policy_url="https://muster.example/cvd",
        support_period_end="2031-12-31",
        placed_on_market="2026-06-01",
        markets=["AT", "DE"],
        intended_purpose="Industrielles Edge-Gateway für Produktionsnetze",
    )
    for key, value in overrides.items():
        setattr(product, key, value)
    return product


def vuln_case(**overrides: object) -> Case:
    case = Case(
        id="2026-09-12-cve-2026-12345",
        kind="vulnerability",
        product_id="edge-gateway-2-1-0",
        reference="CVE-2026-12345",
        aware_at="2026-09-12T08:30:00+02:00",
    )
    for key, value in overrides.items():
        setattr(case, key, value)
    return case


# ------------------------------------------------------------------ register


def test_register_round_trip_and_errors(tmp_path: Path) -> None:
    path = tmp_path / "register.json"
    register = Register.load(path)
    register.add(full_product())
    register.save()
    reloaded = Register.load(path)
    assert reloaded.get("edge-gateway-2-1-0").manufacturer.name == "Muster GmbH"
    assert reloaded.products["edge-gateway-2-1-0"].markets == ["AT", "DE"]
    with pytest.raises(ToolkitError, match="existiert bereits"):
        reloaded.add(full_product())
    with pytest.raises(ToolkitError, match="edge-gateway-2-1-0"):  # lists known IDs
        reloaded.get("nope")
    reloaded.remove("edge-gateway-2-1-0")
    assert reloaded.products == {}


def test_register_tolerates_unknown_keys_from_future_versions() -> None:
    product = Product.from_dict(
        {
            "id": "a",
            "name": "A",
            "version": "1",
            "manufacturer": {"name": "M", "x": 1},
            "future": True,
        }
    )
    assert product.manufacturer.name == "M"


def test_markets_parsing() -> None:
    assert parse_markets("de, FR;at") == ["AT", "DE", "FR"]
    assert parse_markets("EU") == sorted(EU_MEMBER_STATES)
    assert len(EU_MEMBER_STATES) == 27
    with pytest.raises(ToolkitError, match="XX"):
        parse_markets("DE,XX")


def test_default_product_id() -> None:
    assert default_product_id("Edge Gateway", "2.1.0") == "edge-gateway-2-1-0"


def test_completeness_checks() -> None:
    assert all(check.ok for check in check_product(full_product()))
    bare = Product("p", "P", "1", Manufacturer("M"))
    missing = {c.name for c in check_product(bare) if not c.ok}
    assert missing == {
        "manufacturer_address",
        "manufacturer_email",
        "vulnerability_contact",
        "classification",
        "support_period_end",
        "markets",
        "intended_purpose",
    }


def test_classification_must_be_set_deliberately() -> None:
    check = {c.name: c for c in check_product(full_product(classification=None))}["classification"]
    assert not check.ok


def test_support_period_advisories() -> None:
    today = date(2026, 10, 5)
    assert any(
        "abgelaufen" in n for n in advisories(full_product(support_period_end="2026-01-01"), today)
    )
    short = advisories(
        full_product(placed_on_market="2026-06-01", support_period_end="2029-06-01"), today
    )
    assert any("fünf Jahre" in n for n in short)
    exactly_five = advisories(
        full_product(placed_on_market="2026-06-01", support_period_end="2031-06-01"), today
    )
    assert not any("fünf Jahre" in n for n in exactly_five)


def test_conformity_hint_is_marked_as_orientation_not_advice() -> None:
    notes = advisories(full_product(classification="critical"), date(2026, 10, 5))
    assert any("keine Rechtsberatung" in n and "Art. 8" in n for n in notes)


# ------------------------------------------------------------------ deadlines


def by_stage(case: Case) -> dict[str, Deadline]:
    return {d.stage: d for d in compute_deadlines(case)}


def test_vulnerability_deadlines_run_from_awareness_and_fix() -> None:
    d = by_stage(vuln_case())
    assert d["early-warning"].due == datetime(2026, 9, 13, 8, 30, tzinfo=CEST)
    assert d["notification"].due == datetime(2026, 9, 15, 8, 30, tzinfo=CEST)
    assert d["final-report"].due is None
    assert d["final-report"].basis == "pending_fix"


def test_final_report_is_due_14_days_after_the_fix_not_after_awareness() -> None:
    d = by_stage(vuln_case(fix_available_at="2026-09-20T12:00:00+02:00"))
    assert d["final-report"].due == datetime(2026, 10, 4, 12, 0, tzinfo=CEST)
    assert d["final-report"].basis == "fix_available"


def test_clock_hours_not_business_days() -> None:
    # Awareness on a Friday evening: the 24 h clock does not pause for the weekend.
    friday = vuln_case(aware_at="2026-09-11T22:00:00+02:00")
    assert by_stage(friday)["early-warning"].due == datetime(2026, 9, 12, 22, 0, tzinfo=CEST)


def test_incident_final_report_is_one_month_after_the_notification_was_filed() -> None:
    case = Case("i", "incident", "p", "Ransomware", "2026-01-29T10:00:00+01:00")
    assert by_stage(case)["final-report"].basis == "pending_notification"
    mark_filed(case, "notification", datetime(2026, 1, 31, 9, 0, tzinfo=timezone.utc), "REF-1")
    final = by_stage(case)["final-report"]
    assert final.due == datetime(2026, 2, 28, 9, 0, tzinfo=timezone.utc)  # day clamped
    assert final.basis == "notification_filed"


@pytest.mark.parametrize(
    ("start", "months", "expected"),
    [
        (datetime(2026, 1, 31), 1, datetime(2026, 2, 28)),
        (datetime(2028, 1, 31), 1, datetime(2028, 2, 29)),  # leap year
        (datetime(2026, 12, 15), 1, datetime(2027, 1, 15)),
        (datetime(2026, 5, 31), 1, datetime(2026, 6, 30)),
    ],
)
def test_add_months(start: datetime, months: int, expected: datetime) -> None:
    assert add_months(start, months) == expected


def test_deadline_states() -> None:
    now = datetime(2026, 9, 13, 9, 0, tzinfo=CEST)  # 30 min after the 24 h deadline
    case = vuln_case()
    states = {d.stage: d.state(now) for d in compute_deadlines(case)}
    assert states == {"early-warning": "overdue", "notification": "open", "final-report": "pending"}

    mark_filed(case, "early-warning", datetime(2026, 9, 13, 8, 0, tzinfo=CEST), "R1")
    assert by_stage(case)["early-warning"].state(now) == "filed"
    mark_filed(case, "early-warning", datetime(2026, 9, 13, 8, 45, tzinfo=CEST), "R1")
    assert by_stage(case)["early-warning"].state(now) == "filed_late"


def test_naive_timestamps_are_flagged_as_assumed_local() -> None:
    aware, assumed = parse_datetime("2026-09-12T08:30:00+02:00")
    assert assumed is False and aware.utcoffset() == timedelta(hours=2)
    zulu, assumed = parse_datetime("2026-09-12T06:30:00Z")
    assert assumed is False and zulu.utcoffset() == timedelta(0)
    _, assumed = parse_datetime("2026-09-12 08:30")
    assert assumed is True
    with pytest.raises(ToolkitError, match="Uhrzeit"):
        parse_datetime("2026-09-12")
    with pytest.raises(ToolkitError):
        parse_datetime("tomorrow")


def test_case_ids_are_unique(tmp_path: Path) -> None:
    store = CaseStore(tmp_path)
    aware = datetime(2026, 9, 12, 8, 30, tzinfo=CEST)
    first = store.new_id(aware, "CVE-2026-12345")
    assert first == "2026-09-12-cve-2026-12345"
    case = vuln_case(id=first)
    store.save(case)
    assert store.new_id(aware, "CVE-2026-12345") == f"{first}-2"
    assert store.get(first).reference == "CVE-2026-12345"
    with pytest.raises(ToolkitError, match="nicht gefunden"):
        store.get("missing")


# --------------------------------------------------------------------- drafts


def test_draft_marks_unknown_facts_with_visible_placeholders() -> None:
    draft = render_draft(vuln_case(), full_product(), "early-warning")
    assert "ENTWURF — NICHT EINGEREICHT" in draft.text
    assert "[BITTE ERGÄNZEN]" in draft.text
    assert draft.missing == ["Beschreibung der Schwachstelle", "Betroffene Komponente"]
    assert "AT, DE" in draft.text  # Art. 14(2)(a): member states come from the register
    assert "Art. 14 Abs. 2 lit. a CRA" in draft.text
    assert "13.09.2026 08:30 (UTC+02:00)" in draft.text  # deadline in the manufacturer's offset


def test_draft_is_complete_once_facts_are_recorded() -> None:
    case = vuln_case(summary="RCE im Web-Interface", component="pkg:npm/lodash@4.17.15")
    assert render_draft(case, full_product(), "early-warning").missing == []


@pytest.mark.parametrize("stage", ["early-warning", "notification", "final-report"])
@pytest.mark.parametrize("kind", ["vulnerability", "incident"])
def test_every_stage_renders_for_both_kinds_in_both_languages(stage: str, kind: str) -> None:
    case = Case("c", kind, "p", "REF", "2026-09-12T08:30:00+02:00")
    for language in ("de", "en"):
        set_language(language)
        draft = render_draft(case, full_product(), stage)
        assert draft.text.startswith("# ")
        assert "Art. 14" in draft.text
        assert "[" in draft.text  # placeholders present


def test_final_report_draft_explains_the_fix_based_deadline() -> None:
    text = render_draft(vuln_case(), full_product(), "final-report").text
    assert "14 Tage nach Verfügbarkeit" in text
    assert "Art. 14 Abs. 8 CRA" in text  # reminder to inform users


def test_incident_early_warning_asks_about_malicious_acts() -> None:
    case = Case("c", "incident", "p", "Ransomware", "2026-09-12T08:30:00+02:00")
    text = render_draft(case, full_product(), "early-warning").text
    assert "rechtswidrige oder böswillige Handlungen" in text
    assert "Art. 14 Abs. 4 lit. a CRA" in text


def test_english_draft() -> None:
    set_language("en")
    text = render_draft(vuln_case(), full_product(), "early-warning").text
    assert "DRAFT — NOT SUBMITTED" in text
    assert "Art. 14(2)(a) CRA" in text
    assert "2026-09-13 08:30 (UTC+02:00)" in text


# ------------------------------------------------------------------- Annex II


def test_annex_ii_has_all_nine_points_with_citations_and_prefill() -> None:
    text = render_annex_ii(full_product(), today=date(2026, 10, 5))
    for number in range(1, 10):
        assert f"## {number}. " in text
        assert f"Anhang II Nr. {number}" in text
    for sub in "abcdef":
        assert f"8({sub})" in text
    assert "Muster GmbH" in text
    assert "Musterstraße 1, 10115 Berlin" in text
    assert "security@muster.example" in text
    assert "31.12.2031" in text  # support end, German date format
    assert "Industrielles Edge-Gateway" in text
    assert "[BITTE ERGÄNZEN]" in text  # items the register cannot know


def test_annex_ii_sbom_location_and_english() -> None:
    set_language("en")
    text = render_annex_ii(
        full_product(), today=date(2026, 10, 5), sbom_location="https://muster.example/sbom.json"
    )
    assert "https://muster.example/sbom.json" in text
    assert "Annex II No. 9" in text
    assert "2031-12-31" in text


# --------------------------------------------------------------------- status


def test_status_counts_overdue_and_incomplete(tmp_path: Path) -> None:
    data_dir = DataDir(tmp_path)
    register = Register.load(data_dir.register_file)
    register.add(full_product())
    register.add(Product("bare-1", "Bare", "1", Manufacturer("M")))
    register.save()
    CaseStore(data_dir.cases_dir).save(vuln_case())

    now = datetime(2026, 9, 13, 9, 0, tzinfo=CEST)
    status = build_status(data_dir, now)
    assert status.overdue == 1
    assert status.incomplete_products == 1
    text = render_status(status)
    assert "ÜBERFÄLLIG seit 30 Min." in text
    assert "noch 1 Tage 23 Std." in text or "noch 1 Tage 22 Std." in text  # notification, 72 h
    assert "8/8 Pflichtangaben (100 %)" in text
    assert "[FEHLT] Postanschrift des Herstellers (Anhang II Nr. 1)" in text
    assert "[EMPFOHLEN]" in text


def test_status_with_nothing_recorded(tmp_path: Path) -> None:
    text = render_status(
        build_status(DataDir(tmp_path), datetime(2026, 10, 5, tzinfo=timezone.utc))
    )
    assert "Keine Fälle erfasst." in text
    assert "Keine Produkte im Register." in text
