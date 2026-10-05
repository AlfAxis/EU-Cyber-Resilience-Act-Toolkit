from __future__ import annotations

import re
from pathlib import Path

import pytest

import cra_toolkit
from cra_toolkit.i18n import CATALOG, LANGUAGES, get_language, has, set_language, t
from cra_toolkit.register import (
    CLASSIFICATIONS,
    Manufacturer,
    Product,
    check_product,
    recommendations,
)
from cra_toolkit.reports import KINDS, STAGES

SRC = Path(cra_toolkit.__file__).parent
PLACEHOLDER = re.compile(r"\{(\w+)\}")
LITERAL_KEY = re.compile(r"""\bt\(\s*"([A-Za-z0-9_.\-]+)"|\bt\(\s*'([A-Za-z0-9_.\-]+)'""")


def test_every_literal_key_used_in_the_code_exists() -> None:
    missing: list[str] = []
    for path in SRC.rglob("*.py"):
        if path.name == "i18n.py":
            continue
        for match in LITERAL_KEY.finditer(path.read_text(encoding="utf-8")):
            key = match.group(1) or match.group(2)
            if key not in CATALOG:
                missing.append(f"{path.name}: {key}")
    assert missing == []


def test_dynamic_key_families_are_complete() -> None:
    keys: list[str] = []
    keys += [f"class.{c}" for c in CLASSIFICATIONS]
    keys += [f"adv.conformity.{c}" for c in CLASSIFICATIONS]
    keys += [f"stage.{s}" for s in STAGES]
    keys += [f"legal.{k}.{s}" for k in KINDS for s in STAGES]
    keys += [f"draft.title.{k}.{s}" for k in KINDS for s in STAGES]
    keys += [f"severity.{s}" for s in ("critical", "high", "medium", "low", "unknown")]
    keys += [
        f"basis.{b}"
        for b in (
            "awareness",
            "fix_available",
            "pending_fix",
            "notification_filed",
            "pending_notification",
        )
    ]
    product = Product("p", "P", "1", Manufacturer("M"))
    for check in [*check_product(product), *recommendations(product)]:
        keys += [f"check.{check.name}", f"ref.{check.reference}"]
    for name in (
        "id", "name", "type", "manufacturer", "address", "email", "website",
        "vulnerability_contact", "cvd_policy_url", "classification", "support_end",
        "placed_on_market", "markets", "purpose", "doc_url",
    ):  # fmt: skip
        keys.append(f"reg.field.{name}")
    for name in (
        "summary", "component", "malicious_suspected", "member_states", "product_info",
        "exploitation", "measures_taken", "user_measures", "sensitivity", "severity",
        "impact", "actor", "update_details", "root_cause",
    ):  # fmt: skip
        keys.append(f"field.{name}")
    assert [k for k in keys if not has(k)] == []


def test_placeholders_match_between_languages() -> None:
    mismatched = {
        key: (german, english)
        for key, (german, english) in CATALOG.items()
        if set(PLACEHOLDER.findall(german)) != set(PLACEHOLDER.findall(english))
    }
    assert mismatched == {}


def test_no_empty_translations() -> None:
    assert [key for key, pair in CATALOG.items() if not all(part.strip() for part in pair)] == []


@pytest.mark.parametrize("language", LANGUAGES)
def test_every_message_formats_with_its_own_placeholders(language: str) -> None:
    set_language(language)
    for key, (german, _english) in CATALOG.items():
        names = set(PLACEHOLDER.findall(german))
        assert isinstance(t(key, **dict.fromkeys(names, "x")), str)


def test_language_switching() -> None:
    set_language("en")
    assert get_language() == "en" and t("label.error") == "Error"
    set_language("fr")  # unsupported: falls back to German
    assert get_language() == "de" and t("label.error") == "Fehler"
