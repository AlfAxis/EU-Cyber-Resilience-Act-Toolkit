"""Annex II user-information skeleton.

Annex II of Regulation (EU) 2024/2847 lists the information and instructions
that must accompany a product with digital elements. This module renders that
list as a Markdown skeleton, pre-filled from the product register, with the
legal citation next to every item. Items the register cannot know stay as
visible placeholders.
"""

from __future__ import annotations

from datetime import date

from cra_toolkit import __version__
from cra_toolkit.i18n import t
from cra_toolkit.register import Product
from cra_toolkit.timeutil import format_date


def render_annex_ii(product: Product, *, today: date, sbom_location: str | None = None) -> str:
    placeholder = t("draft.placeholder")
    maker = product.manufacturer
    support_end = format_date(product.support_end) if product.support_end else placeholder
    sections: list[tuple[str, str, list[str]]] = [
        (
            "1",
            "annex2.manufacturer",
            [
                f"- {t('annex2.name')}: {maker.name}",
                f"- {t('annex2.address')}: {maker.address or placeholder}",
                f"- {t('annex2.email')}: {maker.email or placeholder}",
                f"- {t('annex2.website')}: {maker.website or t('annex2.where_available')}",
            ],
        ),
        (
            "2",
            "annex2.contact",
            [
                f"- {t('annex2.vuln_contact')}: {product.vulnerability_contact or placeholder}",
                f"- {t('annex2.cvd_policy')}: {product.cvd_policy_url or placeholder}",
            ],
        ),
        (
            "3",
            "annex2.identification",
            [
                f"- {t('annex2.name')}: {product.name}",
                f"- {t('draft.type')}: {product.product_type}",
                f"- {t('draft.version')}: {product.version}",
                f"- {t('annex2.further_ids')}: {placeholder}",
            ],
        ),
        (
            "4",
            "annex2.purpose",
            [
                f"- {t('annex2.intended_purpose')}: {product.intended_purpose or placeholder}",
                f"- {t('annex2.security_environment')}: {placeholder}",
                f"- {t('annex2.functionalities')}: {placeholder}",
                f"- {t('annex2.security_properties')}: {placeholder}",
            ],
        ),
        ("5", "annex2.risks", [placeholder]),
        (
            "6",
            "annex2.doc",
            [product.declaration_of_conformity_url or f"{placeholder} {t('annex2.if_applicable')}"],
        ),
        (
            "7",
            "annex2.support",
            [
                f"- {t('annex2.support_type')}: {placeholder}",
                f"- {t('annex2.support_end')}: {support_end}",
            ],
        ),
        (
            "8",
            "annex2.instructions",
            [
                f"### 8(a) {t('annex2.i_commissioning')}\n\n{placeholder}\n",
                f"### 8(b) {t('annex2.i_changes')}\n\n{placeholder}\n",
                f"### 8(c) {t('annex2.i_updates')}\n\n{placeholder}\n",
                f"### 8(d) {t('annex2.i_decommissioning')}\n\n{placeholder}\n",
                f"### 8(e) {t('annex2.i_auto_updates')}\n\n{placeholder}\n",
                f"### 8(f) {t('annex2.i_integration')}\n\n{placeholder}",
            ],
        ),
        (
            "9",
            "annex2.sbom",
            [
                f"_{t('annex2.sbom_optional')}_",
                "",
                sbom_location or f"{placeholder} {t('annex2.if_applicable')}",
            ],
        ),
    ]

    lines = [
        f"# {t('annex2.title')}: {product.name} {product.version}",
        "",
        f"> **{t('draft.banner_docs')}** {t('annex2.intro')}",
        f"> {t('annex2.generated', date=format_date(today), version=__version__)}",
        "",
    ]
    for number, heading_key, body in sections:
        lines += [f"## {number}. {t(heading_key)}", "", f"*{t('annex2.cite', number=number)}*", ""]
        lines += [*body, ""]
    lines += [f"## {t('annex2.availability_title')}", "", t("annex2.availability"), ""]
    return "\n".join(lines)
