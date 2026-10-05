"""Product register: what you ship, who is responsible, and how it is classified.

The register is the source of truth the other commands draw on: ``docs`` fills
the Annex II skeleton from it, ``report`` addresses Article 14 submissions with
it, and ``status`` checks how complete it is.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from cra_toolkit.errors import ToolkitError
from cra_toolkit.i18n import t
from cra_toolkit.store import read_json, slugify, write_json

#: Annex III (important products, class I / II) and Annex IV (critical products).
CLASSIFICATIONS = ("default", "important-class-1", "important-class-2", "critical")
PRODUCT_TYPES = ("application", "firmware", "device", "library", "operating-system", "framework")
EU_MEMBER_STATES = (
    "AT", "BE", "BG", "CY", "CZ", "DE", "DK", "EE", "ES", "FI", "FR", "GR", "HR", "HU",
    "IE", "IT", "LT", "LU", "LV", "MT", "NL", "PL", "PT", "RO", "SE", "SI", "SK",
)  # fmt: skip

SCHEMA_VERSION = 1


@dataclass
class Manufacturer:
    name: str
    address: str | None = None
    email: str | None = None
    website: str | None = None


@dataclass
class Product:
    id: str
    name: str
    version: str
    manufacturer: Manufacturer
    product_type: str = "application"
    classification: str | None = None
    vulnerability_contact: str | None = None
    cvd_policy_url: str | None = None
    support_period_end: str | None = None
    placed_on_market: str | None = None
    markets: list[str] = field(default_factory=list)
    intended_purpose: str | None = None
    declaration_of_conformity_url: str | None = None
    created_at: str = ""
    updated_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Product:
        known = {f for f in cls.__dataclass_fields__ if f != "manufacturer"}
        maker = data.get("manufacturer") or {}
        return cls(
            manufacturer=Manufacturer(
                **{k: v for k, v in maker.items() if k in Manufacturer.__dataclass_fields__}
            ),
            **{k: v for k, v in data.items() if k in known},
        )

    @property
    def support_end(self) -> date | None:
        return date.fromisoformat(self.support_period_end) if self.support_period_end else None

    @property
    def market_date(self) -> date | None:
        return date.fromisoformat(self.placed_on_market) if self.placed_on_market else None


def default_product_id(name: str, version: str) -> str:
    return slugify(f"{name} {version}")


def parse_markets(value: str) -> list[str]:
    """``"DE,FR"`` -> ``["DE", "FR"]``; ``"EU"`` expands to all 27 member states."""
    codes: list[str] = []
    for raw in value.replace(";", ",").split(","):
        code = raw.strip().upper()
        if not code:
            continue
        expanded = list(EU_MEMBER_STATES) if code == "EU" else [code]
        for item in expanded:
            if item not in EU_MEMBER_STATES:
                raise ToolkitError(t("err.unknown_market", code=item))
            if item not in codes:
                codes.append(item)
    return sorted(codes)


class Register:
    """JSON-backed collection of products."""

    def __init__(self, path: Path, products: dict[str, Product] | None = None) -> None:
        self.path = path
        self.products: dict[str, Product] = products or {}

    @classmethod
    def load(cls, path: Path) -> Register:
        if not path.exists():
            return cls(path)
        data = read_json(path)
        entries = data.get("products", []) if isinstance(data, dict) else []
        products = {p["id"]: Product.from_dict(p) for p in entries}
        return cls(path, products)

    def save(self) -> None:
        payload = {
            "schema": SCHEMA_VERSION,
            "products": [p.to_dict() for p in sorted(self.products.values(), key=lambda p: p.id)],
        }
        write_json(self.path, payload)

    def add(self, product: Product) -> None:
        if product.id in self.products:
            raise ToolkitError(t("err.product_exists", id=product.id))
        self.products[product.id] = product

    def get(self, product_id: str) -> Product:
        try:
            return self.products[product_id]
        except KeyError:
            known = ", ".join(sorted(self.products)) or t("note.none")
            raise ToolkitError(t("err.unknown_product", id=product_id, known=known)) from None

    def remove(self, product_id: str) -> None:
        self.get(product_id)
        del self.products[product_id]


def touch(product: Product, now: datetime | None = None) -> None:
    stamp = (now or datetime.now(timezone.utc)).isoformat(timespec="seconds")
    if not product.created_at:
        product.created_at = stamp
    product.updated_at = stamp


# ------------------------------------------------------------- completeness


@dataclass(frozen=True)
class Check:
    """One required register field and the legal provision that demands it."""

    name: str
    reference: str
    ok: bool


def _filled(value: object) -> bool:
    return bool(value and str(value).strip())


def check_product(product: Product) -> list[Check]:
    maker = product.manufacturer
    return [
        Check("manufacturer_name", "annex2_1", _filled(maker.name)),
        Check("manufacturer_address", "annex2_1", _filled(maker.address)),
        Check("manufacturer_email", "annex2_1", _filled(maker.email)),
        Check("vulnerability_contact", "annex2_2", _filled(product.vulnerability_contact)),
        Check("classification", "classification", product.classification is not None),
        Check("support_period_end", "support", _filled(product.support_period_end)),
        Check("markets", "art14_2a", bool(product.markets)),
        Check("intended_purpose", "annex2_4", _filled(product.intended_purpose)),
    ]


def recommendations(product: Product) -> list[Check]:
    """Optional-but-useful fields; shown by ``status`` without affecting the score."""
    return [
        Check("cvd_policy_url", "annex2_2", _filled(product.cvd_policy_url)),
        Check("placed_on_market", "art13_8", _filled(product.placed_on_market)),
        Check(
            "declaration_of_conformity_url",
            "annex2_6",
            _filled(product.declaration_of_conformity_url),
        ),
    ]


def advisories(product: Product, today: date) -> list[str]:
    """Plausibility warnings, localised. These are hints, never legal conclusions."""
    notes: list[str] = []
    end, placed = product.support_end, product.market_date
    if end is not None:
        if end < today:
            notes.append(t("adv.support_expired", date=end.isoformat()))
        elif placed is not None and end < _add_years(placed, 5):
            notes.append(t("adv.support_short"))
    if product.classification is not None:
        notes.append(t(f"adv.conformity.{product.classification}"))
    return notes


def _add_years(value: date, years: int) -> date:
    try:
        return value.replace(year=value.year + years)
    except ValueError:  # 29 Feb
        return value.replace(year=value.year + years, day=28)
