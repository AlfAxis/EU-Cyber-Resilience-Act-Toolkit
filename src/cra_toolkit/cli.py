"""Command-line interface: ``sbom``, ``scan``, ``register``, ``report``, ``docs``, ``status``.

Exit codes: ``0`` success, ``1`` a compliance gate tripped (findings at or above
``--fail-on``, an overdue Article 14 deadline), ``2`` usage or runtime error
(including an unreachable vulnerability database — a CI job must not turn green
because the check could not run).
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import os
import sys
from collections.abc import Callable, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

from cra_toolkit import __version__
from cra_toolkit.docs import render_annex_ii
from cra_toolkit.errors import ToolkitError
from cra_toolkit.evidence import build_scan_evidence, render_table, severity_cell
from cra_toolkit.i18n import LANGUAGES, set_language, t
from cra_toolkit.register import (
    CLASSIFICATIONS,
    PRODUCT_TYPES,
    Manufacturer,
    Product,
    Register,
    default_product_id,
    parse_markets,
    touch,
)
from cra_toolkit.reports import (
    KINDS,
    STAGES,
    TEXT_FIELDS,
    Case,
    CaseStore,
    compute_deadlines,
    mark_filed,
    render_draft,
)
from cra_toolkit.sbom import Inventory, build_bom, collect
from cra_toolkit.status import build_status, render_status, status_to_dict
from cra_toolkit.store import (
    DataDir,
    dump_json,
    resolve_data_dir,
    utc_stamp,
    write_json,
    write_text,
)
from cra_toolkit.timeutil import (
    format_date,
    format_datetime,
    now_local,
    parse_date,
    parse_datetime,
    to_iso,
)
from cra_toolkit.vulns import (
    FAIL_LEVELS,
    OfflineDb,
    OsvClient,
    ScanResult,
    scan_offline,
    scan_online,
)

Clock = Callable[[], datetime]


def _out(text: str = "") -> None:
    print(text)


def _err(text: str) -> None:
    print(text, file=sys.stderr)


# ---------------------------------------------------------------- arguments


def _common() -> argparse.ArgumentParser:
    parent = argparse.ArgumentParser(add_help=False)
    group = parent.add_argument_group("global options")
    group.add_argument(
        "--data-dir",
        metavar="DIR",
        default=argparse.SUPPRESS,
        help="working data (register, cases, evidence); default: ./.cra or $CRA_TOOLKIT_DATA_DIR",
    )
    group.add_argument(
        "--lang",
        choices=LANGUAGES,
        default=argparse.SUPPRESS,
        help="output language (default: de, or $CRA_TOOLKIT_LANG)",
    )
    return parent


def _add_product_fields(parser: argparse.ArgumentParser, *, creating: bool) -> None:
    parser.add_argument("--name", required=creating, help="product name")
    parser.add_argument(
        "--version", dest="product_version", required=creating, help="product version"
    )
    parser.add_argument("--manufacturer", required=creating, help="manufacturer name")
    parser.add_argument("--address", help="manufacturer postal address (Annex II No. 1)")
    parser.add_argument("--email", help="manufacturer email or digital contact (Annex II No. 1)")
    parser.add_argument("--website", help="manufacturer website")
    parser.add_argument(
        "--contact", help="single point of contact for vulnerability reports (Annex II No. 2)"
    )
    parser.add_argument("--cvd-policy-url", help="coordinated vulnerability disclosure policy URL")
    parser.add_argument(
        "--classification",
        choices=CLASSIFICATIONS,
        help="Annex III/IV class — a legal determination you make, not one the tool infers",
    )
    parser.add_argument("--type", dest="product_type", choices=PRODUCT_TYPES, help="product type")
    parser.add_argument("--support-end", metavar="YYYY-MM-DD", help="end of the support period")
    parser.add_argument(
        "--placed-on-market", metavar="YYYY-MM-DD", help="date first placed on the EU market"
    )
    parser.add_argument("--markets", help="EU member states, e.g. DE,FR,AT — or EU for all 27")
    parser.add_argument("--purpose", help="intended purpose (Annex II No. 4)")
    parser.add_argument("--doc-url", help="URL of the EU declaration of conformity")


def _add_case_fields(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--fix-available-at",
        metavar="TIMESTAMP",
        help="when a corrective/mitigating measure became available",
    )
    parser.add_argument("--component", help="affected component (e.g. a purl)")
    parser.add_argument("--summary", help="short description of the vulnerability/incident")
    parser.add_argument("--exploitation", help="general nature of the exploit")
    parser.add_argument("--actor", help="what is known about the malicious actor")
    parser.add_argument("--measures-taken", help="corrective or mitigating measures taken")
    parser.add_argument("--user-measures", help="measures users can take")
    parser.add_argument("--sensitivity", help="how sensitive the notified information is")
    parser.add_argument("--severity", help="severity of the vulnerability/incident")
    parser.add_argument("--impact", help="impact")
    parser.add_argument("--update-details", help="details of the security update")
    parser.add_argument("--root-cause", help="threat type / root cause (incidents)")
    parser.add_argument(
        "--malicious-suspected", help="suspected unlawful or malicious acts (incidents)"
    )


def build_parser() -> argparse.ArgumentParser:
    common = _common()
    parser = argparse.ArgumentParser(
        prog="cra-toolkit",
        parents=[common],
        description="Tooling for EU Cyber Resilience Act (Regulation (EU) 2024/2847) compliance. "
        "Not legal advice.",
    )
    parser.add_argument("--version", action="version", version=f"cra-toolkit {__version__}")
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    # sbom
    p = sub.add_parser("sbom", parents=[common], help="generate a CycloneDX 1.6 SBOM")
    p.add_argument("path", nargs="?", default=".", help="project directory (default: .)")
    p.add_argument("-o", "--output", default="sbom.cdx.json", help="output file, or - for stdout")
    p.add_argument(
        "--product", metavar="ID", help="register product to describe in the SBOM metadata"
    )
    p.add_argument(
        "--exclude", action="append", default=[], metavar="GLOB", help="skip matching paths"
    )
    p.add_argument("--production-only", action="store_true", help="omit dev/test-only dependencies")

    # scan
    p = sub.add_parser("scan", parents=[common], help="SBOM plus vulnerability matching")
    p.add_argument("path", nargs="?", default=".", help="project directory (default: .)")
    p.add_argument(
        "--product", metavar="ID", help="register product to describe in the SBOM metadata"
    )
    p.add_argument(
        "--offline-db", metavar="PATH", help="OSV records (dir, .zip or .json) instead of OSV.dev"
    )
    p.add_argument(
        "--fail-on", choices=FAIL_LEVELS, default="none", help="exit 1 at this severity or above"
    )
    p.add_argument(
        "--ignore",
        action="append",
        default=[],
        metavar="ID",
        help="accept a vulnerability ID/alias",
    )
    p.add_argument("--sbom", metavar="FILE", help="also write the SBOM here")
    p.add_argument("--report", metavar="FILE", help="also write the JSON evidence report here")
    p.add_argument("--format", choices=("text", "json"), default="text", help="stdout format")
    p.add_argument(
        "--exclude", action="append", default=[], metavar="GLOB", help="skip matching paths"
    )
    p.add_argument("--production-only", action="store_true", help="omit dev/test-only dependencies")
    p.add_argument(
        "--no-archive", action="store_true", help="do not store evidence in the data dir"
    )
    p.add_argument("--timeout", type=float, default=30.0, help="OSV.dev request timeout in seconds")

    # register
    p = sub.add_parser("register", parents=[common], help="product inventory and classification")
    reg = p.add_subparsers(dest="register_command", required=True, metavar="ACTION")
    q = reg.add_parser("add", parents=[common], help="add a product")
    q.add_argument("--id", help="register ID (default: derived from name and version)")
    _add_product_fields(q, creating=True)
    q = reg.add_parser("update", parents=[common], help="change a product")
    q.add_argument("id")
    _add_product_fields(q, creating=False)
    reg.add_parser("list", parents=[common], help="list products")
    q = reg.add_parser("show", parents=[common], help="show one product")
    q.add_argument("id")
    q.add_argument("--json", action="store_true", help="print as JSON")
    q = reg.add_parser("remove", parents=[common], help="remove a product")
    q.add_argument("id")

    # report
    p = sub.add_parser("report", parents=[common], help="Article 14 cases and report drafts")
    rep = p.add_subparsers(dest="report_command", required=True, metavar="ACTION")
    q = rep.add_parser("open", parents=[common], help="open a case at the moment of awareness")
    q.add_argument("--product", required=True, metavar="ID")
    q.add_argument(
        "--reference", required=True, help="vulnerability ID (CVE/GHSA) or incident title"
    )
    q.add_argument(
        "--aware-at",
        required=True,
        metavar="TIMESTAMP",
        help="ISO 8601, e.g. 2026-09-12T08:30+02:00",
    )
    q.add_argument("--kind", choices=KINDS, default="vulnerability")
    _add_case_fields(q)
    q = rep.add_parser("draft", parents=[common], help="write the Markdown draft(s) for a case")
    q.add_argument("case")
    q.add_argument("--stage", choices=(*STAGES, "all"), default="all")
    q.add_argument(
        "-o",
        "--output",
        metavar="DIR",
        help="output directory (default: <data-dir>/reports/<case>)",
    )
    q.add_argument("--stdout", action="store_true", help="print instead of writing files")
    q = rep.add_parser("update", parents=[common], help="add facts to a case")
    q.add_argument("case")
    _add_case_fields(q)
    q = rep.add_parser("filed", parents=[common], help="record that you submitted a stage")
    q.add_argument("case")
    q.add_argument("--stage", choices=STAGES, required=True)
    q.add_argument("--at", metavar="TIMESTAMP", help="submission time (default: now)")
    q.add_argument("--reference", help="confirmation/reference from the reporting platform")
    rep.add_parser("list", parents=[common], help="list cases with their next deadline")

    # docs
    p = sub.add_parser("docs", parents=[common], help="Annex II user-information skeleton")
    p.add_argument("--product", required=True, metavar="ID")
    p.add_argument("-o", "--output", metavar="FILE")
    p.add_argument("--stdout", action="store_true", help="print instead of writing a file")
    p.add_argument("--sbom-location", help="where users can obtain the SBOM (Annex II No. 9)")

    # status
    p = sub.add_parser(
        "status", parents=[common], help="deadline countdown and register completeness"
    )
    p.add_argument("--format", choices=("text", "json"), default="text")
    p.add_argument(
        "--strict", action="store_true", help="also exit 1 if the register is incomplete"
    )
    return parser


# ----------------------------------------------------------------- helpers


def _data_dir(args: argparse.Namespace) -> DataDir:
    return resolve_data_dir(getattr(args, "data_dir", None))


def _resolve_language(args: argparse.Namespace) -> str:
    chosen = getattr(args, "lang", None) or os.environ.get("CRA_TOOLKIT_LANG") or "de"
    return chosen if chosen in LANGUAGES else "de"


def _load_product(data_dir: DataDir, product_id: str | None) -> Product | None:
    if not product_id:
        return None
    return Register.load(data_dir.register_file).get(product_id)


def _filtered(inventory: Inventory, production_only: bool) -> Inventory:
    if not production_only:
        return inventory
    kept = [c for c in inventory.components if c.scope != "excluded"]
    return Inventory(inventory.root, kept, inventory.sources, inventory.warnings)


def _warn_naive(assumed_local: bool, value: datetime) -> None:
    if assumed_local:
        _err(t("report.assumed_local", value=format_datetime(value)))


# -------------------------------------------------------------- sbom / scan


def cmd_sbom(args: argparse.Namespace, clock: Clock) -> int:
    data_dir = _data_dir(args)
    product = _load_product(data_dir, args.product)
    inventory = _filtered(collect(Path(args.path), args.exclude), args.production_only)
    bom = build_bom(inventory, product=product.to_dict() if product else None, timestamp=clock())
    text = dump_json(bom)
    for warning in inventory.warnings:
        _err(f"{t('label.warning')}: {warning}")
    if not inventory.sources:
        _err(f"{t('label.warning')}: {t('sbom.no_sources')}")
    if args.output == "-":
        sys.stdout.write(text)
        return 0
    write_text(Path(args.output), text)
    _out(
        t(
            "sbom.written",
            path=args.output,
            components=len(inventory.components),
            sources=len(inventory.sources),
        )
    )
    return 0


def _render_scan(inventory: Inventory, result: ScanResult, fail_on: str, notes: list[str]) -> str:
    labels = {
        level: t(f"severity.{level}") for level in ("critical", "high", "medium", "low", "unknown")
    }
    counts = result.severity_counts()
    lines = [
        t("scan.inventory", components=len(inventory.components), sources=len(inventory.sources)),
        t("scan.source", source=result.source),
        t("scan.checked", checked=len(result.scanned), unchecked=len(result.unscanned)),
        "",
    ]
    total = sum(counts.values())
    if total:
        breakdown = " · ".join(
            f"{labels[level]} {counts[level]}"
            for level in ("critical", "high", "medium", "low", "unknown")
            if counts[level]
        )
        lines.append(
            t("scan.found", findings=total, components=len(result.findings), breakdown=breakdown)
        )
        lines.append("")
        rows = [
            [
                finding.component.name,
                finding.component.version or "",
                vuln.id,
                severity_cell(vuln.severity, vuln.score, labels),
                ", ".join(vuln.fixed_versions[:2]),
            ]
            for finding in result.findings
            for vuln in finding.vulnerabilities
        ]
        headers = [
            t("scan.col.component"),
            t("scan.col.version"),
            "ID",
            t("scan.col.severity"),
            t("scan.col.fixed"),
        ]
        lines += render_table(headers, rows)
    else:
        lines.append(t("scan.none_found"))
    lines.append("")
    if result.unscanned:
        lines.append(t("scan.not_checkable"))
        for comp in result.unscanned:
            lines.append(f"  - {comp.name} ({comp.constraint or '*'}) — {', '.join(comp.sources)}")
        lines.append("")
    if result.ignored:
        lines.append(t("scan.ignored", count=len(result.ignored)))
    for note in [*inventory.warnings, *notes]:
        lines.append(f"{t('label.warning')}: {note}")
    if fail_on != "none":
        passed = not result.gate_failed(fail_on)
        lines.append(t("scan.gate_passed" if passed else "scan.gate_failed", level=fail_on))
        if fail_on not in ("any", "none") and counts["unknown"]:
            lines.append(t("scan.unknown_not_gated", count=counts["unknown"]))
    lines.append(t("scan.disclaimer"))
    return "\n".join(lines) + "\n"


def cmd_scan(args: argparse.Namespace, clock: Clock) -> int:
    data_dir = _data_dir(args)
    product = _load_product(data_dir, args.product)
    now = clock()
    inventory = _filtered(collect(Path(args.path), args.exclude), args.production_only)
    bom_text = dump_json(
        build_bom(inventory, product=product.to_dict() if product else None, timestamp=now)
    )
    sbom_sha = hashlib.sha256(bom_text.encode("utf-8")).hexdigest()

    notes: list[str] = []
    skipped: list[str] = []
    if args.offline_db:
        result, db = scan_offline(inventory.components, Path(args.offline_db), args.ignore)
        skipped = db.skipped
        notes.append(t("scan.offline_note"))
        if skipped:
            notes.append(t("scan.offline_skipped", count=len(skipped)))
    else:
        client = OsvClient(timeout=args.timeout)
        result = scan_online(inventory.components, client, args.ignore)

    stamp = utc_stamp(now)
    sbom_name = f"sbom-{stamp}.cdx.json"
    evidence = build_scan_evidence(
        inventory=inventory,
        result=result,
        sbom_file=args.sbom or (sbom_name if not args.no_archive else None),
        sbom_sha256=sbom_sha,
        product_id=product.id if product else None,
        fail_on=args.fail_on,
        generated_at=now,
        skipped_db_files=skipped,
    )
    if args.sbom:
        write_text(Path(args.sbom), bom_text)
    if args.report:
        write_json(Path(args.report), evidence)
    saved: list[Path] = []
    if not args.no_archive:
        saved = [data_dir.evidence_dir / sbom_name, data_dir.evidence_dir / f"scan-{stamp}.json"]
        write_text(saved[0], bom_text)
        write_json(saved[1], evidence)

    if args.format == "json":
        sys.stdout.write(dump_json(evidence))
    else:
        sys.stdout.write(_render_scan(inventory, result, args.fail_on, notes))
        if args.sbom:
            _out(
                t(
                    "sbom.written",
                    path=args.sbom,
                    components=len(inventory.components),
                    sources=len(inventory.sources),
                )
            )
        if saved:
            _out(t("scan.evidence", path=saved[1]))
    return 1 if result.gate_failed(args.fail_on) else 0


# ----------------------------------------------------------------- register


def _apply_product_args(product: Product, args: argparse.Namespace) -> None:
    simple = {
        "name": args.name,
        "version": args.product_version,
        "product_type": args.product_type,
        "classification": args.classification,
        "vulnerability_contact": args.contact,
        "cvd_policy_url": args.cvd_policy_url,
        "intended_purpose": args.purpose,
        "declaration_of_conformity_url": args.doc_url,
    }
    for key, value in simple.items():
        if value is not None:
            setattr(product, key, value)
    maker = product.manufacturer
    for key, value in (
        ("name", args.manufacturer),
        ("address", args.address),
        ("email", args.email),
        ("website", args.website),
    ):
        if value is not None:
            setattr(maker, key, value)
    if args.support_end is not None:
        product.support_period_end = parse_date(args.support_end).isoformat()
    if args.placed_on_market is not None:
        product.placed_on_market = parse_date(args.placed_on_market).isoformat()
    if args.markets is not None:
        product.markets = parse_markets(args.markets)


def _show_product(product: Product) -> list[str]:
    maker = product.manufacturer
    unset = t("note.unset")

    def date_text(value: str | None) -> str:
        return format_date(parse_date(value)) if value else unset

    rows = [
        ("id", product.id),
        ("name", f"{product.name} {product.version}"),
        ("type", product.product_type),
        ("manufacturer", maker.name),
        ("address", maker.address or unset),
        ("email", maker.email or unset),
        ("website", maker.website or unset),
        ("vulnerability_contact", product.vulnerability_contact or unset),
        ("cvd_policy_url", product.cvd_policy_url or unset),
        (
            "classification",
            t(f"class.{product.classification}") if product.classification else unset,
        ),
        ("support_end", date_text(product.support_period_end)),
        ("placed_on_market", date_text(product.placed_on_market)),
        ("markets", ", ".join(product.markets) or unset),
        ("purpose", product.intended_purpose or unset),
        ("doc_url", product.declaration_of_conformity_url or unset),
    ]
    return [f"{t(f'reg.field.{key}'):<28} {value}" for key, value in rows]


def cmd_register(args: argparse.Namespace, clock: Clock) -> int:
    data_dir = _data_dir(args)
    register = Register.load(data_dir.register_file)
    action = args.register_command

    if action == "add":
        product_id = args.id or default_product_id(args.name, args.product_version)
        product = Product(
            product_id, args.name, args.product_version, Manufacturer(args.manufacturer)
        )
        _apply_product_args(product, args)
        touch(product, clock())
        register.add(product)
        register.save()
        _out(t("register.added", id=product.id, path=data_dir.register_file))
    elif action == "update":
        product = register.get(args.id)
        _apply_product_args(product, args)
        touch(product, clock())
        register.save()
        _out(t("register.updated", id=product.id))
    elif action == "remove":
        register.remove(args.id)
        register.save()
        _out(t("register.removed", id=args.id))
    elif action == "show":
        product = register.get(args.id)
        if args.json:
            sys.stdout.write(dump_json(product.to_dict()))
        else:
            _out("\n".join(_show_product(product)))
    else:  # list
        if not register.products:
            _out(t("register.empty"))
            return 0
        rows = [
            [
                p.id,
                f"{p.name} {p.version}",
                p.classification or t("note.unset"),
                format_date(parse_date(p.support_period_end))
                if p.support_period_end
                else t("note.unset"),
            ]
            for p in sorted(register.products.values(), key=lambda p: p.id)
        ]
        headers = [
            "ID",
            t("register.col.product"),
            t("register.col.class"),
            t("register.col.support"),
        ]
        _out("\n".join(render_table(headers, rows, max_width=40)))
    return 0


# ------------------------------------------------------------------- report


def _case_updates(args: argparse.Namespace) -> dict[str, Any]:
    updates: dict[str, Any] = {}
    for name in TEXT_FIELDS:
        value = getattr(args, name, None)
        if value is not None:
            updates[name] = value
    if getattr(args, "fix_available_at", None) is not None:
        fix, assumed = parse_datetime(args.fix_available_at)
        _warn_naive(assumed, fix)
        updates["fix_available_at"] = to_iso(fix)
    return updates


def _print_deadlines(case: Case, now: datetime) -> None:
    for deadline in compute_deadlines(case):
        label = t(f"stage.{deadline.stage}")
        due = format_datetime(deadline.due) if deadline.due else t(f"basis.{deadline.basis}")
        _out(f"  {label:<18} {due}")


def cmd_report(args: argparse.Namespace, clock: Clock) -> int:
    data_dir = _data_dir(args)
    store = CaseStore(data_dir.cases_dir)
    action = args.report_command
    now = clock()

    if action == "open":
        product = _load_product(data_dir, args.product)
        assert product is not None
        aware, assumed = parse_datetime(args.aware_at)
        _warn_naive(assumed, aware)
        case = Case(
            id=store.new_id(aware, args.reference),
            kind=args.kind,
            product_id=product.id,
            reference=args.reference,
            aware_at=to_iso(aware),
            created_at=to_iso(now),
        )
        for key, value in _case_updates(args).items():
            setattr(case, key, value)
        store.save(case)
        _out(t("report.opened", id=case.id, path=data_dir.cases_dir / f"{case.id}.json"))
        _out(t("report.deadlines_heading"))
        _print_deadlines(case, now)
        _out(t("report.next_step", id=case.id))
    elif action == "update":
        case = store.get(args.case)
        for key, value in _case_updates(args).items():
            setattr(case, key, value)
        store.save(case)
        _out(t("report.updated", id=case.id))
        _print_deadlines(case, now)
    elif action == "filed":
        case = store.get(args.case)
        at = now
        if args.at:
            at, assumed = parse_datetime(args.at)
            _warn_naive(assumed, at)
        mark_filed(case, args.stage, at, args.reference)
        store.save(case)
        _out(t("report.filed", stage=t(f"stage.{args.stage}"), id=case.id, at=format_datetime(at)))
        _print_deadlines(case, now)
    elif action == "draft":
        case = store.get(args.case)
        product = Register.load(data_dir.register_file).get(case.product_id)
        stages = STAGES if args.stage == "all" else (args.stage,)
        target = Path(args.output) if args.output else data_dir.reports_dir / case.id
        for stage in stages:
            draft = render_draft(case, product, stage)
            if args.stdout:
                _out(draft.text)
                continue
            path = target / f"{stage}.{_language()}.md"
            write_text(path, draft.text)
            _out(t("report.drafted", stage=t(f"stage.{stage}"), path=path))
            if draft.missing:
                _out(t("report.missing", count=len(draft.missing), fields="; ".join(draft.missing)))
    else:  # list
        cases = store.list()
        if not cases:
            _out(t("report.list_empty"))
            return 0
        for case in cases:
            _out(f"{case.id}  [{case.product_id}]  {case.reference}")
            _print_deadlines(case, now)
    return 0


def _language() -> str:
    from cra_toolkit.i18n import get_language

    return get_language()


# --------------------------------------------------------------- docs/status


def cmd_docs(args: argparse.Namespace, clock: Clock) -> int:
    data_dir = _data_dir(args)
    product = _load_product(data_dir, args.product)
    assert product is not None
    text = render_annex_ii(product, today=clock().date(), sbom_location=args.sbom_location)
    if args.stdout:
        sys.stdout.write(text)
        return 0
    path = (
        Path(args.output)
        if args.output
        else data_dir.root / "docs" / f"annex-ii-{product.id}.{_language()}.md"
    )
    write_text(path, text)
    _out(t("docs.written", path=path))
    return 0


def cmd_status(args: argparse.Namespace, clock: Clock) -> int:
    status = build_status(_data_dir(args), clock())
    if args.format == "json":
        sys.stdout.write(dump_json(status_to_dict(status)))
    else:
        sys.stdout.write(render_status(status))
    failed = status.overdue > 0 or (args.strict and status.incomplete_products > 0)
    return 1 if failed else 0


COMMANDS: dict[str, Callable[[argparse.Namespace, Clock], int]] = {
    "sbom": cmd_sbom,
    "scan": cmd_scan,
    "register": cmd_register,
    "report": cmd_report,
    "docs": cmd_docs,
    "status": cmd_status,
}


def _configure_streams() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            with contextlib.suppress(ValueError, OSError):  # exotic stream wrappers
                reconfigure(encoding="utf-8", errors="replace")


def main(argv: Sequence[str] | None = None, *, clock: Clock = now_local) -> int:
    _configure_streams()
    parser = build_parser()
    args = parser.parse_args(argv)
    set_language(_resolve_language(args))
    try:
        return COMMANDS[args.command](args, clock)
    except ToolkitError as exc:
        _err(f"{t('label.error')}: {exc}")
        return 2
    except KeyboardInterrupt:  # pragma: no cover
        return 130


__all__ = ["OfflineDb", "build_parser", "main"]
