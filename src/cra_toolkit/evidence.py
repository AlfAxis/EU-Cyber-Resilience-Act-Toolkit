"""Evidence artifacts for ``scan``: a machine-readable report and a terminal summary.

Compliance is proven by documentation over time, not by a passing scan, so
every scan can leave behind a timestamped record: what was inventoried, which
database answered, what was found, and the checksum of the SBOM it belongs to.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from cra_toolkit import __version__
from cra_toolkit.sbom import Inventory
from cra_toolkit.vulns import SEVERITIES, ScanResult


def build_scan_evidence(
    *,
    inventory: Inventory,
    result: ScanResult,
    sbom_file: str | None,
    sbom_sha256: str | None,
    product_id: str | None,
    fail_on: str,
    generated_at: datetime,
    skipped_db_files: list[str] | None = None,
) -> dict[str, Any]:
    counts = result.severity_counts()
    return {
        "tool": {"name": "cra-toolkit", "version": __version__},
        "generated_at": generated_at.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "target": {"path": str(inventory.root.resolve()), "product": product_id},
        "sbom": {
            "file": sbom_file,
            "sha256": sbom_sha256,
            "components": len(inventory.components),
            "sources": inventory.sources,
        },
        "vulnerability_source": {"type": result.source, "detail": result.source_detail},
        "summary": {
            "components": len(inventory.components),
            "checked": len(result.scanned),
            "not_checkable": len(result.unscanned),
            "vulnerable_components": len(result.findings),
            "findings": sum(counts.values()),
            "by_severity": counts,
            "ignored": len(result.ignored),
        },
        "gate": {"fail_on": fail_on, "passed": not result.gate_failed(fail_on)},
        "findings": [
            {
                "purl": finding.component.purl,
                "name": finding.component.name,
                "version": finding.component.version,
                "scope": finding.component.scope,
                "vulnerabilities": [v.to_dict() for v in finding.vulnerabilities],
            }
            for finding in result.findings
        ],
        "not_checkable": [
            {
                "purl": comp.purl,
                "name": comp.name,
                "version_constraint": comp.constraint,
                "sources": list(comp.sources),
            }
            for comp in result.unscanned
        ],
        "ignored": [
            {"purl": comp.purl, "id": vuln.id, "aliases": list(vuln.aliases)}
            for comp, vuln in result.ignored
        ],
        "warnings": inventory.warnings,
        "offline_db_files_skipped": skipped_db_files or [],
    }


def render_table(headers: list[str], rows: list[list[str]], max_width: int = 44) -> list[str]:
    clipped = [
        [cell if len(cell) <= max_width else cell[: max_width - 1] + "…" for cell in row]
        for row in rows
    ]
    widths = [max(len(headers[i]), *(len(row[i]) for row in clipped)) for i in range(len(headers))]
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    out = [fmt.format(*headers).rstrip(), fmt.format(*("-" * w for w in widths)).rstrip()]
    out.extend(fmt.format(*row).rstrip() for row in clipped)
    return out


def severity_cell(severity: str, score: float | None, labels: dict[str, str]) -> str:
    label = labels[severity]
    return f"{label} {score:.1f}" if score is not None else label


__all__ = ["SEVERITIES", "build_scan_evidence", "render_table", "severity_cell"]
