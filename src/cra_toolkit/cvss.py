"""CVSS v3.x base-score calculation.

OSV records usually carry only the vector string; the numeric score is needed
to rank findings and to gate CI on a severity threshold. Implements the
CVSS v3.1 base equations (https://www.first.org/cvss/v3.1/specification-document).
CVSS v4.0 vectors are not computed here — callers fall back to the database's
own severity label.
"""

from __future__ import annotations

import math

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}

_REQUIRED = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def _roundup(value: float) -> float:
    """Round up to one decimal, per CVSS v3.1 Appendix A (float-safe)."""
    scaled = round(value * 100000)
    if scaled % 10000 == 0:
        return scaled / 100000.0
    return (math.floor(scaled / 10000) + 1) / 10.0


def cvss3_base_score(vector: str) -> float | None:
    """Return the base score for a ``CVSS:3.x/...`` vector, or ``None`` if invalid."""
    parts = vector.strip().split("/")
    if not parts or parts[0] not in ("CVSS:3.0", "CVSS:3.1"):
        return None
    metrics: dict[str, str] = {}
    for part in parts[1:]:
        key, sep, value = part.partition(":")
        if not sep:
            return None
        metrics[key] = value
    if any(key not in metrics for key in _REQUIRED):
        return None

    try:
        scope_changed = {"U": False, "C": True}[metrics["S"]]
        pr_table = _PR_CHANGED if scope_changed else _PR_UNCHANGED
        exploitability = 8.22 * _AV[metrics["AV"]] * _AC[metrics["AC"]]
        exploitability *= pr_table[metrics["PR"]] * _UI[metrics["UI"]]
        iss = 1 - ((1 - _CIA[metrics["C"]]) * (1 - _CIA[metrics["I"]]) * (1 - _CIA[metrics["A"]]))
    except KeyError:
        return None

    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
    if impact <= 0:
        return 0.0
    if scope_changed:
        return _roundup(min(1.08 * (impact + exploitability), 10.0))
    return _roundup(min(impact + exploitability, 10.0))


def severity_from_score(score: float) -> str:
    """Map a numeric score to the CVSS qualitative rating (lower-case)."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "unknown"
