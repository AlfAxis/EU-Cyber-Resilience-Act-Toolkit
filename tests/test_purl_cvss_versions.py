from __future__ import annotations

import pytest

from cra_toolkit.cvss import cvss3_base_score, severity_from_score
from cra_toolkit.purl import build_purl, parse_purl
from cra_toolkit.versions import compare_versions

# ---------------------------------------------------------------------- purl


def test_simple_purl() -> None:
    assert build_purl("pypi", "requests", "2.31.0") == "pkg:pypi/requests@2.31.0"


def test_npm_scope_is_percent_encoded() -> None:
    purl = build_purl("npm", "core", "7.23.0", namespace="@babel")
    assert purl == "pkg:npm/%40babel/core@7.23.0"


def test_plus_in_version_is_encoded() -> None:
    purl = build_purl("golang", "bar", "v2.0.0+incompatible", namespace="github.com/foo")
    assert purl == "pkg:golang/github.com/foo/bar@v2.0.0%2Bincompatible"


def test_purl_without_version() -> None:
    assert build_purl("pypi", "numpy") == "pkg:pypi/numpy"


@pytest.mark.parametrize(
    ("ptype", "name", "version", "namespace"),
    [
        ("npm", "core", "7.23.0", "@babel"),
        ("golang", "semver", "v3.2.0+incompatible", "github.com/Masterminds"),
        ("maven", "log4j-core", "2.14.1", "org.apache.logging.log4j"),
        ("pypi", "requests", None, None),
    ],
)
def test_parse_round_trips_build(
    ptype: str, name: str, version: str | None, namespace: str | None
) -> None:
    parsed = parse_purl(build_purl(ptype, name, version, namespace))
    assert (parsed.type, parsed.name, parsed.version, parsed.namespace) == (
        ptype,
        name,
        version,
        namespace,
    )


@pytest.mark.parametrize("bad", ["requests", "pkg:", "pkg:npm", "https://x"])
def test_parse_rejects_non_purls(bad: str) -> None:
    with pytest.raises(ValueError, match="package URL"):
        parse_purl(bad)


# --------------------------------------------------------------------- cvss


@pytest.mark.parametrize(
    ("vector", "score"),
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 7.8),
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),  # classic reflected XSS
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ],
)
def test_cvss3_base_scores_match_the_specification(vector: str, score: float) -> None:
    assert cvss3_base_score(vector) == score


@pytest.mark.parametrize(
    "vector",
    [
        "",
        "CVSS:4.0/AV:N",
        "CVSS:3.1/AV:N/AC:L",
        "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "7.5",
    ],
)
def test_invalid_or_unsupported_vectors_return_none(vector: str) -> None:
    assert cvss3_base_score(vector) is None


@pytest.mark.parametrize(
    ("score", "label"),
    [(10.0, "critical"), (9.0, "critical"), (8.9, "high"), (7.0, "high"), (6.9, "medium"),
     (4.0, "medium"), (3.9, "low"), (0.1, "low"), (0.0, "unknown")],
)  # fmt: skip
def test_severity_bands(score: float, label: str) -> None:
    assert severity_from_score(score) == label


# ----------------------------------------------------------------- versions


@pytest.mark.parametrize(
    ("older", "newer"),
    [
        ("1.0.0", "1.0.1"),
        ("1.9.0", "1.10.0"),
        ("1.0.0-rc1", "1.0.0"),
        ("1.0.0-alpha", "1.0.0-beta"),
        ("1.0.0-beta", "1.0.0-rc1"),
        ("2.0-beta9", "2.14.1"),
        ("v0.3.7", "v0.3.8"),
        ("4.17.15", "4.17.21"),
        ("2.0.0.dev1", "2.0.0"),
    ],
)
def test_ordering(older: str, newer: str) -> None:
    assert compare_versions(older, newer) == -1
    assert compare_versions(newer, older) == 1


@pytest.mark.parametrize(
    ("left", "right"),
    [("1.0", "1.0.0"), ("v1.2.3", "1.2.3"), ("1.2.3+build5", "1.2.3"), ("1.0.Final", "1.0")],
)
def test_equivalent_versions(left: str, right: str) -> None:
    assert compare_versions(left, right) == 0
