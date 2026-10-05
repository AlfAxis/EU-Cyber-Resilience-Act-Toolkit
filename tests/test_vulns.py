from __future__ import annotations

import json
import zipfile
from pathlib import Path
from typing import Any

import pytest
import requests

from cra_toolkit.errors import ToolkitError, VulnSourceError
from cra_toolkit.sbom import Component, collect
from cra_toolkit.vulns import (
    OsvClient,
    Vulnerability,
    gate_failed,
    merge_duplicates,
    osv_package,
    record_affects,
    scan_offline,
    scan_online,
    vulnerability_from_osv,
)


class FakeResponse:
    def __init__(self, payload: Any = None, *, status: int = 200, bad_json: bool = False) -> None:
        self._payload, self._status, self._bad_json = payload, status, bad_json

    def raise_for_status(self) -> None:
        if self._status >= 400:
            raise requests.HTTPError(f"{self._status} error")

    def json(self) -> Any:
        if self._bad_json:
            raise ValueError("not json")
        return self._payload


class FakeSession:
    """Stands in for requests.Session; records every call it receives."""

    def __init__(
        self,
        pages: dict[str, list[list[str]]] | None = None,
        records: dict[str, dict[str, Any]] | None = None,
        *,
        raises: Exception | None = None,
        status: int = 200,
        bad_json: bool = False,
        short_results: bool = False,
    ) -> None:
        self.pages = pages or {}
        self.records = records or {}
        self.raises, self.status, self.bad_json = raises, status, bad_json
        self.short_results = short_results
        self.queried: list[str] = []
        self.record_fetches: list[str] = []

    def post(self, url: str, *, json: Any, timeout: float) -> FakeResponse:
        if self.raises:
            raise self.raises
        assert url.endswith("/querybatch")
        results = []
        for query in json["queries"]:
            purl = query["package"]["purl"]
            self.queried.append(purl)
            token = query.get("page_token")
            index = int(token[1:]) if token else 0
            pages = self.pages.get(purl, [[]])
            result: dict[str, Any] = {}
            if pages[index]:
                result["vulns"] = [
                    {"id": i, "modified": "2026-01-01T00:00:00Z"} for i in pages[index]
                ]
            if index + 1 < len(pages):
                result["next_page_token"] = f"t{index + 1}"
            results.append(result)
        if self.short_results:
            results = results[:-1]
        return FakeResponse({"results": results}, status=self.status, bad_json=self.bad_json)

    def get(self, url: str, *, timeout: float) -> FakeResponse:
        vuln_id = url.rsplit("/", 1)[1]
        self.record_fetches.append(vuln_id)
        return FakeResponse(self.records[vuln_id])


def osv_record(vuln_id: str, **extra: Any) -> dict[str, Any]:
    return {"id": vuln_id, "summary": f"summary of {vuln_id}", **extra}


def npm(name: str, version: str) -> Component:
    return Component("npm", name, version)


# ------------------------------------------------------------------- online


def test_the_sbom_purl_is_the_exact_key_sent_to_osv(sample_project: Path) -> None:
    components = collect(sample_project).components
    session = FakeSession()
    scan_online(components, OsvClient(session=session))
    resolved = sorted(c.purl for c in components if c.resolved)
    assert sorted(session.queried) == resolved
    assert not any(c.purl in session.queried for c in components if not c.resolved)


def test_online_scan_reports_findings_with_severity_and_fix() -> None:
    comp = npm("lodash", "4.17.15")
    record = osv_record(
        "GHSA-test",
        aliases=["CVE-2099-1"],
        severity=[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        affected=[
            {
                "package": {"ecosystem": "npm", "name": "lodash"},
                "ranges": [
                    {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}
                ],
            },
            {
                "package": {"ecosystem": "npm", "name": "other"},
                "ranges": [{"type": "SEMVER", "events": [{"fixed": "9.9.9"}]}],
            },
        ],
    )
    session = FakeSession({comp.purl: [["GHSA-test"]]}, {"GHSA-test": record})
    result = scan_online([comp], OsvClient(session=session))
    (finding,) = result.findings
    (vuln,) = finding.vulnerabilities
    assert (vuln.severity, vuln.score) == ("critical", 9.8)
    assert vuln.fixed_versions == ("4.17.21",)  # only the matching package's fix
    assert (vuln.id, vuln.aliases) == ("CVE-2099-1", ("GHSA-test",))  # CVE is the primary ID
    assert result.severity_counts()["critical"] == 1


def test_pagination_collects_every_page() -> None:
    comp = npm("busy", "1.0.0")
    session = FakeSession(
        {comp.purl: [["A-1", "A-2"], ["A-3"]]},
        {i: osv_record(i) for i in ("A-1", "A-2", "A-3")},
    )
    result = scan_online([comp], OsvClient(session=session))
    assert sorted(v.id for v in result.findings[0].vulnerabilities) == ["A-1", "A-2", "A-3"]
    assert session.queried == [comp.purl, comp.purl]  # initial query + follow-up page


def test_each_record_is_fetched_only_once() -> None:
    a, b = npm("a", "1.0.0"), npm("b", "1.0.0")
    session = FakeSession(
        {a.purl: [["SHARED"]], b.purl: [["SHARED"]]}, {"SHARED": osv_record("SHARED")}
    )
    result = scan_online([a, b], OsvClient(session=session))
    assert session.record_fetches == ["SHARED"]
    assert len(result.findings) == 2


def test_unresolved_components_are_reported_as_not_checkable() -> None:
    unresolved = Component("pypi", "pyyaml", None, constraint=">=5")
    result = scan_online([unresolved], OsvClient(session=FakeSession()))
    assert result.unscanned == [unresolved]
    assert result.scanned == []


def test_withdrawn_records_are_not_reported() -> None:
    comp = npm("x", "1.0.0")
    session = FakeSession(
        {comp.purl: [["W-1"]]}, {"W-1": osv_record("W-1", withdrawn="2025-01-01")}
    )
    assert scan_online([comp], OsvClient(session=session)).findings == []


def test_ignore_matches_id_or_alias_case_insensitively() -> None:
    comp = npm("x", "1.0.0")
    record = osv_record("GHSA-aaaa", aliases=["CVE-2099-5"])
    session = FakeSession({comp.purl: [["GHSA-aaaa"]]}, {"GHSA-aaaa": record})
    result = scan_online([comp], OsvClient(session=session), ignore=["cve-2099-5"])
    assert result.findings == []
    assert [(v.id, v.aliases) for _, v in result.ignored] == [("CVE-2099-5", ("GHSA-aaaa",))]


@pytest.mark.parametrize(
    "session",
    [
        FakeSession(raises=requests.ConnectionError("no route to host")),
        FakeSession(status=503),
        FakeSession(bad_json=True),
        FakeSession(short_results=True),
    ],
    ids=["connection-error", "http-503", "invalid-json", "result-count-mismatch"],
)
def test_osv_failures_raise_instead_of_reporting_a_false_all_clear(session: FakeSession) -> None:
    with pytest.raises(VulnSourceError):
        scan_online([npm("x", "1.0.0")], OsvClient(session=session))


# ---------------------------------------------------------- record parsing


def test_severity_falls_back_to_the_database_label() -> None:
    assert (
        vulnerability_from_osv(osv_record("X", database_specific={"severity": "MODERATE"})).severity
        == "medium"
    )


def test_severity_from_per_package_label_and_unknown() -> None:
    labelled = osv_record(
        "X",
        affected=[
            {
                "package": {"ecosystem": "npm", "name": "a"},
                "ecosystem_specific": {"severity": "HIGH"},
            }
        ],
    )
    assert vulnerability_from_osv(labelled).severity == "high"
    assert vulnerability_from_osv(osv_record("Y")).severity == "unknown"


def test_cvss4_vector_without_label_is_unknown_not_guessed() -> None:
    record = osv_record(
        "X",
        severity=[
            {
                "type": "CVSS_V4",
                "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            }
        ],
    )
    assert vulnerability_from_osv(record).severity == "unknown"


def test_summary_falls_back_to_first_line_of_details() -> None:
    record = {"id": "X", "details": "First line.\nSecond line."}
    assert vulnerability_from_osv(record).summary == "First line."


def test_pypi_package_names_compare_normalised() -> None:
    record = osv_record(
        "X",
        affected=[
            {
                "package": {"ecosystem": "PyPI", "name": "Flask_Cors"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "4.0"}]}],
            }
        ],
    )
    assert vulnerability_from_osv(record, ("PyPI", "flask-cors")).fixed_versions == ("4.0",)


def test_osv_package_mapping() -> None:
    assert osv_package("pkg:npm/%40babel/core@7.0.0") == ("npm", "@babel/core")
    assert osv_package("pkg:maven/org.apache/commons@1.0") == ("Maven", "org.apache:commons")
    assert osv_package("pkg:golang/github.com/foo/bar@v1.0.0") == ("Go", "github.com/foo/bar")
    assert osv_package("pkg:cargo/serde@1.0.0") == ("crates.io", "serde")
    assert osv_package("pkg:composer/monolog/monolog@2.0.0") == ("Packagist", "monolog/monolog")
    assert osv_package("pkg:deb/debian/curl@7.0") is None


# ------------------------------------------------------- alias de-duplication


def make_record_vuln(
    vuln_id: str,
    aliases: tuple[str, ...] = (),
    severity: str = "unknown",
    score: float | None = None,
    fixed: tuple[str, ...] = (),
) -> Vulnerability:
    return Vulnerability(vuln_id, aliases, f"about {vuln_id}", severity, score, None, fixed, ())


def test_records_sharing_a_cve_collapse_into_one_vulnerability() -> None:
    ghsa = make_record_vuln("GHSA-aaaa", ("CVE-2099-1",), "high", 7.5, ("2.0",))
    pysec = make_record_vuln("PYSEC-2099-1", ("CVE-2099-1",), "high", 7.5, ("2.0", "1.9"))
    (merged,) = merge_duplicates([ghsa, pysec])
    assert merged.id == "CVE-2099-1"  # the CVE is what reports and advisories cite
    assert merged.aliases == ("GHSA-aaaa", "PYSEC-2099-1")
    assert merged.fixed_versions == ("2.0", "1.9")  # union, order kept, no duplicates


def test_merging_is_transitive_through_shared_identifiers() -> None:
    # A links to B, C links to B: all three describe one vulnerability.
    a = make_record_vuln("OSV-A", ("GHSA-b",))
    c = make_record_vuln("OSV-C", ("GHSA-b",))
    unrelated = make_record_vuln("OSV-Z", ("CVE-2099-9",))
    merged = merge_duplicates([a, c, unrelated])
    assert len(merged) == 2
    assert {m.id for m in merged} == {"CVE-2099-9", "GHSA-b"}
    group = next(m for m in merged if m.id == "GHSA-b")
    assert set(group.aliases) == {"OSV-A", "OSV-C"}


def test_the_most_severe_record_wins_the_merge() -> None:
    labelled = make_record_vuln("GHSA-x", ("CVE-2099-2",), "high", None)
    scored = make_record_vuln("PYSEC-x", ("CVE-2099-2",), "critical", 9.8)
    (merged,) = merge_duplicates([labelled, scored])
    assert (merged.severity, merged.score) == ("critical", 9.8)


def test_identifiers_match_case_insensitively_and_unrelated_records_stay_apart() -> None:
    first = make_record_vuln("ghsa-aaaa", ("cve-2099-3",))
    second = make_record_vuln("PYSEC-1", ("CVE-2099-3",))
    other = make_record_vuln("GHSA-bbbb")
    assert len(merge_duplicates([first, second, other])) == 2


def test_a_single_record_gets_the_cve_as_primary_id_too() -> None:
    comp = npm("x", "1.0.0")
    record = osv_record("GHSA-solo", aliases=["CVE-2099-4"])
    session = FakeSession({comp.purl: [["GHSA-solo"]]}, {"GHSA-solo": record})
    (finding,) = scan_online([comp], OsvClient(session=session)).findings
    assert [(v.id, v.aliases) for v in finding.vulnerabilities] == [("CVE-2099-4", ("GHSA-solo",))]


def test_scan_counts_distinct_vulnerabilities_not_records() -> None:
    comp = npm("busy", "1.0.0")
    session = FakeSession(
        {comp.purl: [["GHSA-1", "PYSEC-1", "GHSA-2"]]},
        {
            "GHSA-1": osv_record("GHSA-1", aliases=["CVE-2099-7"]),
            "PYSEC-1": osv_record("PYSEC-1", aliases=["CVE-2099-7"]),
            "GHSA-2": osv_record("GHSA-2", aliases=["CVE-2099-8"]),
        },
    )
    result = scan_online([comp], OsvClient(session=session))
    assert sum(result.severity_counts().values()) == 2


def test_ignoring_any_identifier_of_a_merged_group_ignores_the_whole_group() -> None:
    comp = npm("busy", "1.0.0")
    session = FakeSession(
        {comp.purl: [["GHSA-1", "PYSEC-1"]]},
        {
            "GHSA-1": osv_record("GHSA-1", aliases=["CVE-2099-7"]),
            "PYSEC-1": osv_record("PYSEC-1", aliases=["CVE-2099-7"]),
        },
    )
    result = scan_online([comp], OsvClient(session=session), ignore=["PYSEC-1"])
    assert result.findings == []
    assert [v.id for _, v in result.ignored] == ["CVE-2099-7"]


# ---------------------------------------------------------------- the gate


def make_vuln(severity: str) -> Vulnerability:
    return Vulnerability("V", (), "", severity, None, None, (), ())


@pytest.mark.parametrize(
    ("level", "severities", "expected"),
    [
        ("none", ["critical"], False),
        ("any", ["unknown"], True),
        ("any", [], False),
        ("low", ["unknown"], False),
        ("low", ["low"], True),
        ("high", ["medium", "low"], False),
        ("high", ["high"], True),
        ("high", ["critical"], True),
        ("critical", ["high"], False),
        ("critical", ["critical"], True),
    ],
)
def test_gate_thresholds(level: str, severities: list[str], expected: bool) -> None:
    assert gate_failed([make_vuln(s) for s in severities], level) is expected


# ------------------------------------------------------------------ offline


def found_ids(result: Any) -> set[str]:
    return {v.id for f in result.findings for v in f.vulnerabilities}


def test_offline_directory_matches_ranges_versions_and_normalised_names(
    sample_project: Path, osv_db: Path
) -> None:
    result, db = scan_offline(collect(sample_project).components, osv_db)
    assert found_ids(result) == {
        "CVE-0000-0001",  # TEST-NPM-0001: range 0 .. <4.17.21
        "CVE-0000-0002",  # TEST-PYPI-0001: name 'Requests' vs 'requests', exact versions list
        "TEST-GO-0001",  # two-interval range
        "TEST-MAVEN-0001",  # 2.0-beta9 .. <2.15.0
    }
    assert "TEST-NPM-WITHDRAWN" not in found_ids(result)
    assert "TEST-NPM-ALREADY-FIXED" not in found_ids(result)
    severities = {v.id: v.severity for f in result.findings for v in f.vulnerabilities}
    assert severities == {
        "CVE-0000-0001": "high",  # computed from the CVSS vector (8.1)
        "CVE-0000-0002": "critical",  # database label
        "TEST-GO-0001": "medium",  # MODERATE
        "TEST-MAVEN-0001": "high",
    }
    assert result.source == "offline"
    assert db.skipped == []


def test_offline_findings_are_sorted_most_severe_first(sample_project: Path, osv_db: Path) -> None:
    result, _ = scan_offline(collect(sample_project).components, osv_db)
    ranks = [
        max(
            ("unknown", "low", "medium", "high", "critical").index(v.severity)
            for v in f.vulnerabilities
        )
        for f in result.findings
    ]
    assert ranks == sorted(ranks, reverse=True)


def test_offline_zip_archive_like_the_osv_dump(
    sample_project: Path, osv_db: Path, tmp_path: Path
) -> None:
    archive = tmp_path / "all.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        for path in osv_db.glob("*.json"):
            bundle.writestr(path.name, path.read_text(encoding="utf-8"))
        bundle.writestr("README.txt", "not json")
    result, _ = scan_offline(collect(sample_project).components, archive)
    assert "CVE-0000-0001" in found_ids(result)
    assert len(found_ids(result)) == 4


def test_offline_single_json_file(sample_project: Path, osv_db: Path) -> None:
    result, _ = scan_offline(collect(sample_project).components, osv_db / "TEST-NPM-0001.json")
    assert found_ids(result) == {"CVE-0000-0001"}


def test_offline_unreadable_files_are_skipped_and_reported(tmp_path: Path, osv_db: Path) -> None:
    (tmp_path / "broken.json").write_text("{nope")
    (tmp_path / "TEST-NPM-0001.json").write_text(
        (osv_db / "TEST-NPM-0001.json").read_text(encoding="utf-8")
    )
    _, db = scan_offline([npm("lodash", "4.17.15")], tmp_path)
    assert db.skipped == ["broken.json"]


def test_offline_database_must_exist(tmp_path: Path) -> None:
    with pytest.raises(ToolkitError):
        scan_offline([npm("x", "1.0.0")], tmp_path / "missing")


def test_offline_ignore_list(sample_project: Path, osv_db: Path) -> None:
    result, _ = scan_offline(
        collect(sample_project).components, osv_db, ignore=["CVE-0000-0001", "TEST-GO-0001"]
    )
    assert "CVE-0000-0001" not in found_ids(result)
    assert "TEST-GO-0001" not in found_ids(result)
    assert len(result.ignored) == 2


@pytest.mark.parametrize(
    ("version", "affected"),
    [
        ("v0.9.0", False),
        ("v1.0.0", True),
        ("v1.7.6", True),
        ("v1.7.7", False),  # fixed
        ("v1.8.0", True),  # second interval
        ("v1.8.1", True),
        ("v1.8.2", False),
    ],
)
def test_multi_interval_ranges(version: str, affected: bool) -> None:
    record = json.loads(
        '{"id": "X", "affected": [{"package": {"ecosystem": "Go", "name": "m"}, "ranges": ['
        '{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "1.7.7"},'
        ' {"introduced": "1.8.0"}, {"fixed": "1.8.2"}]}]}]}'
    )
    assert record_affects(record, "Go", "m", version) is affected


@pytest.mark.parametrize(("version", "affected"), [("1.2.3", True), ("1.2.4", False)])
def test_last_affected_is_inclusive(version: str, affected: bool) -> None:
    record = {
        "id": "X",
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "m"},
                "ranges": [
                    {"type": "SEMVER", "events": [{"introduced": "0"}, {"last_affected": "1.2.3"}]}
                ],
            }
        ],
    }
    assert record_affects(record, "npm", "m", version) is affected


def test_git_ranges_are_ignored() -> None:
    record = {
        "id": "X",
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "m"},
                "ranges": [{"type": "GIT", "events": [{"introduced": "0"}]}],
            }
        ],
    }
    assert record_affects(record, "npm", "m", "1.0.0") is False
