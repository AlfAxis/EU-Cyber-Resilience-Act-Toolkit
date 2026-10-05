"""Vulnerability matching: OSV.dev (online) or a local OSV dump (offline).

The purl written into the SBOM is the exact key sent to OSV.dev, so a component
is looked up under the identity it was inventoried with. Offline mode reads
OSV-format records (a directory, ``.zip`` or ``.json`` file) and matches them
with a *simplified* version ordering; the online path is authoritative.
"""

from __future__ import annotations

import functools
import json
import zipfile
from collections.abc import Iterable, Iterator, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import quote

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from cra_toolkit import __version__
from cra_toolkit.cvss import cvss3_base_score, severity_from_score
from cra_toolkit.errors import ToolkitError, VulnSourceError
from cra_toolkit.i18n import t
from cra_toolkit.purl import parse_purl
from cra_toolkit.sbom import Component, normalize_pypi_name
from cra_toolkit.versions import compare_versions

OSV_API = "https://api.osv.dev/v1"
BATCH_SIZE = 1000  # OSV's documented querybatch limit

#: purl type -> OSV ecosystem name
ECOSYSTEMS = {
    "npm": "npm",
    "pypi": "PyPI",
    "golang": "Go",
    "cargo": "crates.io",
    "composer": "Packagist",
    "maven": "Maven",
}

SEVERITIES = ("unknown", "low", "medium", "high", "critical")
FAIL_LEVELS = ("none", "any", "low", "medium", "high", "critical")

_LABELS = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MODERATE": "medium",
    "MEDIUM": "medium",
    "LOW": "low",
}


@dataclass(frozen=True)
class Vulnerability:
    id: str
    aliases: tuple[str, ...]
    summary: str
    severity: str
    score: float | None
    vector: str | None
    fixed_versions: tuple[str, ...]
    references: tuple[str, ...]

    def identifiers(self) -> set[str]:
        return {self.id.upper(), *(alias.upper() for alias in self.aliases)}

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "aliases": list(self.aliases),
            "summary": self.summary,
            "severity": self.severity,
            "cvss_score": self.score,
            "cvss_vector": self.vector,
            "fixed_versions": list(self.fixed_versions),
            "references": list(self.references),
        }


@dataclass
class Finding:
    component: Component
    vulnerabilities: list[Vulnerability]


@dataclass
class ScanResult:
    source: str
    source_detail: str
    scanned: list[Component]
    unscanned: list[Component]
    findings: list[Finding]
    ignored: list[tuple[Component, Vulnerability]] = field(default_factory=list)

    def all_vulnerabilities(self) -> Iterator[Vulnerability]:
        for finding in self.findings:
            yield from finding.vulnerabilities

    def severity_counts(self) -> dict[str, int]:
        counts = dict.fromkeys(reversed(SEVERITIES), 0)
        for vuln in self.all_vulnerabilities():
            counts[vuln.severity] += 1
        return counts

    def gate_failed(self, level: str) -> bool:
        return gate_failed(self.all_vulnerabilities(), level)


def gate_failed(vulns: Iterable[Vulnerability], level: str) -> bool:
    """Whether any finding reaches ``level``.

    ``any`` trips on every finding (including unknown severity); ``low`` and
    above ignore findings whose severity could not be determined.
    """
    if level == "none":
        return False
    if level == "any":
        return any(True for _ in vulns)
    threshold = SEVERITIES.index(level)
    return any(SEVERITIES.index(v.severity) >= threshold for v in vulns)


def osv_package(purl: str) -> tuple[str, str] | None:
    """Map a purl to OSV's ``(ecosystem, package name)``; ``None`` if unsupported."""
    parsed = parse_purl(purl)
    ecosystem = ECOSYSTEMS.get(parsed.type)
    if ecosystem is None:
        return None
    if parsed.type == "maven":
        name = f"{parsed.namespace}:{parsed.name}" if parsed.namespace else parsed.name
    elif parsed.namespace:
        name = f"{parsed.namespace}/{parsed.name}"
    else:
        name = parsed.name
    return ecosystem, name


# ---------------------------------------------------------------- OSV records


def _label(source: object) -> str | None:
    if isinstance(source, Mapping):
        value = source.get("severity")
        if isinstance(value, str):
            return _LABELS.get(value.upper())
    return None


def _severity(record: Mapping[str, Any]) -> tuple[str, float | None, str | None]:
    best: float | None = None
    vector: str | None = None
    for item in record.get("severity") or []:
        if not isinstance(item, Mapping):
            continue
        raw = str(item.get("score", ""))
        score = cvss3_base_score(raw)
        if score is None and not raw.startswith("CVSS:"):
            try:
                score = float(raw)
            except ValueError:
                score = None
        if score is not None and (best is None or score > best):
            best, vector = score, (raw if raw.startswith("CVSS:") else None)
    if best is not None:
        return severity_from_score(best), best, vector
    label = _label(record.get("database_specific"))
    for affected in record.get("affected") or []:
        if label:
            break
        if isinstance(affected, Mapping):
            label = _label(affected.get("database_specific")) or _label(
                affected.get("ecosystem_specific")
            )
    return label or "unknown", None, None


def _same_package(affected: Mapping[str, Any], ecosystem: str, name: str) -> bool:
    package = affected.get("package")
    if not isinstance(package, Mapping) or package.get("ecosystem") != ecosystem:
        return False
    other = str(package.get("name", ""))
    if ecosystem == "PyPI":
        return normalize_pypi_name(other) == normalize_pypi_name(name)
    return other == name


def vulnerability_from_osv(
    record: Mapping[str, Any], package: tuple[str, str] | None = None
) -> Vulnerability:
    severity, score, vector = _severity(record)
    summary = str(record.get("summary") or "").strip()
    if not summary:
        details = str(record.get("details") or "").strip()
        summary = details.splitlines()[0][:200] if details else ""

    fixed: list[str] = []
    for affected in record.get("affected") or []:
        if not isinstance(affected, Mapping) or (
            package is not None and not _same_package(affected, *package)
        ):
            continue
        for rng in affected.get("ranges") or []:
            for event in rng.get("events") or []:
                value = event.get("fixed") if isinstance(event, Mapping) else None
                if isinstance(value, str) and value not in fixed:
                    fixed.append(value)

    refs = [r for r in record.get("references") or [] if isinstance(r, Mapping) and r.get("url")]
    refs.sort(key=lambda r: r.get("type") != "ADVISORY")
    return Vulnerability(
        id=str(record["id"]),
        aliases=tuple(str(a) for a in record.get("aliases") or []),
        summary=summary,
        severity=severity,
        score=score,
        vector=vector,
        fixed_versions=tuple(fixed),
        references=tuple(str(r["url"]) for r in refs[:3]),
    )


# --------------------------------------------------------------- online (OSV)


class _Response(Protocol):
    def raise_for_status(self) -> None: ...

    def json(self) -> Any: ...


class HttpSession(Protocol):
    """The slice of ``requests.Session`` the client uses (lets tests inject a fake)."""

    def post(self, url: str, *, json: Any, timeout: float) -> _Response: ...

    def get(self, url: str, *, timeout: float) -> _Response: ...


def _build_session() -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=1.0,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset({"GET", "POST"}),
    )
    session.mount("https://", HTTPAdapter(max_retries=retry))
    session.headers["User-Agent"] = f"cra-toolkit/{__version__}"
    return session


class OsvClient:
    """Minimal OSV.dev client: batched purl queries plus record lookups."""

    def __init__(
        self,
        *,
        base_url: str = OSV_API,
        session: HttpSession | None = None,
        timeout: float = 30.0,
        max_workers: int = 8,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._session = session or _build_session()
        self._timeout = timeout
        self._max_workers = max_workers

    def _request(self, method: str, path: str, payload: Mapping[str, Any] | None = None) -> Any:
        url = f"{self.base_url}{path}"
        try:
            if method == "POST":
                response = self._session.post(url, json=payload, timeout=self._timeout)
            else:
                response = self._session.get(url, timeout=self._timeout)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as exc:
            raise VulnSourceError(t("err.osv_unreachable", detail=exc)) from exc
        except ValueError as exc:
            raise VulnSourceError(t("err.osv_bad_response", detail=exc)) from exc

    def query_batch(self, purls: Sequence[str]) -> dict[str, list[str]]:
        """Return ``{purl: [vulnerability ids]}``, following result pagination."""
        found: dict[str, list[str]] = {purl: [] for purl in purls}
        pending: list[tuple[str, str | None]] = [(purl, None) for purl in purls]
        while pending:
            following: list[tuple[str, str | None]] = []
            for start in range(0, len(pending), BATCH_SIZE):
                chunk = pending[start : start + BATCH_SIZE]
                queries: list[dict[str, Any]] = []
                for purl, token in chunk:
                    query: dict[str, Any] = {"package": {"purl": purl}}
                    if token:
                        query["page_token"] = token
                    queries.append(query)
                data = self._request("POST", "/querybatch", {"queries": queries})
                results = data.get("results") if isinstance(data, Mapping) else None
                if not isinstance(results, list) or len(results) != len(chunk):
                    raise VulnSourceError(t("err.osv_bad_response", detail="result count mismatch"))
                for (purl, _), result in zip(chunk, results, strict=True):
                    for vuln in (result or {}).get("vulns") or []:
                        if vuln["id"] not in found[purl]:
                            found[purl].append(vuln["id"])
                    token = (result or {}).get("next_page_token")
                    if token:
                        following.append((purl, token))
            pending = following
        return found

    def get_record(self, vuln_id: str) -> dict[str, Any]:
        record = self._request("GET", f"/vulns/{quote(vuln_id, safe='')}")
        if not isinstance(record, dict):
            raise VulnSourceError(t("err.osv_bad_response", detail=vuln_id))
        return record

    def get_records(self, ids: Iterable[str]) -> dict[str, dict[str, Any]]:
        unique = sorted(set(ids))
        if not unique:
            return {}
        with ThreadPoolExecutor(max_workers=self._max_workers) as pool:
            return dict(zip(unique, pool.map(self.get_record, unique), strict=True))


_PREFIX_RANK = {"CVE": 0, "GHSA": 1, "PYSEC": 2}


def _id_sort_key(identifier: str) -> tuple[int, str]:
    return (_PREFIX_RANK.get(identifier.split("-", 1)[0].upper(), 9), identifier)


def _merge_group(group: Sequence[Vulnerability]) -> Vulnerability:
    identifiers: dict[str, str] = {}
    for vuln in group:
        for identifier in (vuln.id, *vuln.aliases):
            identifiers.setdefault(identifier.upper(), identifier)
    ordered = sorted(identifiers.values(), key=_id_sort_key)
    best = max(group, key=lambda v: (SEVERITIES.index(v.severity), v.score or 0.0))
    return Vulnerability(
        id=ordered[0],
        aliases=tuple(ordered[1:]),
        summary=best.summary or next((v.summary for v in group if v.summary), ""),
        severity=best.severity,
        score=best.score,
        vector=best.vector,
        fixed_versions=tuple(dict.fromkeys(f for v in group for f in v.fixed_versions)),
        references=tuple(dict.fromkeys(r for v in group for r in v.references))[:3],
    )


def merge_duplicates(vulns: Sequence[Vulnerability]) -> list[Vulnerability]:
    """Collapse records that describe the same vulnerability.

    OSV often holds a GHSA and a PYSEC (or RUSTSEC, ...) record for one CVE.
    Records that share any identifier are merged transitively; the CVE becomes
    the primary ID because that is what CSIRT reports and advisories cite, and
    every other identifier stays available as an alias.
    """
    parent: dict[str, str] = {}

    def find(key: str) -> str:
        parent.setdefault(key, key)
        while parent[key] != key:
            parent[key] = parent[parent[key]]
            key = parent[key]
        return key

    for vuln in vulns:
        keys = [vuln.id.upper(), *(alias.upper() for alias in vuln.aliases)]
        for other in keys[1:]:
            parent[find(other)] = find(keys[0])
    groups: dict[str, list[Vulnerability]] = {}
    for vuln in vulns:
        groups.setdefault(find(vuln.id.upper()), []).append(vuln)
    return [_merge_group(group) for group in groups.values()]


def _partition(components: Sequence[Component]) -> tuple[list[Component], list[Component]]:
    scanned: list[Component] = []
    unscanned: list[Component] = []
    for comp in components:
        (scanned if comp.resolved and comp.ptype in ECOSYSTEMS else unscanned).append(comp)
    return scanned, unscanned


def _assemble(
    source: str,
    detail: str,
    components: Sequence[Component],
    records_by_purl: Mapping[str, Sequence[Mapping[str, Any]]],
    ignore: Iterable[str],
) -> ScanResult:
    ignored_ids = {item.upper() for item in ignore}
    scanned, unscanned = _partition(components)
    result = ScanResult(source, detail, scanned, unscanned, [])
    for comp in scanned:
        package = osv_package(comp.purl)
        records = [r for r in records_by_purl.get(comp.purl, ()) if not r.get("withdrawn")]
        kept: list[Vulnerability] = []
        for vuln in merge_duplicates([vulnerability_from_osv(r, package) for r in records]):
            if vuln.identifiers() & ignored_ids:
                result.ignored.append((comp, vuln))
            else:
                kept.append(vuln)
        if kept:
            kept.sort(key=lambda v: (-SEVERITIES.index(v.severity), v.id))
            result.findings.append(Finding(comp, kept))
    result.findings.sort(
        key=lambda f: (
            -max(SEVERITIES.index(v.severity) for v in f.vulnerabilities),
            f.component.name,
        )
    )
    return result


def scan_online(
    components: Sequence[Component], client: OsvClient, ignore: Iterable[str] = ()
) -> ScanResult:
    scanned, _ = _partition(components)
    ids_by_purl = client.query_batch([comp.purl for comp in scanned])
    records = client.get_records(i for ids in ids_by_purl.values() for i in ids)
    by_purl = {purl: [records[i] for i in ids] for purl, ids in ids_by_purl.items()}
    return _assemble("osv.dev", client.base_url, components, by_purl, ignore)


# --------------------------------------------------------------- offline (DB)


def _records_in_json(data: object) -> Iterator[dict[str, Any]]:
    if isinstance(data, dict) and "id" in data:
        yield data
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and "id" in item:
                yield item


def _iter_records(path: Path, skipped: list[str]) -> Iterator[dict[str, Any]]:
    if path.is_dir():
        for child in sorted(path.rglob("*")):
            if child.suffix.lower() in (".json", ".zip") and child.is_file():
                yield from _iter_records(child, skipped)
    elif path.suffix.lower() == ".zip":
        try:
            with zipfile.ZipFile(path) as archive:
                for name in archive.namelist():
                    if not name.lower().endswith(".json"):
                        continue
                    try:
                        yield from _records_in_json(json.loads(archive.read(name)))
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        skipped.append(f"{path.name}:{name}")
        except zipfile.BadZipFile:
            skipped.append(path.name)
    elif path.suffix.lower() == ".json":
        try:
            yield from _records_in_json(json.loads(path.read_text(encoding="utf-8-sig")))
        except (json.JSONDecodeError, UnicodeDecodeError):
            skipped.append(path.name)


def _canonical(ecosystem: str, name: str) -> tuple[str, str]:
    return ecosystem, normalize_pypi_name(name) if ecosystem == "PyPI" else name


def _in_range(events: Sequence[Any], version: str) -> bool:
    """OSV range semantics: walk the events in version order."""
    pairs: list[tuple[str, str]] = []
    for event in events:
        if isinstance(event, Mapping):
            for kind in ("introduced", "fixed", "last_affected"):
                if isinstance(event.get(kind), str):
                    pairs.append((kind, event[kind]))

    def order(a: tuple[str, str], b: tuple[str, str]) -> int:
        if a[1] == "0" or b[1] == "0":
            return (a[1] != "0") - (b[1] != "0")
        return compare_versions(a[1], b[1])

    affected = False
    for kind, bound in sorted(pairs, key=functools.cmp_to_key(order)):
        if kind == "introduced":
            if bound == "0" or compare_versions(version, bound) >= 0:
                affected = True
        elif kind == "fixed":
            if compare_versions(version, bound) >= 0:
                affected = False
        elif compare_versions(version, bound) > 0:  # last_affected
            affected = False
    return affected


def record_affects(record: Mapping[str, Any], ecosystem: str, name: str, version: str) -> bool:
    for affected in record.get("affected") or []:
        if not isinstance(affected, Mapping) or not _same_package(affected, ecosystem, name):
            continue
        if version in (affected.get("versions") or []):
            return True
        for rng in affected.get("ranges") or []:
            if (
                isinstance(rng, Mapping)
                and rng.get("type") in ("SEMVER", "ECOSYSTEM")
                and _in_range(rng.get("events") or [], version)
            ):
                return True
    return False


class OfflineDb:
    """OSV records restricted to the packages we actually inventoried."""

    def __init__(
        self, path: Path, index: dict[tuple[str, str], list[dict[str, Any]]], skipped: list[str]
    ):
        self.path = path
        self._index = index
        self.skipped = skipped

    @classmethod
    def load(cls, path: Path, wanted: Iterable[tuple[str, str]]) -> OfflineDb:
        if not path.exists():
            raise ToolkitError(t("err.offline_db_missing", path=path))
        wanted_set = {_canonical(eco, name) for eco, name in wanted}
        index: dict[tuple[str, str], list[dict[str, Any]]] = {}
        skipped: list[str] = []
        for record in _iter_records(path, skipped):
            for affected in record.get("affected") or []:
                package = affected.get("package") if isinstance(affected, Mapping) else None
                if not isinstance(package, Mapping):
                    continue
                key = _canonical(str(package.get("ecosystem", "")), str(package.get("name", "")))
                if key in wanted_set and record not in index.setdefault(key, []):
                    index[key].append(record)
        return cls(path, index, skipped)

    def records_for(self, purl: str, version: str) -> list[dict[str, Any]]:
        package = osv_package(purl)
        if package is None:
            return []
        ecosystem, name = package
        return [
            record
            for record in self._index.get(_canonical(ecosystem, name), [])
            if record_affects(record, ecosystem, name, version)
        ]


def scan_offline(
    components: Sequence[Component], db_path: Path, ignore: Iterable[str] = ()
) -> tuple[ScanResult, OfflineDb]:
    scanned, _ = _partition(components)
    wanted = [pkg for comp in scanned if (pkg := osv_package(comp.purl)) is not None]
    db = OfflineDb.load(db_path, wanted)
    by_purl = {comp.purl: db.records_for(comp.purl, comp.version or "") for comp in scanned}
    return _assemble("offline", str(db_path), components, by_purl, ignore), db
