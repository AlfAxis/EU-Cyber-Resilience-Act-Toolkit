"""Package URLs (purl) — the single key of the toolkit.

The identifier written into the SBOM is exactly the identifier sent to the
vulnerability database, so there is no name mangling between the two steps.
See https://github.com/package-url/purl-spec
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import quote, unquote


def _encode(segment: str) -> str:
    return quote(segment, safe=":")


def build_purl(
    ptype: str,
    name: str,
    version: str | None = None,
    namespace: str | None = None,
) -> str:
    segments: list[str] = []
    if namespace:
        segments.extend(_encode(part) for part in namespace.split("/") if part)
    segments.append(_encode(name))
    purl = f"pkg:{ptype}/" + "/".join(segments)
    if version:
        purl += "@" + _encode(version)
    return purl


@dataclass(frozen=True)
class Purl:
    type: str
    namespace: str | None
    name: str
    version: str | None


def parse_purl(purl: str) -> Purl:
    if not purl.startswith("pkg:"):
        raise ValueError(f"not a package URL: {purl!r}")
    rest = purl[4:].split("#", 1)[0].split("?", 1)[0].lstrip("/")
    version: str | None = None
    if "@" in rest:
        rest, version = rest.rsplit("@", 1)
        version = unquote(version)
    ptype, _, path = rest.partition("/")
    segments = [unquote(part) for part in path.split("/") if part]
    if not ptype or not segments:
        raise ValueError(f"incomplete package URL: {purl!r}")
    namespace = "/".join(segments[:-1]) or None
    return Purl(ptype.lower(), namespace, segments[-1], version)
