"""Dependency discovery and CycloneDX 1.6 SBOM generation.

The CRA is concerned with what you *shipped*, not what you declared, so
lockfiles are preferred over manifests. Per directory and ecosystem the first
matching source in ``SOURCES`` wins; manifests with version ranges
(``requirements.txt``, ``pom.xml``) yield *unresolved* components that are kept
in the SBOM, flagged, and reported as "not checkable" by ``scan`` rather than
silently dropped.

A lockfile that cannot be parsed aborts the run: an SBOM that quietly misses a
whole lockfile is worse than no SBOM.
"""

from __future__ import annotations

import base64
import binascii
import fnmatch
import json
import os
import re
import uuid
import xml.etree.ElementTree as ET
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cra_toolkit import __version__
from cra_toolkit.errors import ToolkitError
from cra_toolkit.i18n import t
from cra_toolkit.purl import build_purl

DEFAULT_EXCLUDE_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".cra",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "site-packages",
        "vendor",
        "target",
    }
)

_SCOPE_RANK = {"required": 0, "optional": 1, "excluded": 2}


@dataclass(frozen=True)
class Component:
    ptype: str
    name: str
    version: str | None
    scope: str = "required"
    sources: tuple[str, ...] = ()
    hashes: tuple[tuple[str, str], ...] = ()
    constraint: str | None = None

    @property
    def resolved(self) -> bool:
        return self.version is not None

    @property
    def purl(self) -> str:
        namespace, name = split_name(self.ptype, self.name)
        return build_purl(self.ptype, name, self.version, namespace)


def split_name(ptype: str, name: str) -> tuple[str | None, str]:
    """Split an ecosystem name into purl ``(namespace, name)``."""
    if ptype == "maven":
        group, _, artifact = name.partition(":")
        return (group or None, artifact or name)
    if ptype in ("npm", "composer", "golang") and "/" in name:
        namespace, _, last = name.rpartition("/")
        return namespace, last
    return None, name


@dataclass
class ParseResult:
    components: list[Component] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


Parser = Callable[[str, str], ParseResult]


def _load_json(text: str, rel: str) -> dict[str, Any]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ToolkitError(t("err.unparsable_source", path=rel, detail=exc)) from exc
    if not isinstance(data, dict):
        raise ToolkitError(
            t("err.unparsable_source", path=rel, detail="top level is not an object")
        )
    return data


def normalize_pypi_name(name: str) -> str:
    """PEP 503 normalisation, which is also what the purl spec and OSV use."""
    return re.sub(r"[-_.]+", "-", name).lower()


_VERSION_LIKE = re.compile(r"v?\d+(\.\d+)*([-+.][0-9A-Za-z.+-]+)?")


def _looks_like_version(value: str) -> bool:
    return bool(_VERSION_LIKE.fullmatch(value)) and not value.endswith("-dev")


# --------------------------------------------------------------------- npm

_INTEGRITY_ALGS = (
    ("sha512", "SHA-512"),
    ("sha384", "SHA-384"),
    ("sha256", "SHA-256"),
    ("sha1", "SHA-1"),
)


def _npm_hashes(integrity: object) -> tuple[tuple[str, str], ...]:
    """Convert an SRI string (``sha512-<base64>``) to a CycloneDX hash."""
    if not isinstance(integrity, str):
        return ()
    by_alg: dict[str, str] = {}
    for token in integrity.split():
        alg, _, encoded = token.partition("-")
        by_alg[alg] = encoded.split("?", 1)[0]
    for alg, cdx_alg in _INTEGRITY_ALGS:
        digest = by_alg.get(alg)
        if not digest:
            continue
        try:
            return ((cdx_alg, base64.b64decode(digest, validate=True).hex()),)
        except (binascii.Error, ValueError):
            continue
    return ()


def _npm_component(name: str, meta: Mapping[str, Any], rel: str) -> Component:
    version = meta.get("version")
    if meta.get("dev") is True:
        scope = "excluded"
    elif meta.get("optional") is True or meta.get("devOptional") is True:
        scope = "optional"
    else:
        scope = "required"
    if isinstance(version, str) and _looks_like_version(version):
        return Component("npm", name, version, scope, (rel,), _npm_hashes(meta.get("integrity")))
    return Component("npm", name, None, scope, (rel,), constraint=str(version or "*"))


def _walk_npm_v1(deps: Mapping[str, Any], out: list[Component], rel: str) -> None:
    for name, meta in deps.items():
        if not isinstance(meta, dict):
            continue
        resolved_name, entry = name, dict(meta)
        version = entry.get("version")
        if isinstance(version, str) and version.startswith("npm:"):
            alias_name, _, alias_version = version[4:].rpartition("@")  # npm:@scope/real@1.2.3
            resolved_name, entry["version"] = alias_name, alias_version
        out.append(_npm_component(resolved_name, entry, rel))
        nested = entry.get("dependencies")
        if isinstance(nested, dict):
            _walk_npm_v1(nested, out, rel)


def parse_package_lock(text: str, rel: str) -> ParseResult:
    """``package-lock.json`` / ``npm-shrinkwrap.json`` (lockfileVersion 1, 2 and 3)."""
    data = _load_json(text, rel)
    result = ParseResult()
    packages = data.get("packages")
    if isinstance(packages, dict):  # v2 and v3
        marker = "node_modules/"
        for key, meta in packages.items():
            if not key or not isinstance(meta, dict) or meta.get("link"):
                continue
            index = key.rfind(marker)
            if index < 0:  # a workspace member: the project's own code, not a dependency
                continue
            name = meta.get("name") or key[index + len(marker) :]
            result.components.append(_npm_component(name, meta, rel))
    elif isinstance(data.get("dependencies"), dict):  # v1
        _walk_npm_v1(data["dependencies"], result.components, rel)
    return result


# -------------------------------------------------------------------- TOML

_KEY_VALUE = re.compile(r"^([A-Za-z0-9_-]+)\s*=\s*(.*)$")
_BASIC_STRING = re.compile(r'^"((?:[^"\\]|\\.)*)"')
_LITERAL_STRING = re.compile(r"^'([^']*)'")
_QUOTED = re.compile(r"\"((?:[^\"\\]|\\.)*)\"|'([^']*)'")


def _toml_string(raw: str) -> str | None:
    match = _BASIC_STRING.match(raw)
    if match:
        try:
            return str(json.loads(f'"{match.group(1)}"'))
        except json.JSONDecodeError:
            return match.group(1)
    match = _LITERAL_STRING.match(raw)
    return match.group(1) if match else None


def toml_package_tables(text: str) -> list[dict[str, Any]]:
    """Extract the ``[[package]]`` tables of ``Cargo.lock`` / ``poetry.lock``.

    Deliberately not a general TOML parser (that would need ``tomli`` on
    Python 3.10 and break the single-dependency promise). It reads only the
    scalar keys and string arrays at the top level of each ``[[package]]`` plus
    the keys of a ``[package.source]`` sub-table (stored as ``source_table``),
    which is all that lockfile formats use for inventory purposes.
    """
    packages: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    section = ""
    in_array = False
    for line in text.splitlines():
        stripped = line.strip()
        if in_array:
            if stripped.startswith("]"):
                in_array = False
            continue
        if not stripped or stripped.startswith("#"):
            continue
        is_header = (
            stripped.startswith("[")
            and not stripped.startswith("[ ")
            and stripped.endswith("]")
            and not _KEY_VALUE.match(stripped)
        )
        if is_header:
            section = stripped.strip("[] ")
            if stripped.startswith("[[") and section == "package":
                current = {}
                packages.append(current)
            continue
        match = _KEY_VALUE.match(stripped)
        if not match or current is None:
            continue
        key, raw = match.group(1), match.group(2).strip()
        if section == "package":
            target = current
        elif section == "package.source":
            target = current.setdefault("source_table", {})
        else:
            continue
        if raw.startswith("["):
            if raw.count("[") > raw.count("]") or not raw.rstrip().endswith("]"):
                in_array = True
                continue
            target[key] = [a or b for a, b in _QUOTED.findall(raw)]
        elif raw.startswith(("true", "false")):
            target[key] = raw.startswith("true")
        else:
            value = _toml_string(raw)
            if value is not None:
                target[key] = value
    return packages


# --------------------------------------------------------------------- PyPI


def parse_poetry_lock(text: str, rel: str) -> ParseResult:
    result = ParseResult()
    for pkg in toml_package_tables(text):
        name, version = pkg.get("name"), pkg.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            continue
        source = pkg.get("source_table") or {}
        if source.get("type") in ("directory", "file"):
            result.warnings.append(t("warn.local_dependency", name=name, path=rel))
            continue
        groups = pkg.get("groups")
        if pkg.get("category") == "dev" or (isinstance(groups, list) and "main" not in groups):
            scope = "excluded"
        elif pkg.get("optional") is True:
            scope = "optional"
        else:
            scope = "required"
        result.components.append(
            Component("pypi", normalize_pypi_name(name), version, scope, (rel,))
        )
    return result


def parse_pipfile_lock(text: str, rel: str) -> ParseResult:
    data = _load_json(text, rel)
    result = ParseResult()
    for section, scope in (("default", "required"), ("develop", "excluded")):
        entries = data.get(section)
        if not isinstance(entries, dict):
            continue
        for name, meta in entries.items():
            if not isinstance(meta, dict):
                continue
            if any(key in meta for key in ("git", "path", "file")):
                result.warnings.append(t("warn.local_dependency", name=name, path=rel))
                continue
            spec = str(meta.get("version", ""))
            norm = normalize_pypi_name(name)
            if spec.startswith("==") and len(spec) > 2:
                result.components.append(Component("pypi", norm, spec[2:], scope, (rel,)))
            else:
                result.components.append(
                    Component("pypi", norm, None, scope, (rel,), constraint=spec or "*")
                )
    return result


_REQ_LINE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$")
_EXACT_PIN = re.compile(r"===?\s*([A-Za-z0-9][A-Za-z0-9._+!-]*)")


def parse_requirements(text: str, rel: str) -> ParseResult:
    """``requirements.txt``: only exact pins (``==``) are resolved."""
    result = ParseResult()
    logical: list[str] = []
    buffer = ""
    for raw in text.splitlines():
        line = raw.rstrip()
        if line.endswith("\\"):
            buffer += line[:-1] + " "
            continue
        logical.append(buffer + line)
        buffer = ""
    if buffer:
        logical.append(buffer)

    for entry in logical:
        line = re.sub(r"(^|\s)#.*$", "", entry).strip()
        if not line or "://" in line or line.startswith(("-", ".", "/")):
            continue  # options (-r, -e, --index-url), URLs and local paths
        line = line.split(";", 1)[0]  # environment markers
        line = " ".join(token for token in line.split() if not token.startswith("--"))
        match = _REQ_LINE.match(line)
        if not match:
            continue
        name, spec = match.group(1), match.group(3).strip()
        pinned = _EXACT_PIN.fullmatch(spec) if "," not in spec else None
        norm = normalize_pypi_name(name)
        if pinned and "*" not in spec:
            result.components.append(Component("pypi", norm, pinned.group(1), "required", (rel,)))
        else:
            result.components.append(
                Component("pypi", norm, None, "required", (rel,), constraint=spec or "*")
            )
    return result


# ----------------------------------------------------------------------- Go

_GO_BLOCK_START = re.compile(r"^(require|replace|exclude|retract)\s*\($")


def _go_tokens(line: str) -> list[str]:
    return [token.strip('"`') for token in line.split()]


def _is_local_path(token: str) -> bool:
    return token.startswith((".", "/", "\\")) or bool(re.match(r"^[A-Za-z]:[\\/]", token))


def parse_go_mod(text: str, rel: str) -> ParseResult:
    result = ParseResult()
    requires: list[tuple[str, str]] = []
    replaces: dict[tuple[str, str | None], tuple[str, str | None] | None] = {}
    block: str | None = None

    def handle(kind: str, body: str) -> None:
        tokens = _go_tokens(body)
        if kind == "require" and len(tokens) >= 2:
            requires.append((tokens[0], tokens[1]))
        elif kind == "replace" and "=>" in tokens:
            arrow = tokens.index("=>")
            left, right = tokens[:arrow], tokens[arrow + 1 :]
            if not left or not right:
                return
            old_key = (left[0], left[1] if len(left) > 1 else None)
            if len(right) == 1 or _is_local_path(right[0]):
                replaces[old_key] = None  # replaced by a local directory
            else:
                replaces[old_key] = (right[0], right[1])

    for raw in text.splitlines():
        line = raw.split("//", 1)[0].strip()
        if not line:
            continue
        if block:
            if line == ")":
                block = None
            else:
                handle(block, line)
            continue
        start = _GO_BLOCK_START.match(line)
        if start:
            block = start.group(1)
            continue
        keyword, _, body = line.partition(" ")
        if keyword in ("require", "replace"):
            handle(keyword, body.strip())

    for path, version in requires:
        key = (path, version) if (path, version) in replaces else (path, None)
        if key in replaces:
            replacement = replaces[key]
            if replacement is None:
                result.warnings.append(t("warn.local_dependency", name=path, path=rel))
                continue
            path, version = replacement[0], replacement[1] or version
        result.components.append(Component("golang", path, version, "required", (rel,)))
    return result


# --------------------------------------------------------------------- Cargo


def parse_cargo_lock(text: str, rel: str) -> ParseResult:
    result = ParseResult()
    for pkg in toml_package_tables(text):
        name, version, source = pkg.get("name"), pkg.get("version"), pkg.get("source")
        if not isinstance(name, str) or not isinstance(version, str) or not isinstance(source, str):
            continue  # no source = workspace member, i.e. the project itself
        checksum = pkg.get("checksum")
        hashes: tuple[tuple[str, str], ...] = ()
        if isinstance(checksum, str) and re.fullmatch(r"[0-9a-fA-F]{64}", checksum):
            hashes = (("SHA-256", checksum.lower()),)
        result.components.append(Component("cargo", name, version, "required", (rel,), hashes))
    return result


# ------------------------------------------------------------------ Composer


def parse_composer_lock(text: str, rel: str) -> ParseResult:
    data = _load_json(text, rel)
    result = ParseResult()
    for section, scope in (("packages", "required"), ("packages-dev", "excluded")):
        entries = data.get(section)
        if not isinstance(entries, list):
            continue
        for pkg in entries:
            if not isinstance(pkg, dict) or not isinstance(pkg.get("name"), str):
                continue
            name, version = pkg["name"], str(pkg.get("version", ""))
            if _looks_like_version(version):
                result.components.append(
                    Component("composer", name, version.removeprefix("v"), scope, (rel,))
                )
            else:
                result.components.append(
                    Component("composer", name, None, scope, (rel,), constraint=version or "*")
                )
    return result


# --------------------------------------------------------------------- Maven

_MAVEN_SCOPE = {
    "compile": "required",
    "runtime": "required",
    "system": "required",
    "import": "required",
    "provided": "optional",
    "test": "excluded",
}
_PROPERTY = re.compile(r"\$\{([^}]+)\}")


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child_text(element: ET.Element, tag: str) -> str | None:
    child = element.find(f"{{*}}{tag}")
    if child is None or child.text is None:
        return None
    return child.text.strip() or None


def parse_pom(text: str, rel: str) -> ParseResult:
    # pom.xml never legitimately needs a DTD. Refusing any DOCTYPE/ENTITY closes the
    # entity-expansion ("billion laughs") hole of the stdlib parser without adding a
    # runtime dependency such as defusedxml.
    upper = text.upper()
    if "<!DOCTYPE" in upper or "<!ENTITY" in upper:
        raise ToolkitError(
            t("err.unparsable_source", path=rel, detail="DOCTYPE/ENTITY not allowed")
        )
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ToolkitError(t("err.unparsable_source", path=rel, detail=exc)) from exc

    parent = root.find("{*}parent")
    group = _child_text(root, "groupId") or (parent is not None and _child_text(parent, "groupId"))
    version = _child_text(root, "version") or (
        parent is not None and _child_text(parent, "version")
    )
    props: dict[str, str] = {}
    prop_root = root.find("{*}properties")
    if prop_root is not None:
        for child in prop_root:
            if child.text:
                props[_local(child.tag)] = child.text.strip()
    for key in ("project.version", "pom.version", "version"):
        if version:
            props.setdefault(key, str(version))
    for key in ("project.groupId", "pom.groupId", "groupId"):
        if group:
            props.setdefault(key, str(group))
    artifact_id = _child_text(root, "artifactId")
    if artifact_id:
        props.setdefault("project.artifactId", artifact_id)

    def interpolate(value: str | None) -> str | None:
        if value is None:
            return None
        for _ in range(10):
            replaced = _PROPERTY.sub(lambda m: props.get(m.group(1), m.group(0)), value)
            if replaced == value:
                break
            value = replaced
        return value

    result = ParseResult()
    deps = root.find("{*}dependencies")
    if deps is None:
        return result
    for dep in deps.findall("{*}dependency"):
        group_id = interpolate(_child_text(dep, "groupId"))
        artifact = interpolate(_child_text(dep, "artifactId"))
        if not group_id or not artifact or "${" in group_id or "${" in artifact:
            result.warnings.append(t("warn.unresolvable_dependency", path=rel))
            continue
        scope = _MAVEN_SCOPE.get(_child_text(dep, "scope") or "compile", "required")
        if (_child_text(dep, "optional") or "").lower() == "true":
            scope = "optional" if scope == "required" else scope
        raw_version = interpolate(_child_text(dep, "version"))
        name = f"{group_id}:{artifact}"
        if raw_version and "${" not in raw_version and not re.search(r"[\[\](),]", raw_version):
            result.components.append(Component("maven", name, raw_version, scope, (rel,)))
        else:
            constraint = raw_version or t("note.version_managed")
            result.components.append(
                Component("maven", name, None, scope, (rel,), constraint=constraint)
            )
    return result


# ----------------------------------------------------------------- discovery

# Per ecosystem, in order of preference: the first file present in a directory wins.
SOURCES: dict[str, tuple[tuple[str, Parser], ...]] = {
    "npm": (
        ("npm-shrinkwrap.json", parse_package_lock),
        ("package-lock.json", parse_package_lock),
    ),
    "pypi": (
        ("poetry.lock", parse_poetry_lock),
        ("Pipfile.lock", parse_pipfile_lock),
        ("requirements.txt", parse_requirements),
    ),
    "golang": (("go.mod", parse_go_mod),),
    "cargo": (("Cargo.lock", parse_cargo_lock),),
    "composer": (("composer.lock", parse_composer_lock),),
    "maven": (("pom.xml", parse_pom),),
}

# Manifests that declare dependencies without pinning them. Only flagged, never parsed.
UNLOCKED_MANIFESTS = {
    "package.json": "npm",
    "Cargo.toml": "cargo",
    "composer.json": "composer",
    "Pipfile": "pypi",
    "pyproject.toml": "pypi",
}


@dataclass
class Inventory:
    root: Path
    components: list[Component]
    sources: list[str]
    warnings: list[str]


def _is_excluded(rel: Path, patterns: Sequence[str]) -> bool:
    posix = rel.as_posix()
    return any(fnmatch.fnmatch(posix, pat) or fnmatch.fnmatch(rel.name, pat) for pat in patterns)


def discover(
    root: Path, exclude: Sequence[str] = ()
) -> tuple[list[tuple[str, str, Parser]], list[str]]:
    """Find the dependency sources to read. Returns ``(sources, warnings)``.

    Each source is ``(relative POSIX path, ecosystem, parser)``.
    """
    sources: list[tuple[str, str, Parser]] = []
    eco_dirs: dict[str, set[Path]] = {eco: set() for eco in SOURCES}
    manifests: list[tuple[Path, str, str]] = []

    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = Path(dirpath).relative_to(root)
        dirnames[:] = sorted(
            d
            for d in dirnames
            if d not in DEFAULT_EXCLUDE_DIRS and not _is_excluded(rel_dir / d, exclude)
        )
        present = set(filenames)
        for eco, candidates in SOURCES.items():
            for filename, parser in candidates:
                if filename in present and not _is_excluded(rel_dir / filename, exclude):
                    sources.append(((rel_dir / filename).as_posix(), eco, parser))
                    eco_dirs[eco].add(rel_dir)
                    break
        for filename, eco in UNLOCKED_MANIFESTS.items():
            if filename in present and not _is_excluded(rel_dir / filename, exclude):
                manifests.append((rel_dir, filename, eco))

    warnings: list[str] = []
    for rel_dir, filename, eco in manifests:
        covered = any(candidate in eco_dirs[eco] for candidate in (rel_dir, *rel_dir.parents))
        if not covered:
            shown = (rel_dir / filename).as_posix()
            warnings.append(t("warn.manifest_without_lock", path=shown))
    return sorted(sources), warnings


def _merge(components: Sequence[Component]) -> list[Component]:
    merged: dict[tuple[str, str, str | None, str | None], Component] = {}
    for comp in components:
        key = (comp.ptype, comp.name, comp.version, None if comp.resolved else comp.constraint)
        existing = merged.get(key)
        if existing is None:
            merged[key] = comp
            continue
        scope = min(existing.scope, comp.scope, key=_SCOPE_RANK.__getitem__)
        sources = tuple(sorted({*existing.sources, *comp.sources}))
        merged[key] = replace(existing, scope=scope, sources=sources)
    return sorted(
        merged.values(),
        key=lambda c: (c.ptype, c.name.lower(), c.version or "", c.constraint or ""),
    )


def collect(root: Path, exclude: Sequence[str] = ()) -> Inventory:
    if not root.is_dir():
        raise ToolkitError(t("err.not_a_directory", path=root))
    sources, warnings = discover(root, exclude)
    components: list[Component] = []
    for rel, _eco, parser in sources:
        path = root / rel
        try:
            text = path.read_text(encoding="utf-8-sig")
        except (OSError, UnicodeDecodeError) as exc:
            raise ToolkitError(t("err.cannot_read", path=rel, detail=exc)) from exc
        parsed = parser(text, rel)
        components.extend(parsed.components)
        warnings.extend(parsed.warnings)
    return Inventory(root, _merge(components), [rel for rel, _, _ in sources], warnings)


# ------------------------------------------------------------- CycloneDX 1.6


def _component_json(comp: Component, used_refs: set[str]) -> dict[str, Any]:
    namespace, name = split_name(comp.ptype, comp.name)
    ref = comp.purl
    suffix = 1
    while ref in used_refs:
        suffix += 1
        ref = f"{comp.purl}#{suffix}"
    used_refs.add(ref)

    entry: dict[str, Any] = {"type": "library", "bom-ref": ref}
    if namespace and comp.ptype in ("npm", "maven", "composer"):
        entry["group"] = namespace
        entry["name"] = name
    else:
        entry["name"] = comp.name
    if comp.version:
        entry["version"] = comp.version
    entry["scope"] = comp.scope
    if comp.hashes:
        entry["hashes"] = [{"alg": alg, "content": content} for alg, content in comp.hashes]
    entry["purl"] = comp.purl
    properties = [{"name": "cra-toolkit:source", "value": src} for src in comp.sources]
    if not comp.resolved:
        properties.append({"name": "cra-toolkit:unresolved", "value": "true"})
        properties.append(
            {"name": "cra-toolkit:version-constraint", "value": comp.constraint or "*"}
        )
    entry["properties"] = properties
    return entry


def build_bom(
    inventory: Inventory,
    *,
    product: Mapping[str, Any] | None = None,
    timestamp: datetime | None = None,
    serial: str | None = None,
) -> dict[str, Any]:
    """Build a CycloneDX 1.6 BOM (as a JSON-serialisable dict)."""
    moment = (timestamp or datetime.now(timezone.utc)).astimezone(timezone.utc)
    stamp = moment.strftime("%Y-%m-%dT%H:%M:%SZ")

    subject: dict[str, Any]
    metadata: dict[str, Any] = {
        "timestamp": stamp,
        "lifecycles": [{"phase": "pre-build"}],
        "tools": {
            "components": [
                {
                    "type": "application",
                    "name": "cra-toolkit",
                    "version": __version__,
                    "description": "EU Cyber Resilience Act compliance toolkit",
                }
            ]
        },
    }
    if product:
        subject = {
            "type": product.get("product_type") or "application",
            "bom-ref": f"product:{product['id']}",
            "name": product["name"],
            "version": product["version"],
        }
        maker = product.get("manufacturer") or {}
        if maker.get("name"):
            entity: dict[str, Any] = {"name": maker["name"]}
            if maker.get("website"):
                entity["url"] = [maker["website"]]
            if maker.get("email"):
                entity["contact"] = [{"email": maker["email"]}]
            metadata["manufacturer"] = entity
    else:
        subject = {
            "type": "application",
            "bom-ref": "product:scan-root",
            "name": inventory.root.resolve().name or "unknown",
        }
    metadata["component"] = subject

    used_refs: set[str] = set()
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": serial or f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": metadata,
        "components": [_component_json(comp, used_refs) for comp in inventory.components],
    }
