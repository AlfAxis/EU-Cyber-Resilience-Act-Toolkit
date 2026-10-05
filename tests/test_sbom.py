from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from cra_toolkit.errors import ToolkitError
from cra_toolkit.sbom import (
    Component,
    Inventory,
    build_bom,
    collect,
    parse_cargo_lock,
    parse_go_mod,
    parse_package_lock,
    parse_pom,
    parse_requirements,
    toml_package_tables,
)
from cra_toolkit.store import dump_json

FIXED = datetime(2026, 10, 5, 12, 0, tzinfo=timezone.utc)


def by_purl(components: list[Component]) -> dict[str, Component]:
    return {c.purl: c for c in components}


# ------------------------------------------------------------------- sample


def test_sample_project_covers_every_ecosystem(sample_project: Path) -> None:
    inventory = collect(sample_project)
    assert {c.ptype for c in inventory.components} == {
        "npm", "pypi", "golang", "cargo", "composer", "maven",
    }  # fmt: skip
    assert inventory.sources == [
        "Cargo.lock",
        "composer.lock",
        "go.mod",
        "package-lock.json",
        "pom.xml",
        "requirements.txt",
        "services/api/poetry.lock",
    ]


def test_npm_lockfile_details(sample_project: Path) -> None:
    components = by_purl(collect(sample_project).components)
    lodash = components["pkg:npm/lodash@4.17.15"]
    assert lodash.scope == "required"
    assert lodash.hashes[0][0] == "SHA-512"
    assert len(lodash.hashes[0][1]) == 128
    assert components["pkg:npm/%40babel/core@7.23.0"].name == "@babel/core"
    assert components["pkg:npm/jest@29.7.0"].scope == "excluded"  # dev
    assert components["pkg:npm/jest@29.7.0"].hashes[0][0] == "SHA-1"
    assert components["pkg:npm/left-pad@1.3.0"].scope == "optional"
    assert "pkg:npm/real-package@2.0.0" in components  # alias resolves to the real package
    assert not any("sample-web" in p or "/ui@" in p for p in components)  # own code, links


def test_unpinned_requirements_are_kept_but_flagged(sample_project: Path) -> None:
    components = by_purl(collect(sample_project).components)
    assert "pkg:pypi/requests@2.19.1" in components
    assert "pkg:pypi/flask-cors@3.0.8" in components  # extras + markers + normalisation
    assert "pkg:pypi/django@4.2.0" in components  # ===
    pyyaml = components["pkg:pypi/pyyaml"]
    assert not pyyaml.resolved
    assert pyyaml.constraint == ">=5.0,<7"
    assert not components["pkg:pypi/numpy"].resolved  # wildcard is not a pin
    assert components["pkg:pypi/urllib3"].constraint == "*"
    assert not any("private" in p or "local-package" in p for p in components)


def test_go_replace_directives(sample_project: Path) -> None:
    inventory = collect(sample_project)
    components = by_purl(inventory.components)
    assert "pkg:golang/github.com/example/forked-fixed@v1.0.1" in components
    assert not any("example/forked@" in p for p in components)
    assert not any("example/local" in p for p in components)  # replaced by a local dir
    assert any("example/local" in w for w in inventory.warnings)
    # case-sensitive module path is preserved, +incompatible is encoded
    assert "pkg:golang/github.com/Masterminds/semver/v3@v3.2.0" in components
    assert "pkg:golang/github.com/example/legacy@v2.0.0%2Bincompatible" in components


def test_cargo_lock_skips_the_workspace_root_and_keeps_checksums(sample_project: Path) -> None:
    components = by_purl(collect(sample_project).components)
    assert not any("sample-cli" in p for p in components)
    serde = components["pkg:cargo/serde@1.0.152"]
    assert serde.hashes == (
        ("SHA-256", "bb7d1f0d3021d347a83e556fc4683dea2ea09d87bccdf88ff5c12545d89d5efb"),
    )


def test_composer_and_poetry_and_maven_scopes(sample_project: Path) -> None:
    components = by_purl(collect(sample_project).components)
    assert components["pkg:composer/symfony/http-kernel@5.4.20"].scope == "required"  # v prefix
    assert components["pkg:composer/phpunit/phpunit@9.6.3"].scope == "excluded"
    assert not components["pkg:composer/example/branch-pinned"].resolved
    assert components["pkg:pypi/jinja2@2.11.2"].scope == "required"
    assert components["pkg:pypi/pytest@7.4.0"].scope == "excluded"
    assert components["pkg:pypi/extra-only@1.0.0"].scope == "optional"
    assert not any("my-local-lib" in p for p in components)
    assert components["pkg:maven/junit/junit@4.13.2"].scope == "excluded"
    assert components["pkg:maven/javax.servlet/servlet-api@2.5"].scope == "optional"


def test_maven_properties_and_unresolved_versions(sample_project: Path) -> None:
    components = by_purl(collect(sample_project).components)
    assert "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" in components  # ${property}
    assert "pkg:maven/com.example/sibling@3.1.0" in components  # ${project.version} via parent
    assert not components["pkg:maven/org.springframework/spring-core"].resolved  # BOM-managed
    assert not components["pkg:maven/org.range/ranged"].resolved  # version range
    assert not any("only-managed" in p for p in components)  # dependencyManagement ignored


# --------------------------------------------------------------- npm formats


def test_npm_lockfile_v1_nested_dependencies() -> None:
    text = json.dumps(
        {
            "lockfileVersion": 1,
            "dependencies": {
                "a": {
                    "version": "1.0.0",
                    "dependencies": {"b": {"version": "2.0.0", "dev": True}},
                },
                "c": {"version": "npm:@scope/real@3.0.0"},
                "d": {"version": "git+https://example.invalid/d.git#abc"},
            },
        }
    )
    components = by_purl(parse_package_lock(text, "package-lock.json").components)
    assert components["pkg:npm/a@1.0.0"].scope == "required"
    assert components["pkg:npm/b@2.0.0"].scope == "excluded"
    assert "pkg:npm/%40scope/real@3.0.0" in components
    assert not components["pkg:npm/d"].resolved


# ------------------------------------------------------------- tolerant TOML


def test_toml_extractor_keeps_package_attached_across_nested_tables() -> None:
    text = """
[[package]]
name = "a"
version = "1.0"
files = [
    {file = "a.whl", hash = "sha256:00"},
]

[[package.files]]
file = "ignored"

[package.source]
type = "directory"

[[package]]
name = "b"
version = "2.0"
groups = ["main", "dev"]
"""
    packages = toml_package_tables(text)
    assert [p["name"] for p in packages] == ["a", "b"]
    assert packages[0]["source_table"] == {"type": "directory"}
    assert packages[1]["groups"] == ["main", "dev"]


def test_cargo_lock_ignores_package_without_source() -> None:
    text = '[[package]]\nname = "me"\nversion = "1.0.0"\n'
    assert parse_cargo_lock(text, "Cargo.lock").components == []


# ------------------------------------------------------------- requirements


def test_requirements_line_continuations_and_comments() -> None:
    text = (
        "pkg==1.0 \\\n"
        "    --hash=sha256:aa \\\n"
        "    --hash=sha256:bb\n"
        "# comment\n"
        "other==2.0  # trailing\n"
    )
    result = parse_requirements(text, "requirements.txt")
    assert [(c.name, c.version) for c in result.components] == [("pkg", "1.0"), ("other", "2.0")]


# --------------------------------------------------------------------- go.mod


def test_go_mod_replace_with_version_for_a_specific_release() -> None:
    text = (
        "module m\nrequire a.example/x v1.0.0\nreplace a.example/x v1.0.0 => b.example/y v1.1.0\n"
    )
    result = parse_go_mod(text, "go.mod")
    assert [(c.name, c.version) for c in result.components] == [("b.example/y", "v1.1.0")]


# ------------------------------------------------------------------ pom.xml


def test_pom_rejects_entity_declarations() -> None:
    evil = (
        '<?xml version="1.0"?><!DOCTYPE p [<!ENTITY a "aaaa">]><project><dependencies/></project>'
    )
    with pytest.raises(ToolkitError, match="DOCTYPE"):
        parse_pom(evil, "pom.xml")


def test_pom_rejects_malformed_xml() -> None:
    with pytest.raises(ToolkitError, match=r"pom\.xml"):
        parse_pom("<project><dependencies>", "pom.xml")


# ------------------------------------------------------------------ discovery


def test_lockfile_is_preferred_over_manifest_in_the_same_directory(tmp_path: Path) -> None:
    (tmp_path / "poetry.lock").write_text('[[package]]\nname = "locked"\nversion = "1.0"\n')
    (tmp_path / "requirements.txt").write_text("manifest==9.9\n")
    names = [c.name for c in collect(tmp_path).components]
    assert names == ["locked"]


def test_vendor_and_dependency_directories_are_skipped(tmp_path: Path) -> None:
    for skipped in ("node_modules/x", "vendor/y", ".venv/z", "target/t"):
        directory = tmp_path / skipped
        directory.mkdir(parents=True)
        (directory / "package-lock.json").write_text('{"lockfileVersion": 3, "packages": {}}')
        (directory / "Cargo.lock").write_text("[[package]]\nname='n'\nversion='1'\nsource='s'\n")
    assert collect(tmp_path).sources == []


def test_exclude_globs(tmp_path: Path) -> None:
    for sub in ("keep", "skipme"):
        (tmp_path / sub).mkdir()
        (tmp_path / sub / "requirements.txt").write_text("a==1\n")
    assert collect(tmp_path, exclude=["skipme"]).sources == ["keep/requirements.txt"]


def test_manifest_without_lockfile_is_flagged_not_parsed(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"dependencies": {"left-pad": "^1.0.0"}}')
    inventory = collect(tmp_path)
    assert inventory.components == []
    assert any("package.json" in w and "Lockfile" in w for w in inventory.warnings)


def test_manifest_covered_by_a_lockfile_higher_up_is_not_flagged(tmp_path: Path) -> None:
    (tmp_path / "package-lock.json").write_text('{"lockfileVersion": 3, "packages": {}}')
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "package.json").write_text("{}")
    assert collect(tmp_path).warnings == []


def test_unparsable_lockfile_aborts_instead_of_producing_a_partial_sbom(tmp_path: Path) -> None:
    (tmp_path / "package-lock.json").write_text("{not json")
    with pytest.raises(ToolkitError, match=r"package-lock\.json"):
        collect(tmp_path)


def test_scan_root_must_be_a_directory(tmp_path: Path) -> None:
    with pytest.raises(ToolkitError):
        collect(tmp_path / "missing")


def test_same_package_from_two_lockfiles_is_merged(tmp_path: Path) -> None:
    for sub, scope in (("a", {}), ("b", {"dev": True})):
        (tmp_path / sub).mkdir()
        lock = {"lockfileVersion": 3, "packages": {"node_modules/x": {"version": "1.0.0", **scope}}}
        (tmp_path / sub / "package-lock.json").write_text(json.dumps(lock))
    (component,) = collect(tmp_path).components
    assert component.scope == "required"  # the more inclusive scope wins
    assert component.sources == ("a/package-lock.json", "b/package-lock.json")


# --------------------------------------------------------------------- CycloneDX


def test_bom_structure_and_determinism(sample_project: Path) -> None:
    inventory = collect(sample_project)
    serial = "urn:uuid:00000000-0000-4000-8000-000000000000"
    first = build_bom(inventory, timestamp=FIXED, serial=serial)
    second = build_bom(inventory, timestamp=FIXED, serial=serial)
    assert first == second
    assert first["bomFormat"] == "CycloneDX"
    assert first["specVersion"] == "1.6"
    assert first["metadata"]["timestamp"] == "2026-10-05T12:00:00Z"
    assert len(first["components"]) == len(inventory.components)
    refs = [c["bom-ref"] for c in first["components"]]
    assert len(refs) == len(set(refs))
    assert all(c["purl"] for c in first["components"])


def test_bom_component_shapes(sample_project: Path) -> None:
    bom = build_bom(collect(sample_project), timestamp=FIXED)
    components = {c["purl"]: c for c in bom["components"]}
    babel = components["pkg:npm/%40babel/core@7.23.0"]
    assert (babel["group"], babel["name"]) == ("@babel", "core")
    log4j = components["pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"]
    assert (log4j["group"], log4j["name"]) == ("org.apache.logging.log4j", "log4j-core")
    unresolved = components["pkg:pypi/pyyaml"]
    assert "version" not in unresolved
    props = {p["name"]: p["value"] for p in unresolved["properties"]}
    assert props["cra-toolkit:unresolved"] == "true"
    assert props["cra-toolkit:version-constraint"] == ">=5.0,<7"


def test_bom_describes_the_product_and_manufacturer(tmp_path: Path) -> None:
    product = {
        "id": "edge-1",
        "name": "Edge Gateway",
        "version": "2.1.0",
        "product_type": "firmware",
        "manufacturer": {
            "name": "Muster GmbH",
            "email": "psirt@muster.example",
            "website": "https://muster.example",
        },
    }
    bom = build_bom(Inventory(tmp_path, [], [], []), product=product, timestamp=FIXED)
    subject = bom["metadata"]["component"]
    assert (subject["type"], subject["name"], subject["version"]) == (
        "firmware",
        "Edge Gateway",
        "2.1.0",
    )
    assert bom["metadata"]["manufacturer"] == {
        "name": "Muster GmbH",
        "url": ["https://muster.example"],
        "contact": [{"email": "psirt@muster.example"}],
    }


def test_bom_validates_against_the_official_cyclonedx_1_6_schema(sample_project: Path) -> None:
    validation = pytest.importorskip("cyclonedx.validation.json")
    schema = pytest.importorskip("cyclonedx.schema")
    bom = build_bom(collect(sample_project), timestamp=FIXED)
    error = validation.JsonStrictValidator(schema.SchemaVersion.V1_6).validate_str(dump_json(bom))
    assert error is None, str(error)
