from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from cra_toolkit.errors import ToolkitError
from cra_toolkit.store import (
    DEFAULT_DATA_DIR,
    ENV_DATA_DIR,
    read_json,
    resolve_data_dir,
    slugify,
    utc_stamp,
    write_json,
    write_text,
)


def test_data_dir_precedence(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv(ENV_DATA_DIR, raising=False)
    assert resolve_data_dir(None).root == Path(DEFAULT_DATA_DIR)
    monkeypatch.setenv(ENV_DATA_DIR, str(tmp_path / "env"))
    assert resolve_data_dir(None).root == tmp_path / "env"
    assert resolve_data_dir(str(tmp_path / "flag")).root == tmp_path / "flag"  # flag beats env


def test_json_round_trip_keeps_unicode(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "data.json"
    write_json(path, {"straße": "Größe — ✓"})
    assert read_json(path) == {"straße": "Größe — ✓"}
    assert "Größe" in path.read_text(encoding="utf-8")  # not \u-escaped
    assert path.read_bytes().endswith(b"\n")
    assert b"\r\n" not in path.read_bytes()  # LF endings even on Windows


def test_read_json_errors_are_user_facing(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{oops")
    with pytest.raises(ToolkitError, match="Ungültiges JSON"):
        read_json(bad)
    with pytest.raises(ToolkitError, match="nicht gelesen"):
        read_json(tmp_path / "missing.json")


def test_read_json_accepts_a_utf8_bom(tmp_path: Path) -> None:
    path = tmp_path / "bom.json"
    path.write_bytes(b"\xef\xbb\xbf" + b'{"a": 1}')
    assert read_json(path) == {"a": 1}


def test_failed_write_leaves_no_partial_file_and_keeps_the_old_content(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "register.json"
    write_text(path, "original")

    def explode(*_args: object, **_kwargs: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", explode)
    with pytest.raises(OSError, match="disk full"):
        write_text(path, "replacement")
    monkeypatch.undo()
    assert path.read_text() == "original"
    assert [p.name for p in tmp_path.iterdir()] == ["register.json"]  # temp file cleaned up


def test_slugify() -> None:
    assert slugify("CVE-2026-12345") == "cve-2026-12345"
    assert slugify("Edge Gateway 2.1.0") == "edge-gateway-2-1-0"
    assert slugify("Müller & Söhne") == "m-ller-s-hne"
    assert slugify("///") == "item"


def test_utc_stamp_converts_offsets() -> None:
    moment = datetime(2026, 9, 12, 8, 30, 5, tzinfo=timezone(timedelta(hours=2)))
    assert utc_stamp(moment) == "20260912T063005Z"
