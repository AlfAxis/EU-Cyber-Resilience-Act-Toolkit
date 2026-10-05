"""On-disk state: the product register, Article 14 cases and evidence files.

Everything lives under one data directory (``.cra`` by default) as plain,
human-readable JSON/Markdown so it can be committed, diffed and audited.
Writes are atomic: a crash never leaves a half-written register behind.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cra_toolkit.errors import ToolkitError
from cra_toolkit.i18n import t

ENV_DATA_DIR = "CRA_TOOLKIT_DATA_DIR"
DEFAULT_DATA_DIR = ".cra"


@dataclass(frozen=True)
class DataDir:
    root: Path

    @property
    def register_file(self) -> Path:
        return self.root / "register.json"

    @property
    def cases_dir(self) -> Path:
        return self.root / "cases"

    @property
    def evidence_dir(self) -> Path:
        return self.root / "evidence"

    @property
    def reports_dir(self) -> Path:
        return self.root / "reports"


def resolve_data_dir(explicit: str | None) -> DataDir:
    """``--data-dir`` wins, then ``$CRA_TOOLKIT_DATA_DIR``, then ``./.cra``."""
    chosen = explicit or os.environ.get(ENV_DATA_DIR) or DEFAULT_DATA_DIR
    return DataDir(Path(chosen).expanduser())


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        raise ToolkitError(t("err.invalid_json", path=path, detail=exc)) from exc
    except OSError as exc:
        raise ToolkitError(t("err.cannot_read", path=path, detail=exc)) from exc


def dump_json(data: Any) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


def write_text(path: Path, text: str) -> None:
    """Atomically write UTF-8 text with LF line endings."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
        os.replace(tmp_name, path)
    except BaseException:
        Path(tmp_name).unlink(missing_ok=True)
        raise


def write_json(path: Path, data: Any) -> None:
    write_text(path, dump_json(data))


def utc_stamp(value: datetime) -> str:
    """Filesystem-safe UTC timestamp, e.g. ``20260912T063000Z``."""
    return value.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def slugify(text: str) -> str:
    chars = [c if c.isascii() and c.isalnum() else "-" for c in text.lower()]
    slug = "".join(chars)
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug.strip("-") or "item"
