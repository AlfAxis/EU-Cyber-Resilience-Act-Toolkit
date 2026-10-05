from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from cra_toolkit import cli
from cra_toolkit.cli import main
from cra_toolkit.errors import VulnSourceError

CEST = timezone(timedelta(hours=2))
NOW = datetime(2026, 9, 12, 7, 0, tzinfo=timezone.utc)  # 09:00 CEST, 30 min after awareness

PRODUCT_ARGS = [
    "register", "add",
    "--name", "Edge Gateway", "--version", "2.1.0", "--manufacturer", "Muster GmbH",
    "--address", "Musterstraße 1, 10115 Berlin", "--email", "psirt@muster.example",
    "--contact", "security@muster.example", "--classification", "important-class-1",
    "--support-end", "2031-12-31", "--markets", "DE,AT",
    "--purpose", "Industrielles Edge-Gateway", "--type", "firmware",
]  # fmt: skip


class Runner:
    def __init__(self, capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
        self.capsys, self.tmp_path = capsys, tmp_path
        self.data_dir = tmp_path / ".cra"
        self.now = NOW

    def __call__(self, *args: str, lang: str | None = None) -> tuple[int, str, str]:
        extra = ["--lang", lang] if lang else []
        code = main([*args, "--data-dir", str(self.data_dir), *extra], clock=lambda: self.now)
        captured = self.capsys.readouterr()
        return code, captured.out, captured.err


@pytest.fixture
def run(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> Runner:
    return Runner(capsys, tmp_path)


# ------------------------------------------------------------ the full workflow


def test_article_14_workflow_end_to_end(run: Runner) -> None:
    code, out, _ = run(*PRODUCT_ARGS)
    assert code == 0 and "edge-gateway-2-1-0" in out

    code, out, _ = run("register", "list")
    assert code == 0 and "Edge Gateway 2.1.0" in out and "important-class-1" in out

    code, out, _ = run(
        "report", "open", "--product", "edge-gateway-2-1-0",
        "--reference", "CVE-2026-12345", "--aware-at", "2026-09-12T08:30+02:00",
        "--summary", "RCE im Web-Interface", "--component", "pkg:npm/lodash@4.17.15",
    )  # fmt: skip
    assert code == 0
    assert "2026-09-12-cve-2026-12345" in out
    assert "13.09.2026 08:30 (UTC+02:00)" in out  # early warning: +24 h
    assert "15.09.2026 08:30 (UTC+02:00)" in out  # notification: +72 h
    assert "14 Tage nach Verfügbarkeit" in out  # final report: not from awareness

    case_id = "2026-09-12-cve-2026-12345"
    code, out, _ = run("report", "draft", case_id)
    assert code == 0
    reports = run.data_dir / "reports" / case_id
    assert sorted(p.name for p in reports.iterdir()) == [
        "early-warning.de.md",
        "final-report.de.md",
        "notification.de.md",
    ]
    assert "Angabe(n) noch offen" in out  # the notification draft still has gaps
    early = (reports / "early-warning.de.md").read_text(encoding="utf-8")
    assert "RCE im Web-Interface" in early and "AT, DE" in early

    code, out, _ = run("status")
    assert code == 0  # nothing overdue yet
    assert "noch 23 Std. 30 Min." in out
    assert "8/8 Pflichtangaben (100 %)" in out

    run.now = datetime(2026, 9, 13, 7, 0, tzinfo=timezone.utc)  # 09:00 CEST: 30 min late
    code, out, _ = run("status")
    assert code == 1 and "ÜBERFÄLLIG seit 30 Min." in out

    code, out, _ = run("report", "filed", case_id, "--stage", "early-warning",
                       "--at", "2026-09-13T08:45+02:00", "--reference", "ENISA-4711")  # fmt: skip
    assert code == 0
    code, out, _ = run("status")
    # a late filing is recorded honestly and stays visible, but it is no longer an open
    # overdue deadline, so it does not keep a CI job red
    assert code == 0 and "VERSPÄTET eingereicht am 13.09.2026 08:45" in out
    assert "(Frist war 13.09.2026 08:30 (UTC+02:00))" in out
    code, out, _ = run("status", "--format", "json")
    states = {d["stage"]: d["state"] for d in json.loads(out)["cases"][0]["deadlines"]}
    assert states == {
        "early-warning": "filed_late",
        "notification": "open",
        "final-report": "pending",
    }

    code, out, _ = run("report", "update", case_id, "--fix-available-at", "2026-09-14T10:00+02:00")
    assert code == 0 and "28.09.2026 10:00 (UTC+02:00)" in out


def test_status_exit_code_ignores_late_but_filed_deadlines(run: Runner) -> None:
    run(*PRODUCT_ARGS)
    run("report", "open", "--product", "edge-gateway-2-1-0", "--reference", "CVE-1",
        "--aware-at", "2026-09-12T08:30+02:00")  # fmt: skip
    run(
        "report",
        "filed",
        "2026-09-12-cve-1",
        "--stage",
        "early-warning",
        "--at",
        "2026-09-12T20:00+02:00",
    )
    run.now = datetime(2026, 9, 12, 12, 0, tzinfo=timezone.utc)
    code, _, _ = run("status")
    assert code == 0


def test_strict_status_fails_on_incomplete_register(run: Runner) -> None:
    run("register", "add", "--name", "Bare", "--version", "1", "--manufacturer", "M")
    assert run("status")[0] == 0
    code, out, _ = run("status", "--strict")
    assert code == 1 and "FEHLT" in out


def test_docs_command_writes_annex_ii(run: Runner) -> None:
    run(*PRODUCT_ARGS)
    code, out, _ = run("docs", "--product", "edge-gateway-2-1-0")
    assert code == 0
    written = run.data_dir / "docs" / "annex-ii-edge-gateway-2-1-0.de.md"
    assert "Anhang II Nr. 7" in written.read_text(encoding="utf-8")
    code, out, _ = run("docs", "--product", "edge-gateway-2-1-0", "--stdout", "--lang", "en")
    assert code == 0 and "Annex II No. 1" in out


def test_register_show_update_remove(run: Runner) -> None:
    run(*PRODUCT_ARGS)
    code, out, _ = run("register", "show", "edge-gateway-2-1-0")
    assert code == 0 and "Muster GmbH" in out and "31.12.2031" in out
    code, out, _ = run("register", "show", "edge-gateway-2-1-0", "--json")
    assert json.loads(out)["classification"] == "important-class-1"
    run(
        "register",
        "update",
        "edge-gateway-2-1-0",
        "--classification",
        "critical",
        "--markets",
        "EU",
    )
    shown = json.loads(run("register", "show", "edge-gateway-2-1-0", "--json")[1])
    assert shown["classification"] == "critical" and len(shown["markets"]) == 27
    assert run("register", "remove", "edge-gateway-2-1-0")[0] == 0
    assert "leer" in run("register", "list")[1]


# --------------------------------------------------------------------- scanning


def test_offline_scan_gate_and_evidence(run: Runner, sample_project: Path, osv_db: Path) -> None:
    base = ["scan", str(sample_project), "--offline-db", str(osv_db)]
    code, out, _ = run(*base)
    assert code == 0  # no --fail-on: findings do not fail the run
    assert "4 Fund(e) in 4 Komponente(n)" in out
    assert "CVE-0000-0001" in out and "hoch 8.1" in out
    assert "Nicht prüfbar" in out and "pyyaml" in out  # unresolved versions are never silent
    assert "Nachweis gespeichert" in out
    assert "keine Konformität" in out

    assert run(*base, "--fail-on", "high")[0] == 1
    assert run(*base, "--fail-on", "critical")[0] == 1  # the PyPI record is critical
    assert run(*base, "--fail-on", "critical", "--ignore", "CVE-0000-0002")[0] == 0

    evidence = sorted((run.data_dir / "evidence").iterdir())
    assert any(p.name.startswith("scan-") for p in evidence)
    assert any(p.name.startswith("sbom-") and p.suffix == ".json" for p in evidence)


def test_scan_json_evidence_contents(
    run: Runner, sample_project: Path, osv_db: Path, tmp_path: Path
) -> None:
    sbom_file = tmp_path / "out.cdx.json"
    code, out, _ = run("scan", str(sample_project), "--offline-db", str(osv_db), "--format", "json",
                       "--fail-on", "high", "--sbom", str(sbom_file))  # fmt: skip
    assert code == 1
    evidence = json.loads(out)
    assert evidence["tool"]["name"] == "cra-toolkit"
    assert evidence["generated_at"] == "2026-09-12T07:00:00Z"
    assert evidence["vulnerability_source"]["type"] == "offline"
    assert evidence["gate"] == {"fail_on": "high", "passed": False}
    assert evidence["summary"]["findings"] == 4
    assert evidence["summary"]["not_checkable"] == 6
    assert {f["name"] for f in evidence["findings"]} == {
        "lodash",
        "requests",
        "github.com/gin-gonic/gin",
        "org.apache.logging.log4j:log4j-core",
    }
    assert all(f["purl"].startswith("pkg:") for f in evidence["findings"])
    import hashlib

    assert evidence["sbom"]["sha256"] == hashlib.sha256(sbom_file.read_bytes()).hexdigest()


def test_no_archive_writes_nothing_to_the_data_dir(
    run: Runner, sample_project: Path, osv_db: Path
) -> None:
    run("scan", str(sample_project), "--offline-db", str(osv_db), "--no-archive")
    assert not run.data_dir.exists()


def test_production_only_drops_dev_dependencies(
    run: Runner, sample_project: Path, tmp_path: Path
) -> None:
    out_file = tmp_path / "bom.json"
    code, _, _ = run("sbom", str(sample_project), "-o", str(out_file), "--production-only")
    assert code == 0
    purls = {c["purl"] for c in json.loads(out_file.read_text(encoding="utf-8"))["components"]}
    assert "pkg:npm/jest@29.7.0" not in purls
    assert "pkg:npm/lodash@4.17.15" in purls


def test_sbom_to_stdout_with_product_metadata(run: Runner, sample_project: Path) -> None:
    run(*PRODUCT_ARGS)
    code, out, _ = run("sbom", str(sample_project), "-o", "-", "--product", "edge-gateway-2-1-0")
    assert code == 0
    bom = json.loads(out)
    assert bom["metadata"]["component"]["name"] == "Edge Gateway"
    assert bom["metadata"]["manufacturer"]["name"] == "Muster GmbH"


def test_sbom_warns_when_nothing_was_found(run: Runner, tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    code, _, err = run("sbom", str(empty), "-o", str(tmp_path / "x.json"))
    assert code == 0 and "leer" in err


# ----------------------------------------------------------------- failure modes


def test_unreachable_osv_is_an_error_not_a_clean_pass(
    run: Runner, sample_project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_args: object, **_kwargs: object) -> None:
        raise VulnSourceError("OSV.dev ist nicht erreichbar: simuliert")

    monkeypatch.setattr(cli, "scan_online", boom)
    code, out, err = run("scan", str(sample_project), "--fail-on", "high")
    assert code == 2
    assert "OSV.dev" in err and "Fehler" in err
    assert out == ""


@pytest.mark.parametrize(
    "args",
    [
        ["register", "show", "nope"],
        [
            "report",
            "open",
            "--product",
            "nope",
            "--reference",
            "X",
            "--aware-at",
            "2026-09-12T08:30+02:00",
        ],
        ["report", "draft", "nope"],
        ["docs", "--product", "nope"],
        [
            "register",
            "add",
            "--name",
            "A",
            "--version",
            "1",
            "--manufacturer",
            "M",
            "--markets",
            "XX",
        ],
        [
            "register",
            "add",
            "--name",
            "A",
            "--version",
            "1",
            "--manufacturer",
            "M",
            "--support-end",
            "soon",
        ],
        ["scan", "/definitely/not/a/directory", "--offline-db", "x"],
    ],
)
def test_expected_failures_exit_2_with_a_message(run: Runner, args: list[str]) -> None:
    code, _, err = run(*args)
    assert code == 2
    assert err.startswith("Fehler: ")


def test_naive_timestamp_prints_the_timezone_assumption(run: Runner) -> None:
    run(*PRODUCT_ARGS)
    code, _, err = run("report", "open", "--product", "edge-gateway-2-1-0", "--reference", "CVE-9",
                       "--aware-at", "2026-09-12 08:30")  # fmt: skip
    assert code == 0 and "ohne Zeitzone" in err


def test_duplicate_product_is_rejected(run: Runner) -> None:
    assert run(*PRODUCT_ARGS)[0] == 0
    code, _, err = run(*PRODUCT_ARGS)
    assert code == 2 and "existiert bereits" in err


# ------------------------------------------------------------------- languages


def test_every_command_works_in_german_and_english(
    run: Runner, sample_project: Path, osv_db: Path
) -> None:
    for lang in ("de", "en"):
        run.data_dir = run.tmp_path / f".cra-{lang}"
        steps = [
            PRODUCT_ARGS,
            ["register", "list"],
            ["register", "show", "edge-gateway-2-1-0"],
            ["report", "open", "--product", "edge-gateway-2-1-0", "--reference", "CVE-1",
             "--aware-at", "2026-09-12T08:30+02:00", "--kind", "incident"],
            ["report", "list"],
            ["report", "draft", "2026-09-12-cve-1", "--stdout"],
            ["report", "filed", "2026-09-12-cve-1", "--stage", "notification",
             "--at", "2026-09-13T08:00+02:00"],
            ["docs", "--product", "edge-gateway-2-1-0", "--stdout"],
            ["scan", str(sample_project), "--offline-db", str(osv_db), "--fail-on", "any"],
            ["status"],
        ]  # fmt: skip
        for step in steps:
            code, _, err = run(*step, lang=lang)
            assert code in (0, 1), (lang, step, err)
            assert "Traceback" not in err


def test_english_output_and_env_default(run: Runner, monkeypatch: pytest.MonkeyPatch) -> None:
    run(*PRODUCT_ARGS)
    _, out, _ = run("status", lang="en")
    assert "CRA status" in out and "required fields" in out
    monkeypatch.setenv("CRA_TOOLKIT_LANG", "en")
    assert "CRA status" in run("status")[1]


def test_data_dir_can_come_from_the_environment(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CRA_TOOLKIT_DATA_DIR", str(tmp_path / "from-env"))
    assert main(["register", "add", "--name", "A", "--version", "1", "--manufacturer", "M"]) == 0
    assert (tmp_path / "from-env" / "register.json").is_file()
    capsys.readouterr()


def test_version_flag(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.startswith("cra-toolkit ")
