<div align="center">

# EU Cyber Resilience Act Toolkit

**Open-source tooling for EU Cyber Resilience Act compliance — SBOM generation, vulnerability matching, and Article 14 report drafting from the command line.**

[![CI](https://github.com/AlfAxis/EU-Cyber-Resilience-Act-Toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/AlfAxis/EU-Cyber-Resilience-Act-Toolkit/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)
![Typed](https://img.shields.io/badge/typing-strict-informational.svg)
![Output: DE / EN](https://img.shields.io/badge/output-DE%20%2F%20EN-lightgrey.svg)

</div>

`cra-toolkit` helps software and hardware manufacturers meet their obligations under
**Regulation (EU) 2024/2847** (the Cyber Resilience Act, CRA). It walks a project, generates a
**CycloneDX 1.6** Software Bill of Materials, matches every component against known
vulnerabilities via **OSV.dev**, maintains a product register with **Annex III/IV classification**,
and drafts the **Article 14** reports that must be filed within 24 hours when a vulnerability is
actively exploited. German-language output by default (English with `--lang en`), MIT licensed,
runs in CI.

> **Not legal advice.** Product classification and the question of whether a given vulnerability
> triggers Article 14 are legal determinations that only you (with your counsel) can make. This
> tool drafts and organises; it does not decide, and it never submits anything on your behalf.
> See [Scope and limits](#scope-and-limits).

---

## Why this exists

Nearly every CRA obligation depends on one thing manufacturers usually don't have: an **accurate,
current inventory of what is actually inside the product**. Without an SBOM you can't know whether
a newly published vulnerability affects you; so you can't report it within 24 hours; so you can't
comply. `cra-toolkit` starts there and builds the rest of the workflow on top of that inventory.

## Regulatory context

| Date | What applies | Source |
|---|---|---|
| 10 Dec 2024 | Regulation enters into force | Art. 71 |
| **11 Sep 2026** | **Article 14 reporting obligations apply** — including to products already on the market | Art. 71, Art. 69(3) |
| 11 Dec 2027 | Full obligations: essential requirements, technical documentation, CE marking with cybersecurity assessment | Art. 71 |

Non-compliance with the essential requirements (Annex I) and the obligations in Articles 13 and 14
can be fined up to **€15 million or 2.5 % of worldwide annual turnover**, whichever is higher
(Art. 64(2)).

**Article 14 reporting clock** — to the CSIRT designated as coordinator *and* ENISA, simultaneously,
via the single reporting platform (Art. 14(1), Art. 16):

| Stage | Actively exploited vulnerability — Art. 14(2) | Severe incident — Art. 14(4) |
|---|---|---|
| **Early warning** | without undue delay, **≤ 24 h** after becoming aware | ≤ 24 h after becoming aware |
| **Notification** | **≤ 72 h** after becoming aware | ≤ 72 h after becoming aware |
| **Final report** | **≤ 14 days after a corrective or mitigating measure is available** | ≤ 1 month after the incident notification |

The clock runs in plain hours: weekends and public holidays do not pause it. More detail, including
how each CRA provision maps onto a command, in [docs/regulatory-context.md](docs/regulatory-context.md).

## Install

Requires Python 3.10 or newer. The only runtime dependency is [`requests`](https://requests.readthedocs.io/).

```bash
pipx install "git+https://github.com/AlfAxis/EU-Cyber-Resilience-Act-Toolkit.git"
```

or, from a clone:

```bash
git clone https://github.com/AlfAxis/EU-Cyber-Resilience-Act-Toolkit.git
cd EU-Cyber-Resilience-Act-Toolkit
pip install .
cra-toolkit --version
```

## Quick start

```bash
# 1. Register the product: the register is what the other commands draw on
cra-toolkit register add \
  --name "Edge Gateway" --version 2.1.0 --manufacturer "Muster GmbH" \
  --address "Musterstraße 1, 10115 Berlin" --email psirt@muster.example \
  --contact security@muster.example --classification important-class-1 \
  --support-end 2031-12-31 --placed-on-market 2026-06-01 --markets DE,AT \
  --purpose "Industrielles Edge-Gateway" --type firmware

# 2. Inventory + vulnerability check; fail the build on high or critical findings
cra-toolkit scan . --product edge-gateway-2-1-0 --fail-on high --sbom sbom.cdx.json

# 3. Where do you stand? (deadlines + register completeness)
cra-toolkit status
```

A try-it-yourself project covering every supported ecosystem ships in
[`tests/fixtures/sample-project`](tests/fixtures/sample-project):

```bash
cra-toolkit scan tests/fixtures/sample-project --no-archive
```

## The six commands

### `sbom` — inventory

Walks a project, parses dependency manifests and lockfiles, and emits **CycloneDX 1.6** with
[Package URLs](https://github.com/package-url/purl-spec). The output is validated against the
official CycloneDX 1.6 JSON schema in the test-suite.

```bash
cra-toolkit sbom ./my-product -o sbom.cdx.json --product edge-gateway-2-1-0
```

Components that cannot be pinned (a `requirements.txt` range, a BOM-managed Maven version) are kept
in the SBOM, flagged `cra-toolkit:unresolved`, and reported as *not checkable* by `scan` — never
silently dropped.

### `scan` — inventory plus live vulnerability matching

SBOM generation plus matching against [OSV.dev](https://osv.dev), using the **same purl** that is
written into the SBOM. Records that describe one vulnerability (a `GHSA-…` and a `PYSEC-…` entry for the
same CVE) are merged, with the CVE as the primary ID.

```text
$ cra-toolkit scan tests/fixtures/sample-project --fail-on critical
SBOM: 34 Komponenten aus 7 Quelle(n)
Schwachstellenquelle: osv.dev
Geprüft: 28 · Nicht prüfbar (Version nicht aufgelöst): 6

101 Fund(e) in 13 Komponente(n): kritisch 8 · hoch 36 · mittel 47 · niedrig 9 · unbekannt 1

KOMPONENTE  VERSION  ID              SCHWERE       BEHOBEN IN
----------  -------  --------------  ------------  --------------
django      4.2.0    CVE-2023-31047  kritisch 9.8  3.2.19, 4.1.9
django      4.2.0    CVE-2024-42005  kritisch 9.1  5.0.8, 4.2.15
…
Nicht prüfbar — Version nicht aufgelöst (Lockfile verwenden oder Version festschreiben):
  - numpy (==1.*) — requirements.txt
  - pyyaml (>=5.0,<7) — requirements.txt
…
Gate (--fail-on critical): NICHT bestanden
Hinweis: Ein sauberer Scan ist ein Nachweis, keine Konformität. Keine Rechtsberatung.
```

<sub>Excerpt. The numbers depend on the advisory database at the time of the scan.</sub>

| Option | Purpose |
|---|---|
| `--fail-on {none,any,low,medium,high,critical}` | CI gate: exit 1 at this severity or above (default `none`) |
| `--offline-db PATH` | Match against a local OSV dump for air-gapped environments — see [docs/offline-scanning.md](docs/offline-scanning.md) |
| `--ignore ID` | Accept a known finding by ID or alias; recorded in the evidence report |
| `--production-only` | Leave out dev/test-only dependencies |
| `--sbom FILE` / `--report FILE` | Also write the SBOM / JSON evidence report |
| `--format json` | Machine-readable output on stdout |

**What leaves your machine:** the online scan sends only the package URLs of your components
(e.g. `pkg:npm/lodash@4.17.15`) to `api.osv.dev` and fetches advisories by ID. If even the inventory is
sensitive, use `--offline-db`, which makes no network calls ([SECURITY.md](SECURITY.md)).

Severity comes from the CVSS v3.x vector (computed locally), falling back to the database's own
label. Findings whose severity cannot be determined are shown as *unbekannt*; they trip only
`--fail-on any`, and the output says how many were not gated.

### `register` — product inventory

Name, version, manufacturer, contact, **Annex III/IV classification**, support period and markets.

```bash
cra-toolkit register add|update|list|show|remove …
```

| `--classification` | Meaning |
|---|---|
| `default` | Not listed in Annex III or IV |
| `important-class-1` | Important product, class I (Annex III) |
| `important-class-2` | Important product, class II (Annex III) |
| `critical` | Critical product (Annex IV) |

The classification is **never inferred**: until you set it, `status` reports it as missing. The
register also flags a support period shorter than five years (Art. 13(8)) and an expired one.

### `report` — Article 14 drafts

Open a *case* at the moment you become aware; deadlines are computed from that timestamp.

```text
$ cra-toolkit report open --product edge-gateway-2-1-0 --reference CVE-2026-12345 \
      --aware-at 2026-10-05T08:30+02:00 --summary "RCE im Web-Interface"
Fall '2026-10-05-cve-2026-12345' angelegt (…).
Fristen:
  Frühwarnung        06.10.2026 08:30 (UTC+02:00)
  Meldung            08.10.2026 08:30 (UTC+02:00)
  Abschlussbericht   offen — 14 Tage nach Verfügbarkeit einer Korrektur- oder Abhilfemaßnahme …
```

```bash
cra-toolkit report draft <case>                       # early warning, notification and final report
cra-toolkit report update <case> --fix-available-at 2026-10-07T10:00+02:00
cra-toolkit report filed <case> --stage early-warning --reference <ID from the platform>
cra-toolkit report list
```

Drafts are Markdown with the legal basis in the header and **visible `[BITTE ERGÄNZEN]`
placeholders** wherever a fact is still missing. Use `--kind incident` for severe incidents
(Art. 14(3)–(4)). Always give timestamps with a UTC offset; a timestamp without one is interpreted
in the local timezone and the tool says so.

> The toolkit **drafts** reports. It does not submit them. Submission happens on the single reporting
> platform (Art. 16); record it with `report filed` so `status` knows the deadline is met.

### `docs` — Annex II user information

Generates the **Annex II** skeleton (points 1–9, sub-points 8(a)–(f)) with the citation next to every
item, pre-filled from the register. Anything the register cannot know is a visible placeholder.

```bash
cra-toolkit docs --product edge-gateway-2-1-0
```

### `status` — countdown and completeness

```text
$ cra-toolkit status
CRA-Status — 05.10.2026 14:27 (UTC+02:00)

Art.-14-Meldungen (0 überfällig)
  2026-10-05-cve-2026-12345  [edge-gateway-2-1-0]  CVE-2026-12345
    Frühwarnung        fällig 06.10.2026 08:30 (UTC+02:00) — noch 16 Std. 2 Min.
    Meldung            fällig 08.10.2026 08:30 (UTC+02:00) — noch 2 Tage 16 Std.
    Abschlussbericht   offen — 14 Tage nach Verfügbarkeit einer Korrektur- oder Abhilfemaßnahme …

Produktregister (0 unvollständig)
  edge-gateway-2-1-0  Edge Gateway 2.1.0 — 8/8 Pflichtangaben (100 %)
    [EMPFOHLEN] CVD-Richtlinie (URL) (Anhang II Nr. 2)
```

Exit code 1 if an unfiled deadline is overdue (`--strict` also fails on an incomplete register), so
it works as a CI check too.

## Ecosystem coverage

Lockfiles are preferred over manifests, because the CRA concerns what you **shipped**, not what you
declared. Per directory and ecosystem, the first file found in this order is used.

| Ecosystem | Sources (in order of preference) | Notes |
|---|---|---|
| **npm** | `npm-shrinkwrap.json`, `package-lock.json` (v1, v2, v3) | integrity hashes, dev/optional scope, aliases, workspaces |
| **PyPI** | `poetry.lock`, `Pipfile.lock`, `requirements.txt` | `requirements.txt`: only `==` pins resolve; ranges are flagged |
| **Go** | `go.mod` | `replace` directives applied; local replacements reported |
| **Rust** | `Cargo.lock` | SHA-256 checksums |
| **PHP** | `composer.lock` | dev packages out of scope |
| **Java** | `pom.xml` | properties resolved; BOM-managed and range versions flagged |

A manifest that declares dependencies *without* a lockfile (`package.json`, `Cargo.toml`,
`composer.json`, `Pipfile`, `pyproject.toml`) is **reported as a warning, not guessed at**. A lockfile
that cannot be parsed **aborts the run**: an SBOM that quietly misses a lockfile is worse than none.

## Running it in CI

```yaml
- run: pipx install "git+https://github.com/AlfAxis/EU-Cyber-Resilience-Act-Toolkit.git"
- run: cra-toolkit scan . --fail-on high --sbom sbom.cdx.json --report scan-report.json
- uses: actions/upload-artifact@v4
  if: always()
  with: { name: cra-evidence, path: "sbom.cdx.json\nscan-report.json" }
```

| Exit code | Meaning |
|---|---|
| `0` | Success |
| `1` | A gate tripped: findings at or above `--fail-on`, or an overdue Article 14 deadline |
| `2` | Usage or runtime error — **including an unreachable vulnerability database**, so a CI job can't turn green because the check never ran |

A complete, annotated workflow is in
[`examples/github-actions/cra-compliance.yml`](examples/github-actions/cra-compliance.yml);
more in [docs/ci-integration.md](docs/ci-integration.md).

## What it writes to disk

Compliance is proven by documentation over time, so every command leaves evidence. State lives in a
data directory (`./.cra` by default; override with `--data-dir` or `$CRA_TOOLKIT_DATA_DIR`) as
plain, diff-able JSON/Markdown:

```text
.cra/
├── register.json            product register
├── cases/<case-id>.json     one file per Article 14 case
├── reports/<case-id>/       Markdown drafts per stage
├── evidence/                timestamped SBOMs and scan reports (sbom-<UTC>.cdx.json, scan-<UTC>.json)
└── docs/                    Annex II skeletons
```

Commit this directory to *your own* compliance repository. Formats are described in
[docs/data-model.md](docs/data-model.md).

## Design principles

- **The purl is the single key.** The identifier written into the SBOM is exactly the identifier sent
  to the vulnerability lookup: no name mangling in between.
- **Everything produces evidence artifacts.** Compliance is proven by documentation over time, not by
  a passing scan.
- **Fail closed.** Unreadable lockfile, unreachable database or unparsable timestamp stop the run
  with a clear message instead of producing a plausible-looking partial result.
- **Nothing is silently dropped or guessed.** Unresolved versions, local dependencies and
  manifests without lockfiles are all listed.
- **German by default**, since the primary market is German manufacturers. `--lang en` (or
  `CRA_TOOLKIT_LANG=en`) switches generated text; `--help` stays English.

## Scope and limits

Stated plainly:

- **It is not legal advice.** Product classification and whether a vulnerability triggers Article 14
  are legal determinations. The tool never infers either.
- **It drafts reports but does not submit them.** You review, complete and file.
- **It covers third-party components, not your own code.**
- **SBOM coverage is dependency-level.** Vendored code, static linking and firmware blobs need
  separate handling. The dependency *graph* (which component pulls in which) and licence data are
  not emitted yet.
- **A clean scan is one piece of evidence toward compliance, not compliance itself.** OSV.dev is
  a good, broad source but not an exhaustive one.
- **Offline matching is best-effort.** It uses a simplified version ordering; the online path
  delegates matching to OSV.dev, which implements each ecosystem's native rules.
- **CVSS v4 vectors are not scored locally**; the database's severity label is used instead.
- It does not claim conformance with the BSI technical guideline TR-03183-2 for SBOMs.

## Technical details

Python 3.10+, **one runtime dependency** (`requests`), about 4,000 lines of strictly typed Python in
15 small modules plus about 1,900 lines of tests. MIT licensed. Package layout:

| Module | Responsibility |
|---|---|
| `sbom.py` | Discovery, per-ecosystem parsers, CycloneDX 1.6 builder |
| `vulns.py`, `cvss.py`, `versions.py` | OSV.dev client, offline matcher, CVSS v3.x scoring, version ordering |
| `register.py` | Product register, classification, completeness checks |
| `reports.py` | Article 14 cases, deadline logic, report drafts |
| `docs.py`, `status.py`, `evidence.py` | Annex II skeleton, status view, scan evidence |
| `cli.py`, `i18n.py`, `store.py`, `purl.py`, `timeutil.py` | Command line, DE/EN catalog, atomic storage, Package URLs, time handling |

## Development

```bash
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
ruff check . && ruff format --check . && mypy && pytest
```

CI runs this on Linux, macOS and Windows across Python 3.10 – 3.13. See
[CONTRIBUTING.md](CONTRIBUTING.md) for the workflow, and [SECURITY.md](SECURITY.md) to report
a vulnerability in the toolkit itself.

## License

[MIT](LICENSE). Regulation (EU) 2024/2847 is quoted by reference only; consult the official text on
[EUR-Lex](https://eur-lex.europa.eu/eli/reg/2024/2847/oj) for the authoritative wording.
