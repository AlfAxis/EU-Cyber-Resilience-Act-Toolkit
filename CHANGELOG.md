# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-10-05

First release published to PyPI (`pip install cra-toolkit`). No functional changes to the toolkit.

### Added

- Release workflow publishes to PyPI via Trusted Publishing (no stored token), once enabled.

### Changed

- README links are absolute, so they work on the PyPI project page.
- Install instructions, CI snippets and the example workflow use the PyPI package and current
  GitHub Actions versions (`checkout`, `setup-python`, `upload-artifact` v7).

## [0.1.0] - 2026-10-05

First public release.

### Added

- **`sbom`**: dependency discovery and **CycloneDX 1.6** output (validated against the official
  schema in the test-suite) with Package URLs, hashes where lockfiles carry them, and
  `required` / `optional` / `excluded` scopes.
  - Ecosystems: npm (`package-lock.json` v1/v2/v3, `npm-shrinkwrap.json`), PyPI (`poetry.lock`,
    `Pipfile.lock`, `requirements.txt`), Go (`go.mod` incl. `replace`), Rust (`Cargo.lock`), PHP
    (`composer.lock`), Java (`pom.xml` incl. property interpolation).
  - Lockfiles preferred over manifests; manifests without a lockfile are flagged, unresolved versions
    are kept and marked rather than dropped; unparsable lockfiles abort the run.
- **`scan`**: live matching against OSV.dev using the SBOM's purl as the lookup key, batched and
  paginated; `--offline-db` for air-gapped use (directory, `.zip` or `.json` of OSV records);
  `--fail-on` CI gate; `--ignore`; `--production-only`; JSON evidence report with the SBOM's SHA-256.
  Records describing the same vulnerability (shared CVE/GHSA/PYSEC identifiers) are merged; severity is
  computed from CVSS v3.x vectors.
- **`register`**: product register with Annex III/IV classification, support period, markets, and a
  completeness check that cites the provision behind every required field.
- **`report`**: Article 14 cases with deadline computation (24 h / 72 h from awareness; final report
  14 days after a corrective or mitigating measure is available, or one month after the incident
  notification), Markdown drafts for all three stages for vulnerabilities and severe incidents, and
  filing records.
- **`docs`**: Annex II user-information skeleton with citations, pre-filled from the register.
- **`status`**: deadline countdown and register completeness; exit code 1 on unfiled overdue deadlines.
- German output by default, English with `--lang en`.
- CI on Linux, macOS and Windows for Python 3.10–3.13; release workflow; Dependabot; issue and pull
  request templates.

[Unreleased]: https://github.com/AlfAxis/EU-Cyber-Resilience-Act-Toolkit/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/AlfAxis/EU-Cyber-Resilience-Act-Toolkit/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/AlfAxis/EU-Cyber-Resilience-Act-Toolkit/releases/tag/v0.1.0
