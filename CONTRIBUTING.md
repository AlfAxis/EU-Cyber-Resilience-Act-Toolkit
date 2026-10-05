# Contributing

Thanks for helping. This toolkit is used to organise legal-compliance work, so the bar is
**correctness first**: a wrong deadline or a mis-cited article is worse than a missing feature.

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md). Security problems go through
[SECURITY.md](SECURITY.md), not public issues.

## Development setup

```bash
git clone https://github.com/AlfAxis/EU-Cyber-Resilience-Act-Toolkit.git
cd EU-Cyber-Resilience-Act-Toolkit
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pre-commit install                   # optional: runs ruff on commit
```

Run everything CI runs:

```bash
ruff check . && ruff format --check . && mypy && pytest
```

`mypy` is strict and targets the oldest supported Python (3.10), which also catches use of newer
standard-library APIs. The project has **one runtime dependency** (`requests`); please do not add
another without a strong reason (the TOML helper in `sbom.py` exists precisely to avoid needing
`tomli` on Python 3.10).

## Ground rules

1. **Tests with every change.** A bug fix includes a test that fails without it. Logic with legal
   consequences (deadlines, gates, version ranges) should survive a quick mutation check: if you can break
   it by hand (change `24` hours to `23`, flip a comparison) and the suite stays green, the suite is
   missing a test.
2. **Legal text is verified, never recalled.** Any article, paragraph or annex reference you add must be
   checked against the official text on [EUR-Lex](https://eur-lex.europa.eu/eli/reg/2024/2847/oj).
   If you cannot pin a paragraph number, cite the article only. Say in the PR where you verified it.
3. **Both languages.** User-facing strings live in `src/cra_toolkit/i18n.py` as `key: (German, English)`.
   `tests/test_i18n.py` fails on a missing key or mismatched placeholders. German is the primary
   language, so give it the same care as English.
4. **Fail closed.** If the tool cannot determine something (an unreadable lockfile, an unreachable
   database, an ambiguous timestamp), it must say so and stop or flag it, never produce a plausible
   partial result.
5. **No silent guesses.** Unknown facts in generated documents are visible placeholders.
6. **Keep the boundary.** The toolkit drafts and organises; it does not decide legal questions
   (classification, "actively exploited", "severe incident") and it does not submit reports.

## Where things live

| Task | Start here |
|---|---|
| Support a new ecosystem | `src/cra_toolkit/sbom.py`: add a parser returning `ParseResult`, register it in `SOURCES`, add `ECOSYSTEMS` mapping in `vulns.py`, add a fixture under `tests/fixtures/sample-project` |
| Change a deadline rule | `src/cra_toolkit/reports.py` (`compute_deadlines`) and `tests/test_register_reports_docs.py` |
| Change draft or Annex II wording | `src/cra_toolkit/i18n.py` (+ layout in `reports.py` / `docs.py`) |
| Add a CLI option | `src/cra_toolkit/cli.py` and `tests/test_cli.py` |

Data flow in one line: *lockfiles → `Component` (purl) → CycloneDX SBOM → OSV query by the same purl →
merged findings → evidence JSON*; and *register + case → drafts / Annex II / status*.

## Commits and pull requests

- Small, focused PRs. Describe *why*, not only *what*.
- Use the imperative mood in commit subjects ("Add Cargo.lock checksums"), keep them under ~72 characters.
- Update [CHANGELOG.md](CHANGELOG.md) under *Unreleased* for user-visible changes.
- CI must be green on all platforms before merge.

## Releasing (maintainers)

1. Move *Unreleased* entries to a new version section in `CHANGELOG.md`.
2. Bump `__version__` in `src/cra_toolkit/__init__.py`.
3. Tag `vX.Y.Z` on `main` and push the tag. The *Release* workflow verifies that the tag matches the
   package version, builds the distributions and publishes a GitHub release.
