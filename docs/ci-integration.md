# CI integration

`cra-toolkit` is designed to run unattended. Everything it does is deterministic given its inputs,
output is plain text or JSON, and exit codes are meaningful.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success (for `scan`: no finding at or above `--fail-on`) |
| `1` | A gate tripped: findings at or above `--fail-on`; or `status` found an unfiled, overdue Article 14 deadline (`--strict`: also an incomplete register) |
| `2` | Usage or runtime error, including an unreachable vulnerability database and unparsable lockfiles |

Exit `2` for an unreachable database is intentional: a gate that cannot run must not look green.

## Choosing a gate

| `--fail-on` | Trips on |
|---|---|
| `none` (default) | never — report only |
| `critical` / `high` / `medium` / `low` | any finding at that severity or above |
| `any` | every finding, including those of unknown severity |

Findings of *unknown* severity (no CVSS v3 vector and no label in the database) are only included by
`any`; when the gate is `low` or above, the output states how many were not gated so they are never
invisible. Accept a specific known finding with `--ignore CVE-… ` (IDs and aliases both work); ignored
findings are recorded in the evidence report, not hidden.

## GitHub Actions

See [`examples/github-actions/cra-compliance.yml`](../examples/github-actions/cra-compliance.yml)
for a complete workflow that gates pull requests and runs a scheduled scan (new advisories appear
without any code change, so a weekly scan matters).

## Keeping evidence

`scan` writes `sbom-<UTC>.cdx.json` and `scan-<UTC>.json` to the data directory unless you pass
`--no-archive`. In CI, upload `--sbom` / `--report` as build artifacts (as the example does) or commit
the data directory to your compliance repository. Each scan report contains the SHA-256 of the SBOM it
belongs to, so the pair can be verified later.

## Other CI systems

Anything that can run `pip` works. A GitLab CI job, for instance:

```yaml
cra-scan:
  image: python:3.12-slim
  script:
    - pip install "cra-toolkit==0.1.1"
    - cra-toolkit scan . --fail-on high --sbom sbom.cdx.json --report scan-report.json
  artifacts:
    when: always
    paths: [sbom.cdx.json, scan-report.json]
```

## Pinning

For reproducible pipelines, pin an exact version so a toolkit update never changes your results
unannounced:

```bash
pip install "cra-toolkit==0.1.1"
```

To use an unreleased state instead, pin a tag or commit from GitHub:

```bash
pip install "git+https://github.com/AlfAxis/EU-Cyber-Resilience-Act-Toolkit.git@v0.1.1"
```
