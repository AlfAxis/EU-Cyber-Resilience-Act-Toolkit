# Data model

All state is plain UTF-8 JSON (LF line endings) or Markdown under the data directory (`./.cra` by
default; `--data-dir` or `$CRA_TOOLKIT_DATA_DIR` override it). Writes are atomic.

Timestamps are ISO 8601 **with UTC offset**.

## `register.json`

```json
{
  "schema": 1,
  "products": [
    {
      "id": "edge-gateway-2-1-0",
      "name": "Edge Gateway",
      "version": "2.1.0",
      "product_type": "firmware",
      "manufacturer": {
        "name": "Muster GmbH",
        "address": "Musterstraße 1, 10115 Berlin",
        "email": "psirt@muster.example",
        "website": "https://muster.example"
      },
      "classification": "important-class-1",
      "vulnerability_contact": "security@muster.example",
      "cvd_policy_url": null,
      "support_period_end": "2031-12-31",
      "placed_on_market": "2026-06-01",
      "markets": ["AT", "DE"],
      "intended_purpose": "Industrielles Edge-Gateway",
      "declaration_of_conformity_url": null,
      "created_at": "2026-10-05T14:20:11+02:00",
      "updated_at": "2026-10-05T14:20:11+02:00"
    }
  ]
}
```

- `classification` is `null` until you set it: `default`, `important-class-1`, `important-class-2` or
  `critical`.
- `product_type` is one of `application`, `firmware`, `device`, `library`, `operating-system`,
  `framework`.
- Unknown keys are ignored on load, so files written by a newer version stay readable.

## `cases/<case-id>.json`

```json
{
  "id": "2026-10-05-cve-2026-12345",
  "kind": "vulnerability",
  "product_id": "edge-gateway-2-1-0",
  "reference": "CVE-2026-12345",
  "aware_at": "2026-10-05T08:30:00+02:00",
  "fix_available_at": null,
  "summary": "RCE im Web-Interface",
  "filings": {
    "early-warning": { "filed_at": "2026-10-05T17:02:00+02:00", "reference": "ENISA-4711" }
  }
}
```

Other free-text fields feeding the drafts: `component`, `exploitation`, `actor`, `measures_taken`,
`user_measures`, `sensitivity`, `severity`, `impact`, `update_details`, `root_cause`,
`malicious_suspected`. `kind` is `vulnerability` or `incident`. The case ID is
`<UTC date of awareness>-<slug of reference>`, with a numeric suffix on collision.

## `evidence/scan-<UTC>.json`

```json
{
  "tool": { "name": "cra-toolkit", "version": "0.1.0" },
  "generated_at": "2026-10-05T12:27:03Z",
  "target": { "path": "/work/my-product", "product": "edge-gateway-2-1-0" },
  "sbom": { "file": "sbom-20261005T122703Z.cdx.json", "sha256": "…", "components": 34, "sources": ["package-lock.json"] },
  "vulnerability_source": { "type": "osv.dev", "detail": "https://api.osv.dev/v1" },
  "summary": { "components": 34, "checked": 28, "not_checkable": 6, "vulnerable_components": 13,
               "findings": 101, "by_severity": { "critical": 8, "high": 36, "medium": 47, "low": 9, "unknown": 1 },
               "ignored": 0 },
  "gate": { "fail_on": "high", "passed": false },
  "findings": [
    { "purl": "pkg:pypi/django@4.2.0", "name": "django", "version": "4.2.0", "scope": "required",
      "vulnerabilities": [
        { "id": "CVE-2023-31047", "aliases": ["GHSA-r3xc-prgr-mg9p"], "summary": "…",
          "severity": "critical", "cvss_score": 9.8, "cvss_vector": "CVSS:3.1/…",
          "fixed_versions": ["3.2.19", "4.1.9"], "references": ["…"] } ] }
  ],
  "not_checkable": [ { "purl": "pkg:pypi/pyyaml", "version_constraint": ">=5.0,<7", "sources": ["requirements.txt"], "name": "pyyaml" } ],
  "ignored": [],
  "warnings": [],
  "offline_db_files_skipped": []
}
```

`id` is the CVE when one is known, otherwise the OSV identifier; every other identifier for the same
vulnerability is in `aliases`. `sbom.sha256` is the SHA-256 of the exact SBOM text written next to it.

## SBOM extensions

The CycloneDX output uses these `properties` on components:

| Property | Meaning |
|---|---|
| `cra-toolkit:source` | Lockfile or manifest the component came from (repeated if several) |
| `cra-toolkit:unresolved` | `"true"` if no exact version could be determined |
| `cra-toolkit:version-constraint` | The declared constraint for an unresolved component |

`scope` follows CycloneDX: `required`, `optional` (npm optional dependencies, Maven `provided`, Poetry
extras) or `excluded` (dev/test-only dependencies).
