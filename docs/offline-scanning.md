# Offline (air-gapped) scanning

`scan --offline-db PATH` matches your inventory against a **local copy of OSV records** instead of
calling OSV.dev. Use it for build networks without internet access, or to scan against a frozen,
auditable snapshot.

## 1. Get the data (on a connected machine)

OSV publishes its full database as per-ecosystem archives:

```text
https://storage.googleapis.com/osv-vulnerabilities/<ECOSYSTEM>/all.zip
```

Download only the ecosystems you use:

| Toolkit ecosystem | `<ECOSYSTEM>` folder |
|---|---|
| npm | `npm` |
| PyPI | `PyPI` |
| Go | `Go` |
| Rust | `crates.io` |
| PHP (Composer) | `Packagist` |
| Java (Maven) | `Maven` |

```bash
mkdir osv-db
curl -L -o osv-db/npm.zip  https://storage.googleapis.com/osv-vulnerabilities/npm/all.zip
curl -L -o osv-db/PyPI.zip https://storage.googleapis.com/osv-vulnerabilities/PyPI/all.zip
```

Transfer the `osv-db/` directory into the isolated environment. Keep the download date: it is the
"as of" date of your evidence.

## 2. Scan

```bash
cra-toolkit scan . --offline-db osv-db --fail-on high
```

`PATH` may be a directory (searched recursively for `.json` and `.zip` files), a single `.zip`, or a
single `.json` file (one record or a list of records). Only records for packages that actually appear
in your SBOM are kept in memory, so the full ecosystem archives are fine.

## What to know

- The evidence report records `"type": "offline"` and the database path, so a reader can tell the
  result came from a snapshot rather than the live service.
- Unreadable files in the database are skipped and counted; the count is printed and stored in the
  report (`offline_db_files_skipped`).
- Matching uses a **simplified version ordering** shared across ecosystems (see
  `src/cra_toolkit/versions.py`). It handles typical SemVer, PEP 440, Maven and Composer ranges, but
  exotic versions (PEP 440 epochs, unusual Maven qualifiers) can mis-order. The online path uses
  OSV.dev's native per-ecosystem matching and is authoritative: **when a result matters, cross-check it
  online.**
- Withdrawn advisories are ignored, as online.
