# Security policy

## Reporting a vulnerability

Please report security problems **privately** through GitHub:

**[Report a vulnerability](https://github.com/AlfAxis/EU-Cyber-Resilience-Act-Toolkit/security/advisories/new)**
(repository → *Security* → *Report a vulnerability*).

Do not open a public issue for security reports. Include what you found, how to reproduce it, and
the affected version (`cra-toolkit --version`). You can expect an acknowledgement within a few days;
this is a volunteer-maintained project, so please allow reasonable time for a fix before disclosure.

## Supported versions

Only the latest released version receives fixes.

## Threat model and what the tool does with your data

`cra-toolkit` is run against project directories you may not fully trust (for example a third-party
checkout), so it is built to be conservative:

- **It never executes code from the scanned project.** It only *reads* lockfiles and manifests.
- **XML is parsed defensively.** A `pom.xml` containing a `DOCTYPE` or `ENTITY` declaration is
  rejected, which closes entity-expansion attacks without needing a third-party XML library.
- **Network access is limited to OSV.dev.** The online `scan` sends the **package URLs of your
  components** (name and version, e.g. `pkg:npm/lodash@4.17.15`) to `api.osv.dev`, and fetches
  advisories by ID. Nothing else about your project, your register or your reports is transmitted.
  If even the component inventory is sensitive, use `--offline-db`, which makes no network calls.
- **Nothing is submitted anywhere.** Article 14 reports are drafted locally; you submit them yourself.
- **Local state is plain files.** The data directory (`.cra/` by default) can contain product and
  contact details and unpublished vulnerability information. Protect and version it accordingly.

## Out of scope

Vulnerabilities in third-party components that the toolkit *reports* are not vulnerabilities of the
toolkit. Report those to the respective project. Questions about how to interpret the
Regulation are not security reports either.
