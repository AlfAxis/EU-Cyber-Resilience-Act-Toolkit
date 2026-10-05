"""Message catalog (German by default, English on request).

Every user-facing string lives here as ``key -> (German, English)``. Legal
citations follow Regulation (EU) 2024/2847; German uses "Abs." / "lit.",
English uses the "(2)(a)" style of the official English text.

``tests/test_i18n.py`` fails if a key referenced in the code is missing or a
placeholder differs between the two languages.
"""

from __future__ import annotations

LANGUAGES = ("de", "en")

_language = "de"


def set_language(language: str) -> None:
    global _language
    _language = language if language in LANGUAGES else "de"


def get_language() -> str:
    return _language


def has(key: str) -> bool:
    return key in CATALOG


def t(key: str, **values: object) -> str:
    """Translate ``key`` into the active language, formatting ``{placeholders}``."""
    german, english = CATALOG[key]
    text = english if _language == "en" else german
    return text.format(**values) if values else text


CATALOG: dict[str, tuple[str, str]] = {
    # ---------------------------------------------------------------- labels
    "label.warning": ("Warnung", "Warning"),
    "label.error": ("Fehler", "Error"),
    "note.none": ("keine", "none"),
    "note.unset": ("(nicht gesetzt)", "(not set)"),
    "note.version_managed": ("Version über Parent/BOM verwaltet", "version managed by parent/BOM"),
    # ---------------------------------------------------------------- errors
    "err.datetime_needs_time": (
        "Zeitangabe '{value}' enthält keine Uhrzeit. Verwenden Sie ISO 8601, z. B. 2026-09-12T08:30+02:00.",
        "Timestamp '{value}' has no time of day. Use ISO 8601, e.g. 2026-09-12T08:30+02:00.",
    ),
    "err.bad_datetime": (
        "Ungültige Zeitangabe '{value}'. Verwenden Sie ISO 8601, z. B. 2026-09-12T08:30+02:00.",
        "Invalid timestamp '{value}'. Use ISO 8601, e.g. 2026-09-12T08:30+02:00.",
    ),
    "err.bad_date": (
        "Ungültiges Datum '{value}'. Erwartet wird JJJJ-MM-TT, z. B. 2031-12-31.",
        "Invalid date '{value}'. Expected YYYY-MM-DD, e.g. 2031-12-31.",
    ),
    "err.invalid_json": ("Ungültiges JSON in {path}: {detail}", "Invalid JSON in {path}: {detail}"),
    "err.cannot_read": (
        "{path} kann nicht gelesen werden: {detail}",
        "Cannot read {path}: {detail}",
    ),
    "err.unparsable_source": (
        "{path} konnte nicht ausgewertet werden: {detail}. Abbruch, damit kein unvollständiges SBOM entsteht.",
        "{path} could not be parsed: {detail}. Aborting rather than emitting an incomplete SBOM.",
    ),
    "err.not_a_directory": ("{path} ist kein Verzeichnis.", "{path} is not a directory."),
    "err.osv_unreachable": (
        "OSV.dev ist nicht erreichbar: {detail}. Es wurde nichts geprüft. Für isolierte Umgebungen: --offline-db.",
        "OSV.dev is unreachable: {detail}. Nothing was checked. For air-gapped use: --offline-db.",
    ),
    "err.osv_bad_response": (
        "Unerwartete Antwort von OSV.dev: {detail}",
        "Unexpected response from OSV.dev: {detail}",
    ),
    "err.offline_db_missing": (
        "Offline-Datenbank nicht gefunden: {path}",
        "Offline database not found: {path}",
    ),
    "err.unknown_market": (
        "Unbekannter Markt '{code}'. Erwartet werden ISO-Ländercodes der EU-Mitgliedstaaten (z. B. DE) oder EU.",
        "Unknown market '{code}'. Expected ISO codes of EU member states (e.g. DE) or EU.",
    ),
    "err.product_exists": (
        "Produkt '{id}' existiert bereits. Mit 'register update' ändern oder --id vergeben.",
        "Product '{id}' already exists. Change it with 'register update' or pass --id.",
    ),
    "err.unknown_product": (
        "Produkt '{id}' nicht im Register. Bekannt: {known}",
        "Product '{id}' is not in the register. Known: {known}",
    ),
    "err.unknown_case": (
        "Fall '{id}' nicht gefunden. Bekannt: {known}",
        "Case '{id}' not found. Known: {known}",
    ),
    "err.unknown_stage": ("Unbekannte Stufe '{stage}'.", "Unknown stage '{stage}'."),
    # -------------------------------------------------------------- warnings
    "warn.local_dependency": (
        "{name} ({path}) ist eine lokale/Git-Abhängigkeit und wurde nicht erfasst.",
        "{name} ({path}) is a local/git dependency and was not inventoried.",
    ),
    "warn.unresolvable_dependency": (
        "In {path} wurde eine Abhängigkeit mit nicht auflösbaren Platzhaltern übersprungen.",
        "A dependency with unresolvable placeholders in {path} was skipped.",
    ),
    "warn.manifest_without_lock": (
        "{path} deklariert Abhängigkeiten ohne Lockfile und wurde nicht ausgewertet — "
        "das CRA betrifft, was Sie ausliefern, nicht was Sie deklarieren.",
        "{path} declares dependencies without a lockfile and was not read — "
        "the CRA concerns what you shipped, not what you declared.",
    ),
    # ------------------------------------------------------------------ time
    "time.days_hours": ("{days} Tage {hours} Std.", "{days} d {hours} h"),
    "time.hours_minutes": ("{hours} Std. {minutes} Min.", "{hours} h {minutes} min"),
    "time.minutes": ("{minutes} Min.", "{minutes} min"),
    # ------------------------------------------------------------ sbom / scan
    "sbom.written": (
        "SBOM geschrieben: {path} ({components} Komponenten aus {sources} Quelle(n))",
        "SBOM written: {path} ({components} components from {sources} source(s))",
    ),
    "sbom.no_sources": (
        "Keine unterstützten Abhängigkeitsdateien gefunden; das SBOM ist leer.",
        "No supported dependency files found; the SBOM is empty.",
    ),
    "scan.inventory": (
        "SBOM: {components} Komponenten aus {sources} Quelle(n)",
        "SBOM: {components} components from {sources} source(s)",
    ),
    "scan.source": ("Schwachstellenquelle: {source}", "Vulnerability source: {source}"),
    "scan.checked": (
        "Geprüft: {checked} · Nicht prüfbar (Version nicht aufgelöst): {unchecked}",
        "Checked: {checked} · Not checkable (version unresolved): {unchecked}",
    ),
    "scan.found": (
        "{findings} Fund(e) in {components} Komponente(n): {breakdown}",
        "{findings} finding(s) in {components} component(s): {breakdown}",
    ),
    "scan.none_found": (
        "Keine bekannten Schwachstellen in den geprüften Komponenten gefunden.",
        "No known vulnerabilities found in the checked components.",
    ),
    "scan.col.component": ("KOMPONENTE", "COMPONENT"),
    "scan.col.version": ("VERSION", "VERSION"),
    "scan.col.severity": ("SCHWERE", "SEVERITY"),
    "scan.col.fixed": ("BEHOBEN IN", "FIXED IN"),
    "scan.not_checkable": (
        "Nicht prüfbar — Version nicht aufgelöst (Lockfile verwenden oder Version festschreiben):",
        "Not checkable — version unresolved (use a lockfile or pin the version):",
    ),
    "scan.ignored": (
        "{count} Fund(e) per --ignore ausgenommen (im Nachweis dokumentiert).",
        "{count} finding(s) accepted via --ignore (recorded in the evidence).",
    ),
    "scan.gate_passed": (
        "Gate (--fail-on {level}): bestanden",
        "Gate (--fail-on {level}): passed",
    ),
    "scan.gate_failed": (
        "Gate (--fail-on {level}): NICHT bestanden",
        "Gate (--fail-on {level}): FAILED",
    ),
    "scan.unknown_not_gated": (
        "{count} Fund(e) mit unbekannter Schwere wurden vom Gate nicht erfasst (nur --fail-on any erfasst sie).",
        "{count} finding(s) of unknown severity were not gated (only --fail-on any includes them).",
    ),
    "scan.offline_note": (
        "Offline-Abgleich nutzt eine vereinfachte Versionsordnung; bei Zweifeln online gegenprüfen.",
        "Offline matching uses a simplified version ordering; cross-check online when in doubt.",
    ),
    "scan.offline_skipped": (
        "{count} Datei(en) der Offline-Datenbank waren nicht lesbar und wurden übersprungen.",
        "{count} offline-database file(s) were unreadable and skipped.",
    ),
    "scan.evidence": ("Nachweis gespeichert: {path}", "Evidence saved: {path}"),
    "scan.disclaimer": (
        "Hinweis: Ein sauberer Scan ist ein Nachweis, keine Konformität. Keine Rechtsberatung.",
        "Note: a clean scan is one piece of evidence, not compliance. Not legal advice.",
    ),
    "severity.critical": ("kritisch", "critical"),
    "severity.high": ("hoch", "high"),
    "severity.medium": ("mittel", "medium"),
    "severity.low": ("niedrig", "low"),
    "severity.unknown": ("unbekannt", "unknown"),
    # -------------------------------------------------------------- register
    "register.added": (
        "Produkt '{id}' im Register angelegt ({path}).",
        "Product '{id}' added to the register ({path}).",
    ),
    "register.updated": ("Produkt '{id}' aktualisiert.", "Product '{id}' updated."),
    "register.removed": ("Produkt '{id}' entfernt.", "Product '{id}' removed."),
    "register.empty": (
        "Das Produktregister ist leer. Mit 'register add' beginnen.",
        "The product register is empty. Start with 'register add'.",
    ),
    "register.col.product": ("PRODUKT", "PRODUCT"),
    "register.col.class": ("EINSTUFUNG", "CLASS"),
    "register.col.support": ("SUPPORT BIS", "SUPPORT UNTIL"),
    "reg.field.id": ("ID", "ID"),
    "reg.field.name": ("Produkt", "Product"),
    "reg.field.type": ("Typ", "Type"),
    "reg.field.manufacturer": ("Hersteller", "Manufacturer"),
    "reg.field.address": ("Postanschrift", "Postal address"),
    "reg.field.email": ("E-Mail/Kontakt", "Email/contact"),
    "reg.field.website": ("Website", "Website"),
    "reg.field.vulnerability_contact": ("Kontaktstelle Schwachstellen", "Vulnerability contact"),
    "reg.field.cvd_policy_url": ("CVD-Richtlinie", "CVD policy"),
    "reg.field.classification": ("Einstufung", "Classification"),
    "reg.field.support_end": ("Supportzeitraum bis", "Support period until"),
    "reg.field.placed_on_market": ("In Verkehr gebracht", "Placed on market"),
    "reg.field.markets": ("Märkte", "Markets"),
    "reg.field.purpose": ("Verwendungszweck", "Intended purpose"),
    "reg.field.doc_url": ("Konformitätserklärung", "Declaration of conformity"),
    "class.default": (
        "Standard (keine Einstufung nach Anhang III/IV)",
        "Default (not listed in Annex III/IV)",
    ),
    "class.important-class-1": (
        "Wichtiges Produkt, Klasse I (Anhang III)",
        "Important product, class I (Annex III)",
    ),
    "class.important-class-2": (
        "Wichtiges Produkt, Klasse II (Anhang III)",
        "Important product, class II (Annex III)",
    ),
    "class.critical": ("Kritisches Produkt (Anhang IV)", "Critical product (Annex IV)"),
    "check.manufacturer_name": ("Name des Herstellers", "Manufacturer name"),
    "check.manufacturer_address": ("Postanschrift des Herstellers", "Manufacturer postal address"),
    "check.manufacturer_email": (
        "E-Mail/digitaler Kontakt des Herstellers",
        "Manufacturer email/digital contact",
    ),
    "check.vulnerability_contact": (
        "Kontaktstelle für Schwachstellenmeldungen",
        "Single point of contact for vulnerability reports",
    ),
    "check.classification": (
        "Einstufung (Standard/Anhang III/IV)",
        "Classification (default/Annex III/IV)",
    ),
    "check.support_period_end": ("Ende des Supportzeitraums", "End of support period"),
    "check.markets": ("Märkte (Mitgliedstaaten)", "Markets (member states)"),
    "check.intended_purpose": ("Verwendungszweck", "Intended purpose"),
    "check.cvd_policy_url": ("CVD-Richtlinie (URL)", "CVD policy (URL)"),
    "check.placed_on_market": ("Datum des Inverkehrbringens", "Date placed on the market"),
    "check.declaration_of_conformity_url": (
        "URL der Konformitätserklärung",
        "Declaration of conformity URL",
    ),
    "ref.annex2_1": ("Anhang II Nr. 1", "Annex II No. 1"),
    "ref.annex2_2": ("Anhang II Nr. 2", "Annex II No. 2"),
    "ref.annex2_4": ("Anhang II Nr. 4", "Annex II No. 4"),
    "ref.annex2_6": ("Anhang II Nr. 6", "Annex II No. 6"),
    "ref.classification": ("Art. 7, 8; Anhang III, IV", "Art. 7, 8; Annex III, IV"),
    "ref.support": ("Art. 13 Abs. 8; Anhang II Nr. 7", "Art. 13(8); Annex II No. 7"),
    "ref.art14_2a": ("Art. 14 Abs. 2 lit. a", "Art. 14(2)(a)"),
    "ref.art13_8": ("Art. 13 Abs. 8", "Art. 13(8)"),
    "adv.support_expired": (
        "Der Supportzeitraum ist am {date} abgelaufen.",
        "The support period ended on {date}.",
    ),
    "adv.support_short": (
        "Der Supportzeitraum ist kürzer als fünf Jahre ab Inverkehrbringen. Nach Art. 13 Abs. 8 CRA "
        "ist das nur zulässig, wenn die erwartete Nutzungsdauer des Produkts kürzer ist.",
        "The support period is shorter than five years from placing on the market. Under Art. 13(8) CRA "
        "that is only allowed if the product is expected to be used for less than five years.",
    ),
    "adv.conformity.default": (
        "Orientierung (keine Rechtsberatung): Für Produkte ohne Einstufung nach Anhang III/IV genügt "
        "grundsätzlich die interne Kontrolle (Art. 32 CRA).",
        "Orientation (not legal advice): products outside Annex III/IV can generally use internal "
        "control (Art. 32 CRA).",
    ),
    "adv.conformity.important-class-1": (
        "Orientierung (keine Rechtsberatung): Wichtiges Produkt Klasse I — interne Kontrolle nur unter den "
        "Voraussetzungen des Art. 32 CRA (z. B. harmonisierte Normen), sonst Bewertung durch Dritte.",
        "Orientation (not legal advice): important product class I — internal control only under the "
        "conditions of Art. 32 CRA (e.g. harmonised standards), otherwise third-party assessment.",
    ),
    "adv.conformity.important-class-2": (
        "Orientierung (keine Rechtsberatung): Wichtiges Produkt Klasse II — Konformitätsbewertung unter "
        "Beteiligung einer notifizierten Stelle (Art. 32 CRA).",
        "Orientation (not legal advice): important product class II — conformity assessment involving a "
        "notified body (Art. 32 CRA).",
    ),
    "adv.conformity.critical": (
        "Orientierung (keine Rechtsberatung): Kritisches Produkt — gegebenenfalls Pflicht zur europäischen "
        "Cybersicherheitszertifizierung (Art. 8 CRA).",
        "Orientation (not legal advice): critical product — European cybersecurity certification may be "
        "mandatory (Art. 8 CRA).",
    ),
    # ---------------------------------------------------------------- report
    "report.assumed_local": (
        "Zeitangabe ohne Zeitzone: es wird die lokale Zeitzone angenommen ({value}). "
        "Für Fristen besser mit Offset angeben (z. B. +02:00).",
        "Timestamp has no timezone: assuming local time ({value}). "
        "For deadlines, prefer an explicit offset (e.g. +02:00).",
    ),
    "report.opened": ("Fall '{id}' angelegt ({path}).", "Case '{id}' opened ({path})."),
    "report.deadlines_heading": ("Fristen:", "Deadlines:"),
    "report.next_step": (
        "Entwurf erzeugen: cra-toolkit report draft {id}",
        "Generate drafts: cra-toolkit report draft {id}",
    ),
    "report.updated": ("Fall '{id}' aktualisiert.", "Case '{id}' updated."),
    "report.filed": (
        "{stage} für Fall '{id}' als eingereicht vermerkt ({at}).",
        "{stage} for case '{id}' recorded as submitted ({at}).",
    ),
    "report.drafted": ("{stage}: Entwurf geschrieben → {path}", "{stage}: draft written → {path}"),
    "report.missing": (
        "  {count} Angabe(n) noch offen: {fields}",
        "  {count} item(s) still open: {fields}",
    ),
    "report.list_empty": ("Keine Fälle erfasst.", "No cases recorded."),
    "stage.early-warning": ("Frühwarnung", "Early warning"),
    "stage.notification": ("Meldung", "Notification"),
    "stage.final-report": ("Abschlussbericht", "Final report"),
    "basis.awareness": ("ab Kenntniserlangung", "from awareness"),
    "basis.fix_available": (
        "14 Tage nach Verfügbarkeit der Korrektur-/Abhilfemaßnahme",
        "14 days after the corrective/mitigating measure became available",
    ),
    "basis.pending_fix": (
        "offen — 14 Tage nach Verfügbarkeit einer Korrektur- oder Abhilfemaßnahme "
        "(erfassen mit 'report update --fix-available-at')",
        "open — 14 days after a corrective or mitigating measure is available "
        "(record with 'report update --fix-available-at')",
    ),
    "basis.notification_filed": (
        "ein Monat nach Einreichung der Meldung",
        "one month after the notification was submitted",
    ),
    "basis.pending_notification": (
        "offen — ein Monat nach Einreichung der Meldung "
        "(erfassen mit 'report filed --stage notification')",
        "open — one month after the notification is submitted "
        "(record with 'report filed --stage notification')",
    ),
    "legal.vulnerability.early-warning": (
        "Art. 14 Abs. 2 lit. a CRA (Frühwarnung, 24 Stunden)",
        "Art. 14(2)(a) CRA (early warning, 24 hours)",
    ),
    "legal.vulnerability.notification": (
        "Art. 14 Abs. 2 lit. b CRA (Meldung der Schwachstelle, 72 Stunden)",
        "Art. 14(2)(b) CRA (vulnerability notification, 72 hours)",
    ),
    "legal.vulnerability.final-report": (
        "Art. 14 Abs. 2 lit. c CRA (Abschlussbericht, 14 Tage nach Verfügbarkeit einer Korrektur- oder Abhilfemaßnahme)",
        "Art. 14(2)(c) CRA (final report, 14 days after a corrective or mitigating measure is available)",
    ),
    "legal.incident.early-warning": (
        "Art. 14 Abs. 4 lit. a CRA (Frühwarnung, 24 Stunden)",
        "Art. 14(4)(a) CRA (early warning, 24 hours)",
    ),
    "legal.incident.notification": (
        "Art. 14 Abs. 4 lit. b CRA (Meldung des Sicherheitsvorfalls, 72 Stunden)",
        "Art. 14(4)(b) CRA (incident notification, 72 hours)",
    ),
    "legal.incident.final-report": (
        "Art. 14 Abs. 4 lit. c CRA (Abschlussbericht, ein Monat nach Einreichung der Meldung)",
        "Art. 14(4)(c) CRA (final report, one month after the incident notification was submitted)",
    ),
    "draft.title.vulnerability.early-warning": (
        "Entwurf: Frühwarnung — aktiv ausgenutzte Schwachstelle",
        "Draft: early warning — actively exploited vulnerability",
    ),
    "draft.title.vulnerability.notification": (
        "Entwurf: Meldung — aktiv ausgenutzte Schwachstelle",
        "Draft: notification — actively exploited vulnerability",
    ),
    "draft.title.vulnerability.final-report": (
        "Entwurf: Abschlussbericht — aktiv ausgenutzte Schwachstelle",
        "Draft: final report — actively exploited vulnerability",
    ),
    "draft.title.incident.early-warning": (
        "Entwurf: Frühwarnung — schwerwiegender Sicherheitsvorfall",
        "Draft: early warning — severe incident",
    ),
    "draft.title.incident.notification": (
        "Entwurf: Meldung — schwerwiegender Sicherheitsvorfall",
        "Draft: notification — severe incident",
    ),
    "draft.title.incident.final-report": (
        "Entwurf: Abschlussbericht — schwerwiegender Sicherheitsvorfall",
        "Draft: final report — severe incident",
    ),
    "draft.banner": ("ENTWURF — NICHT EINGEREICHT", "DRAFT — NOT SUBMITTED"),
    "draft.banner_docs": ("GERÜST — INHALTE PRÜFEN.", "SKELETON — REVIEW THE CONTENT."),
    "draft.disclaimer": (
        "Entwurf zur Prüfung durch den Hersteller. Keine Rechtsberatung. Die Einreichung erfolgt durch Sie.",
        "Draft for the manufacturer's review. Not legal advice. Submission is up to you.",
    ),
    "draft.placeholder": ("[BITTE ERGÄNZEN]", "[PLEASE COMPLETE]"),
    "draft.field": ("Feld", "Field"),
    "draft.entry": ("Angabe", "Entry"),
    "draft.manufacturer": ("Hersteller", "Manufacturer"),
    "draft.product": ("Produkt", "Product"),
    "draft.version": ("Version", "Version"),
    "draft.type": ("Typ", "Type"),
    "draft.classification": ("Einstufung", "Classification"),
    "draft.reference": ("Bezug", "Reference"),
    "draft.aware_at": ("Kenntniserlangung", "Became aware"),
    "draft.deadline": ("Frist", "Deadline"),
    "draft.legal_basis": ("Rechtsgrundlage", "Legal basis"),
    "draft.case_id": ("Fall-ID", "Case ID"),
    "draft.notes": ("Hinweise", "Notes"),
    "field.summary": ("Beschreibung", "Description"),
    "field.summary.vulnerability": (
        "Beschreibung der Schwachstelle",
        "Description of the vulnerability",
    ),
    "field.summary.incident": ("Beschreibung des Vorfalls", "Description of the incident"),
    "field.component": ("Betroffene Komponente", "Affected component"),
    "field.malicious_suspected": (
        "Verdacht auf rechtswidrige oder böswillige Handlungen",
        "Suspected unlawful or malicious acts",
    ),
    "field.member_states": (
        "Mitgliedstaaten, in denen das Produkt bereitgestellt wird",
        "Member States in which the product has been made available",
    ),
    "field.product_info": (
        "Allgemeine Angaben zum Produkt",
        "General information about the product",
    ),
    "field.exploitation": (
        "Allgemeine Art des Exploits und der Schwachstelle",
        "General nature of the exploit and of the vulnerability",
    ),
    "field.measures_taken": (
        "Ergriffene Korrektur- oder Abhilfemaßnahmen",
        "Corrective or mitigating measures taken",
    ),
    "field.user_measures": (
        "Maßnahmen, die Nutzer ergreifen können",
        "Corrective or mitigating measures users can take",
    ),
    "field.sensitivity": (
        "Sensibilität der übermittelten Informationen",
        "Sensitivity of the notified information",
    ),
    "field.severity": ("Schweregrad", "Severity"),
    "field.impact": ("Auswirkungen", "Impact"),
    "field.actor": (
        "Angaben zu böswilligen Akteuren (soweit verfügbar)",
        "Information on the malicious actor (where available)",
    ),
    "field.update_details": (
        "Details zum Sicherheitsupdate bzw. zu den Abhilfemaßnahmen",
        "Details of the security update or other corrective measures",
    ),
    "field.root_cause": ("Art der Bedrohung bzw. Ursache", "Type of threat or root cause"),
    "note.not_filed": (
        "Dies ist ein Entwurf. Das Tool reicht nichts ein; Sie prüfen, ergänzen und übermitteln selbst.",
        "This is a draft. The tool submits nothing; you review, complete and submit it yourself.",
    ),
    "note.platform": (
        "Einreichung über die einheitliche Meldeplattform (Art. 16 CRA); sie erreicht gleichzeitig das als "
        "Koordinator benannte CSIRT und die ENISA (Art. 14 Abs. 1 CRA).",
        "Submit via the single reporting platform (Art. 16 CRA); it reaches the CSIRT designated as "
        "coordinator and ENISA at the same time (Art. 14(1) CRA).",
    ),
    "note.unless_provided": (
        "Informationen, die bereits übermittelt wurden, müssen nicht erneut geliefert werden "
        "(vgl. Art. 14 Abs. 2 lit. b und c CRA).",
        "Information that has already been provided need not be supplied again "
        "(cf. Art. 14(2)(b) and (c) CRA).",
    ),
    "note.final_after_fix": (
        "Die Frist für den Abschlussbericht beginnt erst, wenn eine Korrektur- oder Abhilfemaßnahme "
        "verfügbar ist, und endet 14 Tage danach (Art. 14 Abs. 2 lit. c CRA).",
        "The final-report deadline only starts once a corrective or mitigating measure is available "
        "and ends 14 days later (Art. 14(2)(c) CRA).",
    ),
    "note.final_after_notification": (
        "Der Abschlussbericht ist innerhalb eines Monats nach Einreichung der Meldung zu übermitteln "
        "(Art. 14 Abs. 4 lit. c CRA).",
        "The final report is due within one month after the notification was submitted "
        "(Art. 14(4)(c) CRA).",
    ),
    "note.inform_users": (
        "Betroffene Nutzer — gegebenenfalls alle Nutzer — sind ebenfalls zu informieren, wo nötig mit "
        "Hinweisen zu Abhilfemaßnahmen (Art. 14 Abs. 8 CRA).",
        "Impacted users — and where appropriate all users — must be informed as well, including "
        "available mitigation where necessary (Art. 14(8) CRA).",
    ),
    "note.legal_determination": (
        "Ob eine Schwachstelle aktiv ausgenutzt bzw. ein Vorfall schwerwiegend ist, bewerten Sie als "
        "Hersteller (rechtlich und tatsächlich). Dieses Tool trifft diese Bewertung nicht.",
        "Whether a vulnerability is actively exploited or an incident is severe is your assessment as "
        "manufacturer (legal and factual). This tool does not make it.",
    ),
    # ---------------------------------------------------------------- status
    "status.title": ("CRA-Status — {now}", "CRA status — {now}"),
    "status.cases_heading": (
        "Art.-14-Meldungen ({overdue} überfällig)",
        "Article 14 reports ({overdue} overdue)",
    ),
    "status.no_cases": ("Keine Fälle erfasst.", "No cases recorded."),
    "status.register_heading": (
        "Produktregister ({incomplete} unvollständig)",
        "Product register ({incomplete} incomplete)",
    ),
    "status.no_products": ("Keine Produkte im Register.", "No products in the register."),
    "status.completeness": (
        "{done}/{total} Pflichtangaben ({percent} %)",
        "{done}/{total} required fields ({percent}%)",
    ),
    "status.missing": ("FEHLT", "MISSING"),
    "status.recommended": ("EMPFOHLEN", "RECOMMENDED"),
    "status.hint": ("Hinweis", "Note"),
    "state.filed": ("eingereicht am {at}", "submitted on {at}"),
    "state.filed_late": (
        "VERSPÄTET eingereicht am {at} (Frist war {due})",
        "submitted LATE on {at} (deadline was {due})",
    ),
    "state.overdue": (
        "ÜBERFÄLLIG seit {span} (Frist {due})",
        "OVERDUE by {span} (deadline {due})",
    ),
    "state.open": ("fällig {due} — noch {span}", "due {due} — {span} left"),
    # ------------------------------------------------------------------ docs
    "docs.written": ("Annex-II-Gerüst geschrieben: {path}", "Annex II skeleton written: {path}"),
    "annex2.title": (
        "Informationen und Anweisungen für Nutzer (Anhang II CRA)",
        "Information and instructions to the user (Annex II CRA)",
    ),
    "annex2.intro": (
        "Dieses Gerüst folgt der Gliederung von Anhang II der Verordnung (EU) 2024/2847. Vorausgefüllt sind "
        "nur Angaben aus dem Produktregister; alle übrigen Punkte müssen Sie ergänzen. Keine Rechtsberatung.",
        "This skeleton follows the structure of Annex II of Regulation (EU) 2024/2847. Only data from the "
        "product register is pre-filled; you must complete everything else. Not legal advice.",
    ),
    "annex2.generated": (
        "Erstellt am {date} mit cra-toolkit {version}.",
        "Generated on {date} with cra-toolkit {version}.",
    ),
    "annex2.cite": ("Anhang II Nr. {number}", "Annex II No. {number}"),
    "annex2.manufacturer": ("Hersteller", "Manufacturer"),
    "annex2.contact": (
        "Zentrale Kontaktstelle für Schwachstellen",
        "Single point of contact for vulnerabilities",
    ),
    "annex2.identification": ("Produktidentifikation", "Product identification"),
    "annex2.purpose": (
        "Verwendungszweck und Sicherheitsumgebung",
        "Intended purpose and security environment",
    ),
    "annex2.risks": (
        "Bekannte oder vorhersehbare Umstände mit erheblichen Cybersicherheitsrisiken",
        "Known or foreseeable circumstances that may lead to significant cybersecurity risks",
    ),
    "annex2.doc": ("EU-Konformitätserklärung", "EU declaration of conformity"),
    "annex2.support": (
        "Technischer Sicherheitssupport und Supportzeitraum",
        "Technical security support and support period",
    ),
    "annex2.instructions": ("Detaillierte Anweisungen", "Detailed instructions"),
    "annex2.sbom": ("Software-Stückliste (SBOM)", "Software bill of materials (SBOM)"),
    "annex2.name": ("Name", "Name"),
    "annex2.address": ("Postanschrift", "Postal address"),
    "annex2.email": ("E-Mail oder sonstiger digitaler Kontakt", "Email or other digital contact"),
    "annex2.website": ("Website", "Website"),
    "annex2.where_available": ("(sofern vorhanden)", "(where available)"),
    "annex2.vuln_contact": (
        "Kontaktstelle für Schwachstellenmeldungen",
        "Contact point for vulnerability reports",
    ),
    "annex2.cvd_policy": (
        "Richtlinie zur koordinierten Offenlegung von Schwachstellen",
        "Coordinated vulnerability disclosure policy",
    ),
    "annex2.further_ids": (
        "Weitere Angaben zur eindeutigen Identifikation (z. B. Typ-, Chargen- oder Seriennummer)",
        "Further information enabling unique identification (e.g. type, batch or serial number)",
    ),
    "annex2.intended_purpose": ("Verwendungszweck", "Intended purpose"),
    "annex2.security_environment": (
        "Vom Hersteller bereitgestellte Sicherheitsumgebung",
        "Security environment provided by the manufacturer",
    ),
    "annex2.functionalities": ("Wesentliche Funktionen", "Essential functionalities"),
    "annex2.security_properties": ("Sicherheitseigenschaften", "Security properties"),
    "annex2.if_applicable": ("(sofern zutreffend)", "(where applicable)"),
    "annex2.support_type": (
        "Art des angebotenen technischen Sicherheitssupports",
        "Type of technical security support offered",
    ),
    "annex2.support_end": ("Ende des Supportzeitraums", "End of the support period"),
    "annex2.i_commissioning": (
        "Maßnahmen bei der Inbetriebnahme und während der gesamten Lebensdauer für eine sichere Nutzung",
        "Measures needed at initial commissioning and throughout the lifetime for secure use",
    ),
    "annex2.i_changes": (
        "Auswirkungen von Änderungen am Produkt auf die Datensicherheit",
        "How changes to the product can affect the security of data",
    ),
    "annex2.i_updates": (
        "Installation sicherheitsrelevanter Software-Updates",
        "How security-relevant software updates can be installed",
    ),
    "annex2.i_decommissioning": (
        "Sichere Außerbetriebnahme einschließlich sicherer Entfernung von Nutzerdaten",
        "Secure decommissioning, including how user data can be securely removed",
    ),
    "annex2.i_auto_updates": (
        "Deaktivierung der standardmäßig aktivierten automatischen Sicherheitsupdates",
        "How the default setting enabling automatic security updates can be turned off",
    ),
    "annex2.i_integration": (
        "Informationen für Integratoren (bei Produkten zur Integration in andere Produkte)",
        "Information for integrators (for products intended for integration into other products)",
    ),
    "annex2.sbom_optional": (
        "Optional: nur auszufüllen, wenn der Hersteller die SBOM den Nutzern bereitstellen will.",
        "Optional: only complete this if the manufacturer decides to make the SBOM available to users.",
    ),
    "annex2.availability_title": ("Bereitstellung", "Availability"),
    "annex2.availability": (
        "Werden die Informationen online bereitgestellt, müssen sie nach Art. 13 CRA über einen längeren "
        "Zeitraum abrufbar bleiben (mindestens 10 Jahre nach dem Inverkehrbringen oder für die Dauer des "
        "Supportzeitraums, je nachdem, was länger ist). Prüfen Sie den genauen Wortlaut in Art. 13 CRA.",
        "Where the information is provided online, Art. 13 CRA requires it to stay accessible for an "
        "extended period (at least 10 years after placing on the market or for the support period, "
        "whichever is longer). Check the exact wording in Art. 13 CRA.",
    ),
}
