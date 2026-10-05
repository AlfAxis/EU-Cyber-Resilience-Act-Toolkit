# Regulatory context

This page explains which part of Regulation (EU) 2024/2847 (the Cyber Resilience Act, CRA) each
`cra-toolkit` command supports. It is an orientation aid, **not legal advice**; the authoritative
text is on [EUR-Lex](https://eur-lex.europa.eu/eli/reg/2024/2847/oj).

## Timeline

| Date | What applies | Provision |
|---|---|---|
| 10 December 2024 | Entry into force | Art. 71 |
| 11 June 2026 | Chapter IV (notification of conformity assessment bodies, Arts. 35–51) | Art. 71 |
| **11 September 2026** | **Article 14: reporting of actively exploited vulnerabilities and severe incidents** | Art. 71 |
| 11 December 2027 | The rest of the Regulation: essential requirements, technical documentation, CE marking with cybersecurity assessment | Art. 71 |

**Products already on the market.** Products placed on the market before 11 December 2027 are subject
to the Regulation only if they are substantially modified from that date (Art. 69(2)) — *but* the
Article 14 reporting obligations apply to all in-scope products, including those already on the
market (Art. 69(3)).

**Penalties.** Up to €15 000 000 or 2.5 % of worldwide annual turnover, whichever is higher, for
non-compliance with the essential cybersecurity requirements of Annex I and the obligations of
Articles 13 and 14 (Art. 64(2)). Lower tiers apply to other obligations and to supplying incorrect
information to authorities (Art. 64(3)–(4)).

## Article 14: the reporting clock

| Stage | Vulnerability (Art. 14(2)) | Severe incident (Art. 14(4)) |
|---|---|---|
| Early warning | (a) without undue delay, in any event ≤ 24 h after becoming aware; indicates the Member States where the product is available | ≤ 24 h after becoming aware |
| Notification | (b) ≤ 72 h after becoming aware; general product information, nature of the exploit and vulnerability, measures taken and measures users can take, sensitivity of the information | ≤ 72 h after becoming aware |
| Final report | (c) **≤ 14 days after a corrective or mitigating measure is available**; vulnerability description incl. severity and impact, information on the malicious actor where available, details of the security update | ≤ 1 month after the incident notification was submitted |

Further points the toolkit reflects:

- Notifications go **simultaneously** to the CSIRT designated as coordinator and to ENISA, through the
  **single reporting platform** (Art. 14(1), Art. 16).
- The notification and final report are required "unless the relevant information has already been
  provided" (Art. 14(2)(b)–(c)); the drafts carry that reminder.
- After becoming aware, the manufacturer must also **inform impacted users** (Art. 14(8)); every draft
  ends with that reminder.
- The clock runs in **clock hours**, not business days.

### How the toolkit computes deadlines

| Stage | Computed as |
|---|---|
| Early warning | `aware_at + 24 h` |
| Notification | `aware_at + 72 h` |
| Final report — vulnerability | `fix_available_at + 14 days`; **open** until you record the fix with `report update --fix-available-at` |
| Final report — incident | one calendar month after the notification was filed (`report filed --stage notification`); open until then |

The final report is deliberately **not** counted from the moment of awareness: the Regulation anchors
it to the availability of a corrective or mitigating measure (vulnerabilities) or to the submission
of the incident notification (incidents). Until that anchor is known, `status` shows the stage as
*open* with an explanation rather than inventing a date.

## Command ↔ provision map

| Command | Supports | Notes |
|---|---|---|
| `sbom` | Annex I, Part II, point 1 (identify and document components, including by drawing up an SBOM in a commonly used, machine-readable format) | CycloneDX 1.6 |
| `scan` | Annex I, Part II (vulnerability handling); evidence for Art. 13 due diligence | Third-party components only |
| `register` | Art. 7/8 with Annexes III/IV (classification); Art. 13(8) (support period, at least five years unless the product is expected to be used for less); Art. 14(2)(a) (Member States) | Classification is never inferred |
| `report` | Art. 14(1)–(4), (8); Art. 16 | Drafts only; no submission |
| `docs` | Art. 13 with Annex II (information and instructions to the user), points 1–9 | Point 9 (SBOM) is optional for the manufacturer |
| `status` | Operational overview for the above | |

## What is deliberately out of scope

- **Classification and the "actively exploited" / "severe" judgement.** These are the manufacturer's
  legal and factual assessments. `register` stores your decision; `report` records your facts.
- **Submission.** Reports are filed on the single reporting platform by you.
- **Conformity assessment, technical documentation (Annex VII) and the EU declaration of conformity.**
  `register` and `docs` help collect inputs but do not produce these artefacts.
- **First-party code analysis.** The toolkit inventories third-party components.
