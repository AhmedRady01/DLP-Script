# Egyptian Mini-DLP

A lightweight **Data Loss Prevention (DLP) prototype** in Python that detects Egyptian personal and sensitive data in text, files, PDFs and images, calculates a risk score, applies an **ALLOW / ALERT / BLOCK** policy, masks sensitive values and writes SOC-ready logs.

Built for the CyberGuardX SOC Diploma, Project 04 (Egyptian Data Protection DLP Challenge).

> **Disclaimer:** this is a classroom security prototype. It is not an enterprise DLP product, not legal advice, and not a certification of compliance with Egypt's Personal Data Protection Law No. 151 of 2020. Use **synthetic test data only**.

## Pipeline

```
INPUT (text / file / PDF / image)
   -> Detection (regex + rules)
   -> Validation (National ID structure, Luhn, IBAN mod-97)
   -> Classification
   -> Risk engine (+ correlation rules)
   -> Policy engine (ALLOW / ALERT / BLOCK)
   -> Masking
   -> SOC logging (dlp.log + SIEM JSON)
```

## Features

| Area | What it does |
|---|---|
| Egyptian National ID | Regex plus validation of century digit, real birth date and governorate code. Structurally invalid IDs are flagged as *suspected* (lower score) to reduce false positives |
| Mobile, email | `01[0125]` + 8 digits (also `+20` and spaces), standard email pattern |
| Credit cards | Pattern + **Luhn** check + brand (Visa, Mastercard, Amex, Meeza) |
| Egyptian IBAN | `EG` + 27 digits with **mod-97** validation |
| Keywords | English and Arabic: password, medical record, salary, passport, bank account, national ID (Arabic-Indic digits are normalised) |
| Masking | `29801011234567` -> `************4567`, `ahmed@example.com` -> `a***@example.com`, secrets -> `********` |
| Logging | Human-readable `dlp.log` and one-JSON-per-line `dlp_siem.jsonl` (SIEM-ready). Raw values are never written; a keyed HMAC fingerprint lets analysts correlate events |
| Inputs | Text, `.txt`, `.csv`, `.pdf` (with page numbers), images via optional OCR, folders, and an active **watch mode** |

## Quick start

Requires Python 3.8+. The core needs **no third-party packages**.

```bash
python project4.py                 # run the mandatory test scenario
python project4.py --selftest      # run the built-in test cases
```

Optional extras:

```bash
pip install -r requirements.txt    # pypdf (PDF), pytesseract + pillow (images)
```

Image scanning also needs the [Tesseract OCR](https://github.com/UB-Mannheim/tesseract/wiki) program installed. If an optional dependency is missing, the file is skipped with a clear message and the scan continues.

## Usage

```bash
python project4.py --text "Email: a@b.com, Phone: 01012345678"
python project4.py --file data.csv report.pdf screenshot.png folder/
python project4.py --watch inbox/          # active mode, Ctrl+C to stop
python project4.py --watch inbox/ --interval 5
python project4.py --file data.csv --json  # also print the SIEM-ready JSON alert
```

## Risk and policy

| Finding | Score |
|---|---|
| Email | +10 |
| Egyptian mobile | +10 |
| National ID (valid) | +40 |
| Credit card (Luhn valid) | +40 |
| Egyptian IBAN / bank account | +40 |
| Password | +50 |
| Medical record | +50 |
| Passport | +30 |
| Salary | +20 |
| Suspected (failed validation) | +15 |

Repeated findings of the same type add 25% each, capped at 2x the base score.

**Correlation rules** (dangerous combinations):

| Rule | Condition | Score |
|---|---|---|
| `IDENTITY_FRAUD_KIT` | National ID + card / IBAN / bank account | +20 |
| `CREDENTIAL_WITH_PII` | Password + personal data | +10 |
| `BULK_PII_EXPOSURE` | 10 or more personal-data findings | +20 |

| Total risk | Action | Level |
|---|---|---|
| 0-20 | ALLOW | LOW |
| 21-50 | ALERT | MEDIUM |
| 51-80 | BLOCK | HIGH |
| 81+ | BLOCK | CRITICAL |

A leaked **password always triggers BLOCK**, even if the total score is low.

## Example output

```
RISK SCORE : 200   LEVEL: CRITICAL
ACTION     : BLOCK

Redacted preview (what is safe to show/store):
  Email: a***@example.com
  Phone: *******5678
  National ID: ************4567
  Credit Card: ************1111
  Password: ********
```

Log line:

```
2026-10-19 15:21:51,040 | CRITICAL | EVENT=DLP_FINDING SCAN=a69e9515 SOURCE=demo_scenario LINE=4 TYPE=EGYPTIAN_NATIONAL_ID CLASSIFICATION=HIGHLY_SENSITIVE FINDING_SCORE=40 RISK=200 ACTION=BLOCK VALUE=************4567 FP=727bf86f7193
```

## Project files

| File | Purpose |
|---|---|
| `project4.py` | The DLP prototype |
| `sample_customers.csv`, `sample_report.pdf`, `sample_screenshot.png` | Synthetic sample inputs |
| `project4_commands.pdf` | Command reference |
| `requirements.txt` | Optional dependencies |

## Limitations

- Regex and rule based, so it can produce false positives and false negatives.
- OCR can misread digits; results from images should be verified manually.
- Scanned (image-only) PDFs are skipped. Arabic text extracted from some PDFs may come out reversed.
- Not a substitute for an enterprise DLP, legal review or compliance assessment.

## Legal context

Designed around the principles of Egypt's Personal Data Protection Law No. 151 of 2020 and its Executive Regulations. Official reference: Personal Data Protection Center, <https://pdpc.gov.eg/>.
