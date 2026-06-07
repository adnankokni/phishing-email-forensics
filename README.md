# phishing-email-forensics

A SOC analyst toolkit for investigating phishing emails — parses headers,
extracts IOCs (IPs, URLs, emails, domains), and generates forensics reports.

---

## Project Structure

    phishing-email-forensics/
    ├── samples/        # Raw .eml phishing samples
    ├── scripts/        # Python analysis scripts
    ├── iocs/           # Extracted IOC CSV reports
    ├── reports/        # Forensics report outputs
    └── README.md

## Scripts

| Script | Description |
|---|---|
| `scripts/parse_email.py` | Parses email headers and body from .eml files |
| `scripts/extract_iocs.py` | Extracts IPs, URLs, emails, and suspicious domains |
| `scripts/detect_spoofing.py` | Detects spoofing indicators and gives risk verdict |
| `scripts/generate_report.py` | Auto-generates a full forensics report |

## Usage

**Parse an email:**

    python scripts/parse_email.py samples/phishing_sample_01.eml

**Extract IOCs:**

    python scripts/extract_iocs.py samples/phishing_sample_01.eml

**Detect spoofing:**

    python scripts/detect_spoofing.py samples/phishing_sample_01.eml

**Generate full report:**

    python scripts/generate_report.py samples/phishing_sample_01.eml

IOCs are saved to `iocs/ioc_report.csv` automatically.

## Requirements

- Python 3.10+
- No external dependencies — standard library only

## Status

- [x] Email header parsing
- [x] IOC extraction (IPs, URLs, emails, domains)
- [x] Header spoofing detection
- [x] Automated report generation
