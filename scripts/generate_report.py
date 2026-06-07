#!/usr/bin/env python3
import email
import re
import sys
from datetime import datetime, timezone

IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
URL_PATTERN = re.compile(r'https?://[^\s<>"\'()]+')
EMAIL_PATTERN = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')
KEYWORDS = ["urgent", "verify", "account", "suspended", "click", "confirm", "password"]

def generate_report(filepath):
    with open(filepath, "r", encoding="utf-8-sig") as f:
        msg = email.message_from_file(f)

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    source = filepath.split("/")[-1].split("\\")[-1]

    # Extract headers
    from_h = msg.get("From", "N/A")
    to_h = msg.get("To", "N/A")
    subject = msg.get("Subject", "N/A")
    date = msg.get("Date", "N/A")
    reply_to = msg.get("Reply-To", "None")
    return_path = msg.get("Return-Path", "None")

    # Extract body
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                body = part.get_payload(decode=True).decode()
    else:
        body = msg.get_payload()

    # Extract IOCs
    urls = sorted(set(URL_PATTERN.findall(content)))
    ips = sorted(set(IP_PATTERN.findall(content)))
    emails = sorted(set(EMAIL_PATTERN.findall(content)))

    # Spoofing checks
    alerts = []
    if reply_to and reply_to != "None" and reply_to != from_h:
        alerts.append(f"Reply-To mismatch: {reply_to}")
    if return_path and return_path != "None" and return_path != from_h:
        alerts.append(f"Return-Path mismatch: {return_path}")
    found_kw = [w for w in KEYWORDS if w.lower() in subject.lower()]
    if found_kw:
        alerts.append(f"Suspicious subject keywords: {', '.join(found_kw)}")

    # Verdict
    if len(alerts) >= 2:
        verdict = "HIGH RISK"
    elif len(alerts) == 1:
        verdict = "MEDIUM RISK"
    else:
        verdict = "LOW RISK"

    # Build report
    report = f"""
================================================
       PHISHING EMAIL FORENSICS REPORT
================================================
Generated : {timestamp}
Analyst   : SOC Analyst
Source    : {source}

------------------------------------------------
SECTION 1 — EMAIL HEADERS
------------------------------------------------
From        : {from_h}
To          : {to_h}
Subject     : {subject}
Date        : {date}
Reply-To    : {reply_to}
Return-Path : {return_path}

------------------------------------------------
SECTION 2 — EMAIL BODY (PREVIEW)
------------------------------------------------
{body.strip()[:500]}

------------------------------------------------
SECTION 3 — EXTRACTED IOCs
------------------------------------------------
URLs found    : {len(urls)}
{chr(10).join(f"  - {u}" for u in urls) or "  None"}

IPs found     : {len(ips)}
{chr(10).join(f"  - {i}" for i in ips) or "  None"}

Emails found  : {len(emails)}
{chr(10).join(f"  - {e}" for e in emails) or "  None"}

------------------------------------------------
SECTION 4 — SPOOFING INDICATORS
------------------------------------------------
{chr(10).join(f"  ⚠️  {a}" for a in alerts) or "  None detected"}

------------------------------------------------
SECTION 5 — VERDICT
------------------------------------------------
  {verdict}

================================================
END OF REPORT
================================================
"""

    out = f"reports/report_{source.replace('.eml','')}.txt"
    with open(out, "w", encoding="utf-8") as f:
        f.write(report)

    print(report)
    print(f"✅ Report saved to {out}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scripts/generate_report.py <path_to_eml>")
        sys.exit(1)
    generate_report(sys.argv[1])
