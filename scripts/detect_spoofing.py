#!/usr/bin/env python3
import email
import sys

def detect_spoofing(filepath):
    with open(filepath, "r", encoding="utf-8-sig") as f:
        msg = email.message_from_file(f)

    print("=" * 50)
    print("SPOOFING DETECTION REPORT")
    print("=" * 50)

    from_header = msg.get("From", "")
    reply_to = msg.get("Reply-To", "")
    return_path = msg.get("Return-Path", "")

    print(f"\n[+] From:        {from_header}")
    print(f"[+] Reply-To:    {reply_to}")
    print(f"[+] Return-Path: {return_path}")

    alerts = []

    # Check 1: Reply-To mismatch
    if reply_to and reply_to != from_header:
        alerts.append(f"⚠️  Reply-To mismatch: replies go to {reply_to} not {from_header}")

    # Check 2: Return-Path mismatch
    if return_path and return_path != from_header:
        alerts.append(f"⚠️  Return-Path mismatch: bounces go to {return_path}")

    # Check 3: Display name vs actual email domain
    if "<" in from_header:
        display = from_header.split("<")[0].strip().strip('"')
        actual = from_header.split("<")[1].strip(">")
        actual_domain = actual.split("@")[-1] if "@" in actual else ""
        if display and actual_domain and actual_domain.lower() not in display.lower():
            alerts.append(f"⚠️  Display name '{display}' does not match sending domain '{actual_domain}'")

    # Check 4: Suspicious keywords in subject
    subject = msg.get("Subject", "")
    keywords = ["urgent", "verify", "account", "suspended", "click", "confirm", "password"]
    found = [w for w in keywords if w.lower() in subject.lower()]
    if found:
        alerts.append(f"⚠️  Suspicious subject keywords: {', '.join(found)}")

    # Check 5: Received hops
    received = msg.get_all("Received") or []
    print(f"\n[+] Mail hops (Received headers): {len(received)}")
    if len(received) > 5:
        alerts.append(f"⚠️  Unusually high number of mail hops: {len(received)}")

    # Results
    print("\n--- Alerts ---")
    if alerts:
        for a in alerts:
            print(a)
    else:
        print("✅ No spoofing indicators detected")

    print("\n--- Verdict ---")
    if len(alerts) >= 2:
        print("🔴 HIGH RISK — multiple spoofing indicators found")
    elif len(alerts) == 1:
        print("🟡 MEDIUM RISK — one spoofing indicator found")
    else:
        print("🟢 LOW RISK — no spoofing indicators found")

    print("=" * 50)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scripts/detect_spoofing.py <path_to_eml>")
        sys.exit(1)
    detect_spoofing(sys.argv[1])
