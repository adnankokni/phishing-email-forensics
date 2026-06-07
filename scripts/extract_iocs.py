#!/usr/bin/env python3
import re
import sys
import csv
from datetime import datetime

IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
URL_PATTERN = re.compile(r'https?://[^\s<>"\'()]+')
EMAIL_PATTERN = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')
DOMAIN_PATTERN = re.compile(r'\b(?:[a-z0-9\-]+\.)+(?:ru|cn|tk|xyz|top|click|info|online)\b', re.I)

def extract_iocs(filepath):
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    iocs = []
    timestamp = datetime.utcnow().isoformat() + "Z"
    source = filepath.split('/')[-1].split('\\')[-1]
    for ip in set(IP_PATTERN.findall(content)):
        iocs.append([timestamp, source, "IP", ip, ""])
    for url in set(URL_PATTERN.findall(content)):
        iocs.append([timestamp, source, "URL", url, ""])
    for addr in set(EMAIL_PATTERN.findall(content)):
        iocs.append([timestamp, source, "EMAIL", addr, ""])
    for dom in set(DOMAIN_PATTERN.findall(content)):
        iocs.append([timestamp, source, "DOMAIN", dom, ""])
    return iocs

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scripts/extract_iocs.py <path_to_eml>")
        sys.exit(1)
    iocs = extract_iocs(sys.argv[1])
    out = "iocs/ioc_report.csv"
    write_header = True
    try:
        with open(out, 'r') as f:
            write_header = f.readline() == ''
    except FileNotFoundError:
        pass
    with open(out, 'a', newline='') as f:
        writer = csv.writer(f)
        if write_header:
            writer.writerow(["timestamp", "source_file", "type", "value", "notes"])
        writer.writerows(iocs)
    print(f"\n✅ Extracted {len(iocs)} IOCs → saved to {out}")
    for ioc in iocs:
        print(f"  [{ioc[2]}] {ioc[3]}")
