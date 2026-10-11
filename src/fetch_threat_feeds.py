"""
CyberGuardian Desk - Threat Feed Ingestion Engine

Fetches live, verified malicious URLs from leading open-source threat intelligence feeds:
1. URLhaus (abuse.ch) - Active malware distribution sites
2. OpenPhish - Active zero-day phishing URLs
Saves deduplicated threat intelligence feed to datasets/raw_threat_feeds_malicious.csv
"""

import os
import csv
import ssl
import urllib.request
import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASETS_DIR = os.path.join(BASE_DIR, "datasets")
OUTPUT_PATH = os.path.join(DATASETS_DIR, "raw_threat_feeds_malicious.csv")

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE


def fetch_urlhaus() -> list[str]:
    urls = []
    feed_url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
    print(f"Connecting to URLhaus ({feed_url})...")
    try:
        req = urllib.request.Request(feed_url, headers={"User-Agent": "CyberGuardian-ThreatIntel/1.0"})
        with urllib.request.urlopen(req, context=ctx, timeout=20) as resp:
            content = resp.read().decode("utf-8", errors="ignore")

        lines = [line for line in content.splitlines() if line and not line.startswith("#")]
        reader = csv.reader(lines)
        for row in reader:
            if len(row) > 2:
                u = row[2].strip().strip('"')
                if u.startswith("http://") or u.startswith("https://"):
                    urls.append(u)
        print(f"URLhaus fetched: {len(urls)} active malware URLs.")
    except Exception as exc:
        print(f"URLhaus fetch warning: {exc}")
    return urls


def fetch_openphish() -> list[str]:
    urls = []
    feed_url = "https://openphish.com/feed.txt"
    print(f"Connecting to OpenPhish ({feed_url})...")
    try:
        req = urllib.request.Request(feed_url, headers={"User-Agent": "CyberGuardian-ThreatIntel/1.0"})
        with urllib.request.urlopen(req, context=ctx, timeout=20) as resp:
            content = resp.read().decode("utf-8", errors="ignore")

        for line in content.splitlines():
            u = line.strip()
            if u.startswith("http://") or u.startswith("https://"):
                urls.append(u)
        print(f"OpenPhish fetched: {len(urls)} active phishing URLs.")
    except Exception as exc:
        print(f"OpenPhish fetch warning: {exc}")
    return urls


def main():
    print("=" * 72)
    print("CYBERGUARDIAN DESK - LIVE THREAT INTELLIGENCE INGESTION")
    print("=" * 72)

    urlhaus_list = fetch_urlhaus()
    openphish_list = fetch_openphish()

    # Existing local malicious URLs
    local_urls = []
    for fname in ["malicious_urls.csv", "baseline_training_v2_candidate.csv"]:
        fpath = os.path.join(DATASETS_DIR, fname)
        if os.path.exists(fpath):
            df = pd.read_csv(fpath)
            if "label" in df.columns:
                local_urls.extend(df[df["label"] == 1]["url"].dropna().tolist())
            elif "url" in df.columns:
                local_urls.extend(df["url"].dropna().tolist())

    combined = list(dict.fromkeys(u.strip() for u in (urlhaus_list + openphish_list + local_urls) if u.strip()))
    print(f"\nTotal combined unique verified malicious URLs: {len(combined)}")

    df_out = pd.DataFrame({"url": combined, "label": 1})
    df_out.to_csv(OUTPUT_PATH, index=False)
    print(f"Saved verified threat pool to: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()

