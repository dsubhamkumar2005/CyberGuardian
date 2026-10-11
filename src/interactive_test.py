import os
import sys
from classifier import classify

SAMPLE_URLS = [
    # Safe / Legitimate URLs
    "https://google.com",
    "https://en.wikipedia.org/wiki/Cybersecurity",
    "https://github.com/torvalds/linux",

    # Phishing / Deceptive URLs
    "http://192.168.1.50/login/paypal/update",
    "https://login.example.com/account/update",
    "https://g5.lu/vu39k",
    "http://paypal-security-alert.com//verify-account?token=89234823",
    "http://bankofamerica.com@evil-phishing.ru/auth/login.php",
    "http://secure.login.bank.com.phishingsite.org/auth?session=9238928392",
    "http://www.deskthipk.com/"
]


def run_benchmark():
    print("=" * 75)
    print("   LATEST 16-PARAMETER MALICIOUS URL CLASSIFIER - LIVE TEST BENCHMARK")
    print("=" * 75)

    for i, url in enumerate(SAMPLE_URLS, 1):
        result = classify(url)
        verdict = result["verdict"]
        conf = result["confidence"] * 100

        badge = "[ SAFE ]     " if verdict == "Safe" else "[ MALICIOUS ]"
        print(f"\n{i:2d}. {badge} -> {url}")
        print(f"    Verdict    : {verdict}")
        print(f"    Confidence : {conf:.2f}%")
        print("    Key Reasons:")
        for reason in result["reasons"]:
            print(f"      * {reason}")

    print("\n" + "=" * 75)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        custom_url = sys.argv[1]
        res = classify(custom_url)
        print(f"\nURL        : {custom_url}")
        print(f"Verdict    : {res['verdict']}")
        print(f"Confidence : {res['confidence'] * 100:.2f}%")
        print("Reasons    :")
        for r in res["reasons"]:
            print(f"  - {r}")
        print("\nExtracted 16 Features:")
        for k, v in res["features"].items():
            print(f"  {k:26}: {v}")
    else:
        run_benchmark()

