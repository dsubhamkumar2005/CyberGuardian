import sys
from classifier import classify

SAMPLE_URLS = [
    # 1. Clean Benign Core URLs (No hardcoded whitelist override; pure ML prediction)
    "https://google.com",
    "https://docs.python.org/3/library/math.html",
    "https://react.dev/learn",
    "https://github.com/torvalds/linux",
    "https://subdomain.university.edu/courses/cs101/syllabus",
    "http://info.cern.ch/hypertext/WWW/TheProject.html",
    "https://hub.docker.com/_/python",

    # 2. Benign Executable Downloads (Should NOT be falsely blocked merely for .exe)
    "https://www.python.org/ftp/python/3.12.0/python-3.12.0-amd64.exe",

    # 3. Valid IPv6 Hostname (Properly parsed by is_ip_address)
    "http://[2001:db8::1]:8080/login/update",

    # 4. Deceptive / Attack URLs
    "http://192.168.1.50:8080/login/paypal/update",
    "https://login.example.com/account/update",
    "https://g5.lu/vu39k",
    "http://paypal-security-alert.com//verify-account?token=89234823",
    "http://bankofamerica.com@evil-phishing.ru/auth/login.php",
    "https://dl.zerotheme.ir/kokorila/cgl-bin/bin.exe",

    # 5. Malformed / Non-Web Scheme (Safely rejected by validate_url)
    "javascript:alert(1)",
]


def run_benchmark():
    print("=" * 80)
    print("   CYBERGUARDIAN 23-PARAMETER URL CLASSIFIER - PURE ML BENCHMARK")
    print("=" * 80)

    for i, url in enumerate(SAMPLE_URLS, 1):
        result = classify(url)
        verdict = result["verdict"]
        conf = result["confidence"] * 100
        p_mal = result["prob_malicious"]

        badge = f"[{verdict.upper():^11}]"
        print(f"\n{i:2d}. {badge} -> {url}")
        print(f"    Confidence : {conf:.2f}% (P(Malicious)={p_mal:.2f})")
        print(f"    Reputation : {result.get('domain_reputation', 'None')}")
        print("    Key Reasons:")
        for reason in result["reasons"]:
            print(f"      * {reason}")

    print("\n" + "=" * 80)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        custom_url = sys.argv[1]
        res = classify(custom_url)
        print(f"\nURL        : {custom_url}")
        print(f"Verdict    : {res['verdict']}")
        print(f"Confidence : {res['confidence'] * 100:.2f}% (P(Malicious)={res['prob_malicious']:.2f})")
        print(f"Reputation : {res.get('domain_reputation', 'None')}")
        print("Reasons    :")
        for r in res["reasons"]:
            print(f"  - {r}")
        if res.get("features"):
            print("\nExtracted 23 Features:")
            for k, v in res["features"].items():
                print(f"  {k:26}: {v}")
    else:
        run_benchmark()
