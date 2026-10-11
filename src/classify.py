"""
CyberGuardian Desk - URL Classifier CLI Wrapper
Forwards calls directly to classifier.py.
"""
import sys
from classifier import classify, main_cli

if __name__ == "__main__":
    if len(sys.argv) > 1:
        custom_url = sys.argv[1]
        threshold = float(sys.argv[2]) if len(sys.argv) > 2 else 0.50
        res = classify(custom_url, threshold=threshold)
        print(f"\nURL        : {custom_url}")
        print(f"Verdict    : {res['verdict']}")
        print(f"Confidence : {res['confidence'] * 100:.2f}% (P(Malicious)={res['prob_malicious']:.2f}, P(Safe)={res['prob_safe']:.2f})")
        print(f"Threshold  : {res['decision_threshold']}")
        print(f"Reputation : {res['domain_reputation']}")
        print("Indicators :")
        for r in res["reasons"]:
            print(f"  - {r}")
        if res.get("features"):
            print("\nExtracted Features:")
            for k, v in res["features"].items():
                print(f"  {k:26}: {v}")
    else:
        main_cli()