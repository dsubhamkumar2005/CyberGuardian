"""
CLI and programmatic wrapper for the URL Classifier.
Forwards calls directly to classifier.py.
"""
import sys
from classifier import classify, is_trusted_domain, main_cli

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
        print("\nExtracted Features:")
        for k, v in res["features"].items():
            print(f"  {k:26}: {v}")
    else:
        main_cli()