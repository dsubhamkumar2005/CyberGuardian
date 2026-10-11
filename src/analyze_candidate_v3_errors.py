"""
CyberGuardian Desk - V3 Out-Of-Fold Error Analysis
Analyzes false positives and false negatives from domain cross-validation v3.
"""

import os
import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS_DIR = os.path.join(BASE_DIR, "results")
PREDICTIONS_PATH = os.path.join(RESULTS_DIR, "domain_cv_v3_oof_predictions.csv")
IMPORTANCE_PATH = os.path.join(RESULTS_DIR, "random_forest_v3_cv_importance.csv")
OUTPUT_PATH = os.path.join(RESULTS_DIR, "random_forest_v3_errors.csv")


def main():
    print("=" * 70)
    print("CYBERGUARDIAN DESK - V3 RANDOM FOREST ERROR ANALYSIS")
    print("=" * 70)

    if not os.path.exists(PREDICTIONS_PATH):
        raise FileNotFoundError(f"Predictions not found: {PREDICTIONS_PATH}")

    df = pd.read_csv(PREDICTIONS_PATH)
    rf = df[df["model"] == "Random Forest"].copy()

    fn = rf[(rf["label"] == 1) & (rf["prediction"] == 0)]
    fp = rf[(rf["label"] == 0) & (rf["prediction"] == 1)]

    print(f"\nTotal held-out URL predictions: {len(rf)}")
    print(f"False Negatives (malicious predicted safe): {len(fn)} / 664 ({len(fn)/664*100:.2f}%)")
    print(f"False Positives (safe predicted malicious): {len(fp)} / 664 ({len(fp)/664*100:.2f}%)")

    errors = rf[rf["label"] != rf["prediction"]].copy()
    errors.to_csv(OUTPUT_PATH, index=False)
    print(f"Saved all error rows to: {OUTPUT_PATH}")

    print("\n--- SAMPLE FALSE NEGATIVES (Top 5) ---")
    print(fn[["url", "registrable_domain", "fold"]].head(5).to_string(index=False) if len(fn) else "None")

    print("\n--- SAMPLE FALSE POSITIVES (Top 5) ---")
    print(fp[["url", "registrable_domain", "fold"]].head(5).to_string(index=False) if len(fp) else "None")

    if os.path.exists(IMPORTANCE_PATH):
        imp = pd.read_csv(IMPORTANCE_PATH).sort_values("importance_mean", ascending=False)
        print("\n--- TOP 10 FEATURES ---")
        print(imp.head(10).to_string(index=False))


if __name__ == "__main__":
    main()

