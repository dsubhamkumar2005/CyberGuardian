import os
import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS_DIR = os.path.join(BASE_DIR, "results")
FEATURES_PATH = os.path.join(BASE_DIR, "features", "features_v2_candidate.csv")
PREDICTIONS_PATH = os.path.join(RESULTS_DIR, "domain_cv_v2_oof_predictions.csv")
IMPORTANCE_PATH = os.path.join(RESULTS_DIR, "random_forest_v2_cv_importance.csv")
OUTPUT_PATH = os.path.join(RESULTS_DIR, "random_forest_v2_errors.csv")


def main():
    predictions = pd.read_csv(PREDICTIONS_PATH)
    features = pd.read_csv(FEATURES_PATH)

    rf = predictions[predictions["model"] == "Random Forest"].copy()
    metadata_cols = [
        c for c in [
            "url", "registrable_domain", "url_shape", "https_group",
            "source_file", "source_category", "label_provenance",
            "ClassLabel_original",
        ] if c in features.columns
    ]
    meta = features[metadata_cols].drop_duplicates(subset=["url"])
    merged = rf.merge(meta, on="url", how="left", validate="one_to_one")

    fn = merged[(merged["label"] == 1) & (merged["prediction"] == 0)]
    fp = merged[(merged["label"] == 0) & (merged["prediction"] == 1)]

    print("=" * 68)
    print("CYBERGUARDIAN DESK - V2 RANDOM FOREST ERROR ANALYSIS")
    print("=" * 68)
    print(f"Out-of-fold URL predictions: {len(merged)}")
    print(f"False negatives (malicious predicted safe): {len(fn)}")
    print(f"False positives (safe predicted malicious): {len(fp)}")

    show_cols = [
        c for c in [
            "url", "registrable_domain", "url_shape", "https_group",
            "source_category", "label_provenance", "label", "prediction", "fold"
        ] if c in merged.columns
    ]
    print("\n--- FALSE NEGATIVES ---")
    print(fn[show_cols].to_string(index=False) if len(fn) else "None")
    print("\n--- FALSE POSITIVES ---")
    print(fp[show_cols].to_string(index=False) if len(fp) else "None")

    merged[merged["label"] != merged["prediction"]].to_csv(OUTPUT_PATH, index=False)
    print(f"\nError rows saved to: {OUTPUT_PATH}")

    if os.path.exists(IMPORTANCE_PATH):
        imp = pd.read_csv(IMPORTANCE_PATH).sort_values("importance_mean", ascending=False)
        print("\n--- TOP 10 FEATURES ---")
        print(imp.head(10).to_string(index=False))


if __name__ == "__main__":
    main()
