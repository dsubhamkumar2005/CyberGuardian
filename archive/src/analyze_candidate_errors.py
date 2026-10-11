
import os
import pandas as pd

BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)
RESULTS_DIR = os.path.join(BASE_DIR, "results")
FEATURES_PATH = os.path.join(
    BASE_DIR, "features", "features_candidate.csv"
)

PREDICTIONS_PATH = os.path.join(
    RESULTS_DIR, "domain_cv_candidate_oof_predictions.csv"
)
IMPORTANCE_PATH = os.path.join(
    RESULTS_DIR, "random_forest_candidate_cv_importance.csv"
)
OUTPUT_PATH = os.path.join(
    RESULTS_DIR, "random_forest_candidate_errors.csv"
)


def main():
    print("=" * 65)
    print("CYBERGUARDIAN DESK - RANDOM FOREST ERROR ANALYSIS")
    print("=" * 65)

    predictions = pd.read_csv(PREDICTIONS_PATH)
    features = pd.read_csv(FEATURES_PATH)

    rf = predictions[
        predictions["model"] == "Random Forest"
    ].copy()

    # Keep source and structure metadata when available.
    metadata_cols = ["url"]
    for column in features.columns:
        name = column.lower()

        if column == "url":
            continue

        if (
            column in {"structure", "domain"}
            or "source" in name
            or "provenance" in name
            or "note" in name
        ):
            metadata_cols.append(column)

    metadata = features[metadata_cols].drop_duplicates(
        subset=["url"]
    )

    # Avoid duplicate domain columns during the merge.
    if "domain" in metadata.columns:
        metadata = metadata.drop(columns=["domain"])

    merged = rf.merge(
        metadata,
        on="url",
        how="left",
        validate="one_to_one",
    )

    false_negatives = merged[
        (merged["label"] == 1)
        & (merged["prediction"] == 0)
    ].copy()

    false_positives = merged[
        (merged["label"] == 0)
        & (merged["prediction"] == 1)
    ].copy()

    print(f"\nTotal held-out predictions: {len(merged)}")
    print(f"False negatives: {len(false_negatives)}")
    print(f"False positives: {len(false_positives)}")

    display_columns = [
        column for column in [
            "url",
            "domain",
            "structure",
            "source",
            "label_provenance",
            "label",
            "prediction",
            "fold",
        ]
        if column in merged.columns
    ]

    print("\n--- FALSE NEGATIVES: malicious predicted safe ---")
    if false_negatives.empty:
        print("None")
    else:
        print(
            false_negatives[display_columns]
            .to_string(index=False)
        )

    print("\n--- FALSE POSITIVES: safe predicted malicious ---")
    if false_positives.empty:
        print("None")
    else:
        print(
            false_positives[display_columns]
            .to_string(index=False)
        )

    errors = merged[
        merged["label"] != merged["prediction"]
    ].copy()

    errors.to_csv(OUTPUT_PATH, index=False)
    print(f"\nError details saved to: {OUTPUT_PATH}")

    if os.path.exists(IMPORTANCE_PATH):
        importance = pd.read_csv(IMPORTANCE_PATH)

        importance = importance.sort_values(
            "importance_mean",
            ascending=False,
        )

        print("\n--- TOP 10 RANDOM FOREST FEATURES ---")
        print(importance.head(10).to_string(index=False))
    else:
        print("\nFeature-importance file not found.")


if __name__ == "__main__":
    main()
