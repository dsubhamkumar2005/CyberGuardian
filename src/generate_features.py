import os
import sys
import pandas as pd
from feature_extractor import extract_features

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_PATH = os.path.join(BASE_DIR, "datasets", "baseline_training.csv")
OUTPUT_PATH = os.path.join(BASE_DIR, "features", "features.csv")


def generate_dataset_features():
    print("=" * 60)
    print("EXTRACTING ENRICHED FEATURES (16 PARAMETERS)")
    print("=" * 60)

    if not os.path.exists(DATASET_PATH):
        print(f"Error: Dataset not found at {DATASET_PATH}")
        sys.exit(1)

    print(f"Reading dataset: {DATASET_PATH}")
    df_raw = pd.read_csv(DATASET_PATH)
    print(f"Total raw URLs loaded: {len(df_raw)}")

    # Clean missing / invalid rows
    df_raw = df_raw.dropna(subset=["url", "label"])
    df_raw["label"] = df_raw["label"].astype(int)

    rows = []
    total = len(df_raw)

    print(f"Extracting features for {total} URLs...")
    for idx, (_, row) in enumerate(df_raw.iterrows(), start=1):
        url = str(row["url"]).strip()
        label = int(row["label"])

        feats = extract_features(url)
        feats["label"] = label
        rows.append(feats)

        if idx % 100 == 0 or idx == total:
            print(f"Processed {idx}/{total} URLs...")

    df_features = pd.DataFrame(rows)

    # Ensure column ordering: 16 features first, then label
    feature_cols = [
        "length",
        "path_length",
        "query_length",
        "subdomain_count",
        "num_subdirectories",
        "uses_ip",
        "has_https",
        "special_char_count",
        "shannon_entropy",
        "num_digits",
        "digit_ratio",
        "num_hyphens",
        "has_at_symbol",
        "has_double_slash_redirect",
        "is_shortened",
        "has_suspicious_keywords",
        "label"
    ]

    df_features = df_features[feature_cols]

    # Save to features.csv
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    df_features.to_csv(OUTPUT_PATH, index=False)
    print(f"\nSaved updated features dataset to: {OUTPUT_PATH}")
    print(f"Total rows: {len(df_features)}, Total columns: {len(df_features.columns)}")
    print("\nClass distribution:")
    print(df_features["label"].value_counts().to_dict())
    print("\nSample rows:")
    print(df_features.head())
    print("=" * 60)
    print("FEATURE GENERATION COMPLETED SUCCESSFULLY")
    print("=" * 60)


if __name__ == "__main__":
    generate_dataset_features()

