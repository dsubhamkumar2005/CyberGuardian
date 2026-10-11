
import os
import sys
import pandas as pd
from feature_extractor import extract_features


# --------------------------------------------------
# PATHS
# --------------------------------------------------

BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

DATASET_PATH = os.path.join(
    BASE_DIR, "datasets", "baseline_training_rebuilt.csv"
)

OUTPUT_PATH = os.path.join(
    BASE_DIR, "features", "features_rebuilt.csv"
)


# --------------------------------------------------
# EXPECTED 16 FEATURES
# --------------------------------------------------

FEATURE_COLUMNS = [
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
]


# --------------------------------------------------
# GENERATE FEATURE DATASET
# --------------------------------------------------

def generate_dataset_features():

    print("=" * 60)
    print("GENERATING FEATURES FOR CYBERGUARDIAN DESK")
    print("=" * 60)

    # Check whether the input dataset exists.
    if not os.path.exists(DATASET_PATH):
        print(f"ERROR: Dataset not found:\n{DATASET_PATH}")
        sys.exit(1)

    print(f"\nReading dataset: {DATASET_PATH}")

    df_raw = pd.read_csv(DATASET_PATH)

    print(f"Total raw rows loaded: {len(df_raw)}")

    # Check required columns.
    required_columns = {"url", "label"}

    if not required_columns.issubset(df_raw.columns):
        raise ValueError(
            "Dataset must contain 'url' and 'label' columns. "
            f"Found: {list(df_raw.columns)}"
        )

    # Remove missing URLs or labels.
    df_raw = df_raw.dropna(subset=["url", "label"]).copy()

    # Validate labels before converting to integers.
    labels = pd.to_numeric(df_raw["label"], errors="coerce")

    if labels.isna().any():
        raise ValueError("Some labels are not valid numbers.")

    if not labels.isin([0, 1]).all():
        raise ValueError("Labels must be 0 (Safe) or 1 (Malicious).")

    if not (labels % 1 == 0).all():
        raise ValueError("Labels must be integers.")

    df_raw["label"] = labels.astype(int)

    # Normalize URL strings and remove empty URLs.
    df_raw["url"] = df_raw["url"].astype(str).str.strip()

    df_raw = df_raw[df_raw["url"] != ""].copy()

    if df_raw.empty:
        raise ValueError("No valid URL rows found in the dataset.")

    # Keep only one occurrence of each URL.
    # If the same URL has contradictory labels, stop instead of guessing.
    df_raw["url_key"] = df_raw["url"].str.lower()

    label_counts = df_raw.groupby("url_key")["label"].nunique()
    conflicting_urls = label_counts[label_counts > 1].index

    if len(conflicting_urls) > 0:
        raise ValueError(
            f"Found {len(conflicting_urls)} URLs with conflicting labels. "
            "Resolve these labels in the source dataset first."
        )

    df_raw = df_raw.drop_duplicates(subset="url_key")
    df_raw = df_raw.drop(columns=["url_key"]).reset_index(drop=True)

    if df_raw["label"].nunique() != 2:
        raise ValueError(
            "Both classes are required: 0 = Safe, 1 = Malicious."
        )

    print(f"Valid unique URLs: {len(df_raw)}")
    print("\nInput class distribution:")
    print(
        df_raw["label"]
        .value_counts()
        .sort_index()
        .rename(index={0: "Safe", 1: "Malicious"})
    )

    # Extract features for each URL.
    rows = []
    errors = []

    total = len(df_raw)

    print(f"\nExtracting 16 features for {total} URLs...")

    for idx, row in df_raw.iterrows():

        url = row["url"]
        label = int(row["label"])

        try:
            feats = extract_features(url)

            if not isinstance(feats, dict):
                raise ValueError(
                    "extract_features() must return a dictionary."
                )

            # Ensure the extractor returns all expected features.
            missing = set(FEATURE_COLUMNS) - set(feats.keys())
            extra = set(feats.keys()) - set(FEATURE_COLUMNS)

            if missing or extra:
                raise ValueError(
                    f"Missing features: {sorted(missing)}; "
                    f"unexpected features: {sorted(extra)}"
                )

            # Convert feature values to numeric values.
            feature_row = {}

            for column in FEATURE_COLUMNS:
                value = pd.to_numeric(
                    feats[column], errors="coerce"
                )

                if pd.isna(value):
                    raise ValueError(
                        f"Feature '{column}' is not numeric."
                    )

                feature_row[column] = value

            feature_row["label"] = label

            rows.append(feature_row)

        except Exception as exc:
            errors.append((idx, url, str(exc)))

        if (idx + 1) % 100 == 0 or idx + 1 == total:
            print(f"Processed {idx + 1}/{total} URLs...")

    # Stop if any URL could not be processed.
    # We don't silently create an incomplete dataset.
    if errors:
        print(f"\nERROR: {len(errors)} URLs failed feature extraction.")

        for idx, url, reason in errors[:10]:
            print(f"Row {idx}: {url} -> {reason}")

        raise RuntimeError(
            "Feature generation stopped. Fix the extraction errors "
            "before generating the final dataset."
        )

    df_features = pd.DataFrame(rows)

    # Explicitly preserve the expected feature order.
    df_features = df_features[FEATURE_COLUMNS + ["label"]]

    # Check the final output.
    if len(df_features.columns) != 17:
        raise ValueError(
            f"Expected 17 columns (16 features + label), "
            f"got {len(df_features.columns)}."
        )

    if df_features.isna().any().any():
        raise ValueError("Missing values found in the generated features.")

    # Save separately so the old features.csv remains untouched.
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)

    df_features.to_csv(OUTPUT_PATH, index=False)

    print("\n" + "=" * 60)
    print("FEATURE GENERATION COMPLETED SUCCESSFULLY")
    print("=" * 60)

    print(f"\nOutput file: {OUTPUT_PATH}")
    print(f"Total rows: {len(df_features)}")
    print(f"Total columns: {len(df_features.columns)}")
    print(f"Feature count: {len(FEATURE_COLUMNS)}")

    print("\nClass distribution:")
    print(
        df_features["label"]
        .value_counts()
        .sort_index()
        .rename(index={0: "Safe", 1: "Malicious"})
    )

    print("\nFeature columns:")
    for number, column in enumerate(FEATURE_COLUMNS, start=1):
        print(f"{number:2}. {column}")

    print("\nSample rows:")
    print(df_features.head())

    print("=" * 60)


if __name__ == "__main__":
    generate_dataset_features()
