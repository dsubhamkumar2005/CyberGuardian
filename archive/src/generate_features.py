
import os
import pandas as pd

from feature_extractor import extract_features

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DATASET_PATH = os.path.join(
    BASE_DIR, "datasets", "baseline_training_rebuilt.csv"
)

OUTPUT_PATH = os.path.join(
    BASE_DIR, "features", "features_domain.csv"
)

FEATURE_NAMES = [
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


def main():
    print("=" * 60)
    print("CYBERGUARDIAN DESK - DOMAIN EVALUATION FEATURES")
    print("=" * 60)

    df = pd.read_csv(DATASET_PATH)

    required_columns = {"url", "label"}
    if not required_columns.issubset(df.columns):
        raise ValueError(
            "Dataset must contain 'url' and 'label' columns."
        )

    df = df.dropna(subset=["url", "label"]).copy()
    df["url"] = df["url"].astype(str).str.strip()
    df = df[df["url"] != ""]
    df["label"] = pd.to_numeric(df["label"], errors="raise").astype(int)

    if not set(df["label"].unique()).issubset({0, 1}):
        raise ValueError("Labels must be 0 (safe) or 1 (malicious).")

    if df["url"].duplicated().any():
        print("Warning: duplicate URLs found; keeping the first occurrence.")
        df = df.drop_duplicates(subset=["url"], keep="first")

    rows = []

    for index, row in enumerate(df.itertuples(index=False), start=1):
        url = row.url
        label = row.label

        features = extract_features(url)

        # Support a dictionary returned by the feature extractor.
        if not isinstance(features, dict):
            raise TypeError(
                "extract_features(url) must return a dictionary "
                "with the 16 named features."
            )

        missing = set(FEATURE_NAMES) - set(features.keys())
        if missing:
            raise ValueError(f"Missing extracted features: {sorted(missing)}")

        output_row = {"url": url}

        for name in FEATURE_NAMES:
            output_row[name] = features[name]

        output_row["label"] = label
        rows.append(output_row)

        if index % 100 == 0 or index == len(df):
            print(f"Processed {index}/{len(df)} URLs")

    result = pd.DataFrame(rows)

    numeric_columns = FEATURE_NAMES + ["label"]
    result[numeric_columns] = result[numeric_columns].apply(
        pd.to_numeric, errors="raise"
    )

    if result[numeric_columns].isnull().any().any():
        raise ValueError("Missing values found in generated features.")

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    result.to_csv(OUTPUT_PATH, index=False)

    print("\nFeature generation completed.")
    print(f"Output: {OUTPUT_PATH}")
    print(f"Rows: {len(result)}")
    print(f"Columns: {len(result.columns)} (URL + 16 features + label)")
    print("\nClass distribution:")
    print(result["label"].value_counts().sort_index())


if __name__ == "__main__":
    main()
