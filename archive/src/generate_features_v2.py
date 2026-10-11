import os
import numpy as np
import pandas as pd

from feature_extractor import extract_features

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INPUT_PATH = os.path.join(BASE_DIR, "datasets", "baseline_training_v2_candidate.csv")
OUTPUT_PATH = os.path.join(BASE_DIR, "features", "features_v2_candidate.csv")

FEATURE_NAMES = [
    "length", "path_length", "query_length", "subdomain_count",
    "num_subdirectories", "uses_ip", "has_https", "special_char_count",
    "shannon_entropy", "num_digits", "digit_ratio", "num_hyphens",
    "has_at_symbol", "has_double_slash_redirect", "is_shortened",
    "has_suspicious_keywords",
]

META_COLUMNS = [
    "url", "label", "registrable_domain", "url_shape", "protocol",
    "https_group", "source_file", "source_category", "label_provenance",
    "ClassLabel_original", "normalized_url", "selection_seed",
    "max_urls_per_domain_per_class",
]


def main():
    print("=" * 68)
    print("CYBERGUARDIAN DESK - V2 CANDIDATE FEATURE GENERATION")
    print("=" * 68)

    if not os.path.exists(INPUT_PATH):
        raise FileNotFoundError(
            f"Dataset not found: {INPUT_PATH}\n"
            "Copy baseline_training_v2_candidate.csv into datasets/ first."
        )

    df = pd.read_csv(INPUT_PATH)
    required = {"url", "label", "registrable_domain", *FEATURE_NAMES}
    missing = ({"url", "label", "registrable_domain"} - set(df.columns))
    if missing:
        raise ValueError(f"Dataset is missing required columns: {sorted(missing)}")

    df = df.dropna(subset=["url", "label", "registrable_domain"]).copy()
    df["url"] = df["url"].astype(str).str.strip()
    df["registrable_domain"] = df["registrable_domain"].astype(str).str.lower().str.strip()
    df["label"] = pd.to_numeric(df["label"], errors="raise").astype(int)

    if not set(df["label"].unique()).issubset({0, 1}):
        raise ValueError("CyberGuardian labels must be 0 (safe) or 1 (malicious).")

    if df["url"].duplicated().any():
        raise ValueError("Duplicate URLs found in the v2 candidate dataset.")

    rows = []
    for index, row in enumerate(df.to_dict(orient="records"), start=1):
        features = extract_features(row["url"])

        if not isinstance(features, dict):
            raise TypeError(
                "extract_features(url) must return a dictionary keyed by the 16 feature names."
            )

        missing_features = set(FEATURE_NAMES) - set(features.keys())
        if missing_features:
            raise ValueError(
                f"Feature extractor is missing: {sorted(missing_features)}"
            )

        out = {key: row[key] for key in META_COLUMNS if key in row}
        out.update({name: features[name] for name in FEATURE_NAMES})
        rows.append(out)

        if index % 50 == 0 or index == len(df):
            print(f"Processed {index}/{len(df)} URLs")

    result = pd.DataFrame(rows)
    result[FEATURE_NAMES] = result[FEATURE_NAMES].apply(pd.to_numeric, errors="raise")

    if result[FEATURE_NAMES].isna().any().any():
        raise ValueError("Missing values found in generated numeric features.")

    if not np.isfinite(result[FEATURE_NAMES].to_numpy(dtype=float)).all():
        raise ValueError("Non-finite values found in generated numeric features.")

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    result.to_csv(OUTPUT_PATH, index=False)

    print("\nFeature generation completed.")
    print(f"Output: {OUTPUT_PATH}")
    print(f"Rows: {len(result)}")
    print(f"Feature columns: {len(FEATURE_NAMES)}")
    print(f"Metadata columns retained: {len(result.columns) - len(FEATURE_NAMES)}")
    print("\nClass counts:")
    print(result["label"].value_counts().sort_index().rename(
        index={0: "Safe", 1: "Malicious"}
    ))
    print("\nSource composition:")
    if "source_category" in result:
        print(pd.crosstab(result["source_category"], result["label"]).rename(
            columns={0: "Safe", 1: "Malicious"}
        ).to_string())


if __name__ == "__main__":
    main()
