import os
import pandas as pd
import numpy as np
from feature_extractor import extract_features

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INPUT_PATH = os.path.join(BASE_DIR, "datasets", "baseline_training_candidate.csv")
OUTPUT_PATH = os.path.join(BASE_DIR, "features", "features_candidate.csv")

FEATURE_NAMES = [
    "length", "path_length", "query_length", "subdomain_count",
    "num_subdirectories", "uses_ip", "has_https", "special_char_count",
    "shannon_entropy", "num_digits", "digit_ratio", "num_hyphens",
    "has_at_symbol", "has_double_slash_redirect", "is_shortened",
    "has_suspicious_keywords",
]
META_COLUMNS = [
    "url", "label", "registrable_domain", "url_shape", "source_file",
    "source_category", "label_provenance", "selection_seed",
    "max_urls_per_domain",
]


def main():
    print("=" * 65)
    print("CYBERGUARDIAN DESK - CANDIDATE FEATURE GENERATION")
    print("=" * 65)
    df = pd.read_csv(INPUT_PATH)
    missing = set(["url", "label", "registrable_domain"]) - set(df.columns)
    if missing:
        raise ValueError(f"Missing required columns: {sorted(missing)}")
    df = df.dropna(subset=["url", "label", "registrable_domain"]).copy()
    df["url"] = df["url"].astype(str).str.strip()
    df["label"] = pd.to_numeric(df["label"], errors="raise").astype(int)
    if not set(df["label"].unique()).issubset({0, 1}):
        raise ValueError("Labels must be 0 (safe) or 1 (malicious).")
    if df["url"].duplicated().any():
        raise ValueError("Candidate dataset contains duplicate URLs.")

    rows = []
    for idx, row in enumerate(df.to_dict(orient="records"), start=1):
        features = extract_features(row["url"])
        if not isinstance(features, dict):
            raise TypeError(
                "extract_features(url) must return a dictionary keyed by the 16 feature names."
            )
        missing_features = set(FEATURE_NAMES) - set(features)
        if missing_features:
            raise ValueError(f"Missing extracted features: {sorted(missing_features)}")
        out = {col: row[col] for col in META_COLUMNS if col in row}
        out.update({name: features[name] for name in FEATURE_NAMES})
        rows.append(out)
        if idx % 50 == 0 or idx == len(df):
            print(f"Processed {idx}/{len(df)} URLs")

    result = pd.DataFrame(rows)
    result[FEATURE_NAMES] = result[FEATURE_NAMES].apply(pd.to_numeric, errors="raise")
    if result[FEATURE_NAMES].isna().any().any():
        raise ValueError("Missing values found in extracted features.")
    if not np.isfinite(result[FEATURE_NAMES].to_numpy(dtype=float)).all():
        raise ValueError("Non-finite values found in extracted features.")

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    result.to_csv(OUTPUT_PATH, index=False)
    print("\nFeature generation completed.")
    print(f"Output: {OUTPUT_PATH}")
    print(f"Rows: {len(result)}; feature columns: {len(FEATURE_NAMES)}")
    print("Class counts:")
    print(result["label"].value_counts().sort_index().rename(index={0: "Safe", 1: "Malicious"}))
    print("Metadata retained: URL, domain, structure, source and label-provenance notes.")


if __name__ == "__main__":
    main()
