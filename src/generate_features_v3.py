"""
Feature Generation Script (v3)

Extracts all 21 security features from datasets/baseline_training_v3.csv
and outputs features/features_v3.csv with complete metadata.
"""

import os
import numpy as np
import pandas as pd
from feature_extractor import extract_features

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INPUT_PATH = os.path.join(BASE_DIR, "datasets", "baseline_training_v3.csv")
OUTPUT_PATH = os.path.join(BASE_DIR, "features", "features_v3.csv")

FEATURE_NAMES = [
    # Core 16
    "length", "path_length", "query_length", "subdomain_count",
    "num_subdirectories", "uses_ip", "has_https", "special_char_count",
    "shannon_entropy", "num_digits", "digit_ratio", "num_hyphens",
    "has_at_symbol", "has_double_slash_redirect", "is_shortened",
    "has_suspicious_keywords",
    # Advanced 6
    "domain_entropy", "path_entropy", "is_high_risk_tld",
    "is_institutional_tld", "brand_impersonation", "non_standard_port",
]

META_COLUMNS = [
    "url", "label", "registrable_domain", "url_shape", "protocol", "source_category"
]


def main():
    print("=" * 68)
    print("CYBERGUARDIAN DESK - V3 FEATURE GENERATION (21 FEATURES)")
    print("=" * 68)

    if not os.path.exists(INPUT_PATH):
        raise FileNotFoundError(f"Input dataset not found at {INPUT_PATH}. Run build_balanced_dataset_v3.py first.")

    df = pd.read_csv(INPUT_PATH)
    print(f"Loaded {len(df)} URLs from {INPUT_PATH}")

    rows = []
    for idx, row in enumerate(df.to_dict(orient="records"), start=1):
        url = row["url"]
        feats = extract_features(url)

        out = {k: row.get(k, "") for k in META_COLUMNS}
        out.update({name: feats[name] for name in FEATURE_NAMES})
        rows.append(out)

        if idx % 200 == 0 or idx == len(df):
            print(f"Processed {idx}/{len(df)} URLs...")

    result = pd.DataFrame(rows)
    result[FEATURE_NAMES] = result[FEATURE_NAMES].apply(pd.to_numeric, errors="raise")

    # Safety checks
    if result[FEATURE_NAMES].isna().any().any():
        raise ValueError("Missing values found in extracted numeric features.")
    if not np.isfinite(result[FEATURE_NAMES].to_numpy(dtype=float)).all():
        raise ValueError("Non-finite values found in extracted features.")

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    result.to_csv(OUTPUT_PATH, index=False)

    print("\nFeature generation completed.")
    print(f"Output: {OUTPUT_PATH}")
    print(f"Rows: {len(result)}; Features: {len(FEATURE_NAMES)}")
    print("\nClass distribution:")
    print(result["label"].value_counts().sort_index().rename(index={0: "Safe", 1: "Malicious"}))


if __name__ == "__main__":
    main()
