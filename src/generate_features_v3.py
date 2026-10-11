"""
CyberGuardian Desk - Feature Generation Script (v3)

Extracts all 23 security features from:
1. datasets/baseline_training_v3.csv -> features/features_v3.csv
2. datasets/independent_validation.csv -> features/features_independent_validation.csv
"""

import os
import numpy as np
import pandas as pd
from feature_extractor import extract_features, FEATURE_COLUMNS_V3

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASETS_DIR = os.path.join(BASE_DIR, "datasets")
FEATURES_DIR = os.path.join(BASE_DIR, "features")

TRAIN_INPUT = os.path.join(DATASETS_DIR, "baseline_training_v3.csv")
TRAIN_OUTPUT = os.path.join(FEATURES_DIR, "features_v3.csv")

INDEP_INPUT = os.path.join(DATASETS_DIR, "independent_validation.csv")
INDEP_OUTPUT = os.path.join(FEATURES_DIR, "features_independent_validation.csv")

FEATURE_NAMES = FEATURE_COLUMNS_V3
META_COLUMNS = ["url", "label", "registrable_domain", "url_shape", "protocol", "source_category", "source", "retrieved_at"]


def generate_for_file(input_path: str, output_path: str, dataset_name: str):
    print("\n" + "=" * 70)
    print(f"GENERATING {len(FEATURE_NAMES)} FEATURES FOR {dataset_name}")
    print("=" * 70)

    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Input dataset not found at {input_path}")

    df = pd.read_csv(input_path)
    print(f"Loaded {len(df)} URLs from {input_path}")

    rows = []
    for idx, row in enumerate(df.to_dict(orient="records"), start=1):
        url = row["url"]
        feats = extract_features(url)

        out = {k: row.get(k, "") for k in META_COLUMNS if k in row}
        out.update({name: feats[name] for name in FEATURE_NAMES})
        rows.append(out)

        if idx % 200 == 0 or idx == len(df):
            print(f"Processed {idx}/{len(df)} URLs...")

    result = pd.DataFrame(rows)
    result[FEATURE_NAMES] = result[FEATURE_NAMES].apply(pd.to_numeric, errors="raise")

    # Safety assertions
    assert not result[FEATURE_NAMES].isna().any().any(), "Missing values found in extracted features"
    assert np.isfinite(result[FEATURE_NAMES].to_numpy(dtype=float)).all(), "Non-finite values found in extracted features"
    assert len(FEATURE_NAMES) == 23, f"Expected exactly 23 features, found {len(FEATURE_NAMES)}"

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    result.to_csv(output_path, index=False)

    print(f"Output saved: {output_path}")
    print(f"Rows: {len(result)}; Features: {len(FEATURE_NAMES)}")
    print("Class counts:")
    print(result["label"].value_counts().sort_index().rename(index={0: "Safe", 1: "Malicious"}))
    return result


def main():
    generate_for_file(TRAIN_INPUT, TRAIN_OUTPUT, "TRAINING DATASET (V3)")
    if os.path.exists(INDEP_INPUT):
        generate_for_file(INDEP_INPUT, INDEP_OUTPUT, "INDEPENDENT EVALUATION DATASET")


if __name__ == "__main__":
    main()
