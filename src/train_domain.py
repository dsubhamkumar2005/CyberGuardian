
import os
import json
import warnings

import joblib
import pandas as pd
import tldextract

from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix,
)

warnings.filterwarnings("ignore", category=UserWarning)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

FEATURES_PATH = os.path.join(
    BASE_DIR, "features", "features_domain.csv"
)
RESULTS_DIR = os.path.join(BASE_DIR, "results")
MODELS_DIR = os.path.join(BASE_DIR, "models")

os.makedirs(RESULTS_DIR, exist_ok=True)
os.makedirs(MODELS_DIR, exist_ok=True)

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


def get_domain(url):
    """Return the registrable domain used to group related URLs."""
    extracted = tldextract.extract(url)
    domain = extracted.top_domain_under_public_suffix

    if domain:
        return domain.lower()

    # Fallback for IP addresses, localhost, or unusual hostnames.
    from urllib.parse import urlparse

    hostname = urlparse(
        url if "://" in url else "https://" + url
    ).hostname

    return hostname.lower() if hostname else None


def main():
    print("=" * 65)
    print("CYBERGUARDIAN DESK - DOMAIN-SEPARATED EVALUATION")
    print("=" * 65)

    df = pd.read_csv(FEATURES_PATH)

    required = {"url", "label", *FEATURE_NAMES}
    missing = required - set(df.columns)

    if missing:
        raise ValueError(f"Missing columns: {sorted(missing)}")

    if df["url"].isna().any() or df["label"].isna().any():
        raise ValueError("Dataset contains missing URLs or labels.")

    df["label"] = pd.to_numeric(df["label"], errors="raise").astype(int)

    if not set(df["label"].unique()).issubset({0, 1}):
        raise ValueError("Labels must be 0 (safe) or 1 (malicious).")

    df[FEATURE_NAMES] = df[FEATURE_NAMES].apply(
        pd.to_numeric, errors="raise"
    )

    if df[FEATURE_NAMES].isna().any().any():
        raise ValueError("Numeric features contain missing values.")

    df["domain"] = df["url"].apply(get_domain)

    if df["domain"].isna().any():
        bad = df.loc[df["domain"].isna(), "url"].tolist()
        raise ValueError(f"Could not extract domains for: {bad[:5]}")

    # Remove exact duplicate URLs to avoid duplicate rows.
    df = df.drop_duplicates(subset=["url"]).reset_index(drop=True)

    X = df[FEATURE_NAMES]
    y = df["label"]
    groups = df["domain"]

    print(f"\nTotal URLs: {len(df)}")
    print(f"Unique registrable domains: {groups.nunique()}")
    print("\nClass distribution:")
    print(y.value_counts().sort_index().rename(
        index={0: "Safe", 1: "Malicious"}
    ))

    # Try multiple group splits and choose a valid split whose test
    # size is close to 20% and whose class balance is reasonable.
    splitter = GroupShuffleSplit(
        n_splits=100, test_size=0.20, random_state=42
    )

    best_split = None
    best_score = float("inf")

    for train_idx, test_idx in splitter.split(X, y, groups):
        y_train_candidate = y.iloc[train_idx]
        y_test_candidate = y.iloc[test_idx]

        if y_train_candidate.nunique() != 2:
            continue
        if y_test_candidate.nunique() != 2:
            continue

        test_fraction = len(test_idx) / len(df)
        test_malicious_fraction = y_test_candidate.mean()
        overall_malicious_fraction = y.mean()

        score = (
            abs(test_fraction - 0.20)
            + abs(test_malicious_fraction - overall_malicious_fraction)
        )

        if score < best_score:
            best_score = score
            best_split = (train_idx, test_idx)

    if best_split is None:
        raise RuntimeError(
            "Could not find a domain-separated split containing both "
            "classes in training and testing. The dataset may have too "
            "few distinct domains. Do not fall back silently to a random "
            "row split; improve the dataset or choose a suitable split."
        )

    train_idx, test_idx = best_split

    X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
    y_train, y_test = y.iloc[train_idx], y.iloc[test_idx]
    train_domains = set(groups.iloc[train_idx])
    test_domains = set(groups.iloc[test_idx])

    # Essential leakage check.
    overlap = train_domains.intersection(test_domains)
    if overlap:
        raise RuntimeError(f"Domain leakage detected: {sorted(overlap)[:5]}")

    print("\nSplit summary:")
    print(f"Training URLs: {len(train_idx)}")
    print(f"Testing URLs : {len(test_idx)}")
    print(f"Training domains: {len(train_domains)}")
    print(f"Testing domains : {len(test_domains)}")
    print(f"Domain overlap: {len(overlap)}")
    print("\nTraining labels:")
    print(y_train.value_counts().sort_index())
    print("\nTesting labels:")
    print(y_test.value_counts().sort_index())

    models = {
        "Logistic Regression": Pipeline([
            ("scaler", StandardScaler()),
            ("model", LogisticRegression(
                max_iter=2000, random_state=42
            )),
        ]),
        "Random Forest": RandomForestClassifier(
            n_estimators=200,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        ),
        "MLP": Pipeline([
            ("scaler", StandardScaler()),
            ("model", MLPClassifier(
                hidden_layer_sizes=(32, 16),
                max_iter=1500,
                early_stopping=True,
                random_state=42,
            )),
        ]),
    }

    results = []
    predictions_by_model = {}

    for name, model in models.items():
        print("\n" + "=" * 65)
        print(f"MODEL: {name}")
        print("=" * 65)

        model.fit(X_train, y_train)
        predictions = model.predict(X_test)
        predictions_by_model[name] = predictions

        accuracy = accuracy_score(y_test, predictions)
        precision = precision_score(
            y_test, predictions, zero_division=0
        )
        recall = recall_score(
            y_test, predictions, zero_division=0
        )
        f1 = f1_score(
            y_test, predictions, zero_division=0
        )

        print(f"Accuracy : {accuracy:.4f}")
        print(f"Precision: {precision:.4f}")
        print(f"Recall   : {recall:.4f}")
        print(f"F1-score : {f1:.4f}")

        print("\nClassification report:")
        print(classification_report(
            y_test,
            predictions,
            labels=[0, 1],
            target_names=["Safe", "Malicious"],
            zero_division=0,
        ))

        matrix = confusion_matrix(
            y_test, predictions, labels=[0, 1]
        )
        print("Confusion matrix (rows=actual, columns=predicted):")
        print(matrix)

        results.append({
            "model": name,
            "accuracy": accuracy,
            "precision_malicious": precision,
            "recall_malicious": recall,
            "f1_malicious": f1,
            "test_urls": len(test_idx),
            "test_domains": len(test_domains),
        })

    results_df = pd.DataFrame(results).sort_values(
        "f1_malicious", ascending=False
    )

    metrics_path = os.path.join(
        RESULTS_DIR, "domain_model_results.csv"
    )
    results_df.to_csv(metrics_path, index=False)

    split_path = os.path.join(
        RESULTS_DIR, "domain_split_manifest.csv"
    )
    manifest = df[["url", "label", "domain"]].copy()
    manifest["split"] = "train"
    manifest.loc[test_idx, "split"] = "test"
    manifest.to_csv(split_path, index=False)

    # Save a separate RF model and feature order only as candidates.
    rf_model = models["Random Forest"]
    joblib.dump(
        rf_model,
        os.path.join(MODELS_DIR, "url_classifier_domain_candidate.pkl"),
    )

    with open(
        os.path.join(MODELS_DIR, "feature_order_domain_candidate.json"),
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(FEATURE_NAMES, file, indent=2)

    print("\n" + "=" * 65)
    print("DOMAIN-SEPARATED MODEL COMPARISON")
    print("=" * 65)
    print(results_df.to_string(index=False))
    print(f"\nMetrics saved to: {metrics_path}")
    print(f"Split manifest saved to: {split_path}")
    print("\nDomain-separated evaluation completed.")
    print("These results are still preliminary, not final validation.")


if __name__ == "__main__":
    main()
