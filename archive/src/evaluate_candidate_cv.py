import os
import warnings

import pandas as pd
import tldextract

from sklearn.model_selection import StratifiedGroupKFold
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
    confusion_matrix,
)

warnings.filterwarnings("ignore", category=UserWarning)

# --------------------------------------------------
# PATHS AND CONFIGURATION
# --------------------------------------------------

BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

FEATURES_PATH = os.path.join(
    BASE_DIR, "features", "features_candidate.csv"
)

RESULTS_DIR = os.path.join(BASE_DIR, "results")
os.makedirs(RESULTS_DIR, exist_ok=True)

N_SPLITS = 5
RANDOM_STATE = 42

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

# Include private suffixes so that tenants on hosting
# platforms can be grouped by their own registrable domain.
extract_domain = tldextract.TLDExtract(
    include_psl_private_domains=True
)


# --------------------------------------------------
# DOMAIN EXTRACTION
# --------------------------------------------------

def get_domain(url):
    """Extract the registrable domain from a URL."""

    from urllib.parse import urlparse

    url = str(url).strip()

    if not url:
        return None

    # Add a scheme when the URL does not provide one.
    if "://" not in url:
        url = "https://" + url

    extracted = extract_domain(url)

    domain = extracted.top_domain_under_public_suffix

    if domain:
        return domain.lower()

    # Fallback for IP addresses, localhost, or unusual hosts.
    hostname = urlparse(url).hostname

    if hostname:
        return hostname.lower()

    return None


# --------------------------------------------------
# MODEL DEFINITIONS
# --------------------------------------------------

def make_models():
    """Create fresh model instances for each fold."""

    return {
        "Logistic Regression": Pipeline([
            ("scaler", StandardScaler()),
            (
                "model",
                LogisticRegression(
                    max_iter=2000,
                    random_state=RANDOM_STATE,
                ),
            ),
        ]),

        "Random Forest": RandomForestClassifier(
            n_estimators=200,
            class_weight="balanced",
            random_state=RANDOM_STATE,
            n_jobs=-1,
        ),

        "MLP": Pipeline([
            ("scaler", StandardScaler()),
            (
                "model",
                MLPClassifier(
                    hidden_layer_sizes=(32, 16),
                    max_iter=1500,
                    early_stopping=True,
                    random_state=RANDOM_STATE,
                ),
            ),
        ]),
    }


# --------------------------------------------------
# METRICS
# --------------------------------------------------

def calculate_metrics(actual, predicted):
    """Calculate metrics for the malicious class (label 1)."""

    return {
        "accuracy": accuracy_score(actual, predicted),
        "precision_malicious": precision_score(
            actual, predicted, zero_division=0
        ),
        "recall_malicious": recall_score(
            actual, predicted, zero_division=0
        ),
        "f1_malicious": f1_score(
            actual, predicted, zero_division=0
        ),
    }


# --------------------------------------------------
# MAIN EVALUATION
# --------------------------------------------------

def main():

    print("=" * 68)
    print("CYBERGUARDIAN DESK - FIVE-FOLD DOMAIN CROSS-VALIDATION")
    print("=" * 68)

    if not os.path.exists(FEATURES_PATH):
        raise FileNotFoundError(
            f"Features file not found: {FEATURES_PATH}\n"
            "Run generate_features_candidate.py first."
        )

    df = pd.read_csv(FEATURES_PATH)

    # The domain column is NOT required; we derive it from each URL.
    required_columns = {"url", "label", *FEATURE_NAMES}
    missing_columns = required_columns - set(df.columns)

    if missing_columns:
        raise ValueError(
            f"Missing required columns: {sorted(missing_columns)}"
        )

    # Clean and validate the input rows.
    df = df.dropna(subset=["url", "label"]).copy()

    df["url"] = df["url"].astype(str).str.strip()
    df = df[df["url"] != ""].copy()

    if df["url"].duplicated().any():
        duplicates = int(df["url"].duplicated().sum())

        raise ValueError(
            f"Found {duplicates} duplicate URLs. "
            "Resolve duplicate rows before evaluation."
        )

    df["label"] = pd.to_numeric(
        df["label"], errors="raise"
    ).astype(int)

    if set(df["label"].unique()) != {0, 1}:
        raise ValueError(
            "Dataset must contain both classes: "
            "0 = safe and 1 = malicious."
        )

    X = df[FEATURE_NAMES].apply(
        pd.to_numeric, errors="raise"
    )

    y = df["label"]

    if X.isna().any().any():
        raise ValueError(
            "Feature columns contain missing values."
        )

    # Derive registrable domains directly from the original URLs.
    print("\nExtracting domains from URLs...")

    df["domain"] = df["url"].apply(get_domain)

    if df["domain"].isna().any():
        bad_urls = df.loc[
            df["domain"].isna(), "url"
        ].tolist()

        raise ValueError(
            "Could not extract domains from these URLs: "
            f"{bad_urls[:5]}"
        )

    groups = df["domain"].astype(str).str.lower()

    print(f"\nTotal URLs: {len(df)}")
    print(f"Unique registrable domains: {groups.nunique()}")

    print("\nClass distribution:")
    print(
        y.value_counts()
        .sort_index()
        .rename(index={0: "Safe", 1: "Malicious"})
    )

    # --------------------------------------------------
    # STRATIFIED GROUP CROSS-VALIDATION
    # --------------------------------------------------

    cv = StratifiedGroupKFold(
        n_splits=N_SPLITS,
        shuffle=True,
        random_state=RANDOM_STATE,
    )

    fold_records = []
    oof_records = []
    importance_records = []

    # Each domain is held out as a whole group.
    for fold, (train_idx, test_idx) in enumerate(
        cv.split(X, y, groups), start=1
    ):

        train_domains = set(groups.iloc[train_idx])
        test_domains = set(groups.iloc[test_idx])

        overlap = train_domains.intersection(test_domains)

        if overlap:
            raise RuntimeError(
                f"Domain leakage in fold {fold}: "
                f"{sorted(overlap)[:5]}"
            )

        X_train = X.iloc[train_idx]
        X_test = X.iloc[test_idx]

        y_train = y.iloc[train_idx]
        y_test = y.iloc[test_idx]

        if y_train.nunique() != 2 or y_test.nunique() != 2:
            raise RuntimeError(
                f"Fold {fold} does not contain both classes. "
                "Review the data and grouping strategy."
            )

        print("\n" + "-" * 68)
        print(f"FOLD {fold}/{N_SPLITS}")
        print("-" * 68)

        print(f"Training URLs: {len(train_idx)}")
        print(f"Testing URLs : {len(test_idx)}")
        print(f"Training domains: {len(train_domains)}")
        print(f"Testing domains : {len(test_domains)}")
        print(f"Domain overlap: {len(overlap)}")

        print("\nTest class counts:")
        print(
            y_test.value_counts()
            .sort_index()
            .rename(index={0: "Safe", 1: "Malicious"})
        )

        models = make_models()

        for model_name, model in models.items():

            model.fit(X_train, y_train)
            predictions = model.predict(X_test)

            metrics = calculate_metrics(
                y_test, predictions
            )

            fold_records.append({
                "fold": fold,
                "model": model_name,
                "train_urls": len(train_idx),
                "test_urls": len(test_idx),
                "train_domains": len(train_domains),
                "test_domains": len(test_domains),
                **metrics,
            })

            print(
                f"\n{model_name}: "
                f"Accuracy={metrics['accuracy']:.4f}, "
                f"Precision={metrics['precision_malicious']:.4f}, "
                f"Recall={metrics['recall_malicious']:.4f}, "
                f"F1={metrics['f1_malicious']:.4f}"
            )

            # Preserve each URL's prediction from its held-out fold.
            for position, row_index in enumerate(test_idx):

                oof_records.append({
                    "url": df.iloc[row_index]["url"],
                    "domain": groups.iloc[row_index],
                    "label": int(y_test.iloc[position]),
                    "fold": fold,
                    "model": model_name,
                    "prediction": int(predictions[position]),
                })

            # Record Random Forest feature importance per fold.
            if model_name == "Random Forest":

                for feature, importance in zip(
                    FEATURE_NAMES,
                    model.feature_importances_,
                ):
                    importance_records.append({
                        "fold": fold,
                        "feature": feature,
                        "importance": importance,
                    })

    # --------------------------------------------------
    # AGGREGATE RESULTS
    # --------------------------------------------------

    fold_df = pd.DataFrame(fold_records)
    oof_df = pd.DataFrame(oof_records)

    summary_rows = []

    for model_name in [
        "Logistic Regression",
        "Random Forest",
        "MLP",
    ]:

        model_folds = fold_df[
            fold_df["model"] == model_name
        ]

        model_oof = oof_df[
            oof_df["model"] == model_name
        ]

        actual = model_oof["label"]
        predicted = model_oof["prediction"]

        overall_metrics = calculate_metrics(
            actual, predicted
        )

        summary_rows.append({
            "model": model_name,

            "accuracy_mean": model_folds["accuracy"].mean(),
            "accuracy_std": model_folds["accuracy"].std(
                ddof=1
            ),

            "precision_mean":
                model_folds["precision_malicious"].mean(),

            "recall_mean":
                model_folds["recall_malicious"].mean(),

            "f1_mean":
                model_folds["f1_malicious"].mean(),

            "oof_accuracy":
                overall_metrics["accuracy"],

            "oof_precision_malicious":
                overall_metrics["precision_malicious"],

            "oof_recall_malicious":
                overall_metrics["recall_malicious"],

            "oof_f1_malicious":
                overall_metrics["f1_malicious"],
        })

        matrix = confusion_matrix(
            actual, predicted, labels=[0, 1]
        )

        print("\n" + "=" * 68)
        print(f"AGGREGATED OUT-OF-FOLD RESULTS: {model_name}")
        print("=" * 68)

        print(
            f"Accuracy : {overall_metrics['accuracy']:.4f}"
        )
        print(
            f"Precision: "
            f"{overall_metrics['precision_malicious']:.4f}"
        )
        print(
            f"Recall   : "
            f"{overall_metrics['recall_malicious']:.4f}"
        )
        print(
            f"F1-score : "
            f"{overall_metrics['f1_malicious']:.4f}"
        )

        print(
            "\nConfusion matrix "
            "(rows=actual, columns=predicted):"
        )
        print(matrix)

    summary_df = pd.DataFrame(summary_rows).sort_values(
        "oof_f1_malicious",
        ascending=False,
    )

    # --------------------------------------------------
    # SAVE RESULTS WITHOUT OVERWRITING BASELINE FILES
    # --------------------------------------------------

    fold_path = os.path.join(
        RESULTS_DIR,
        "domain_cv_candidate_fold_metrics.csv",
    )

    oof_path = os.path.join(
        RESULTS_DIR,
        "domain_cv_candidate_oof_predictions.csv",
    )

    summary_path = os.path.join(
        RESULTS_DIR,
        "domain_cv_candidate_summary.csv",
    )

    importance_path = os.path.join(
        RESULTS_DIR,
        "random_forest_candidate_cv_importance.csv",
    )

    fold_df.to_csv(fold_path, index=False)
    oof_df.to_csv(oof_path, index=False)
    summary_df.to_csv(summary_path, index=False)

    # Mean and standard deviation of RF importance across folds.
    importance_df = pd.DataFrame(importance_records)

    if not importance_df.empty:

        mean_importance = (
            importance_df.groupby("feature")["importance"]
            .agg(["mean", "std"])
            .reset_index()
            .rename(columns={
                "mean": "importance_mean",
                "std": "importance_std",
            })
            .sort_values(
                "importance_mean",
                ascending=False,
            )
        )

        mean_importance.to_csv(
            importance_path, index=False
        )

    print("\n" + "=" * 68)
    print("FIVE-FOLD DOMAIN CROSS-VALIDATION SUMMARY")
    print("=" * 68)

    print(summary_df.to_string(index=False))

    print("\nSaved results:")
    print(fold_path)
    print(oof_path)
    print(summary_path)

    if not importance_df.empty:
        print(importance_path)

    print("\nCross-validation completed.")
    print(
        "These results are preliminary. "
        "Dataset label quality and query handling "
        "still require validation."
    )


if __name__ == "__main__":
    main()