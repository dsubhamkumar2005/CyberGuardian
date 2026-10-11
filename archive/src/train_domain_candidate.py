import os
import json
import warnings
import joblib
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    classification_report, confusion_matrix,
)

warnings.filterwarnings("ignore", category=UserWarning)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FEATURES_PATH = os.path.join(BASE_DIR, "features", "features_candidate.csv")
RESULTS_DIR = os.path.join(BASE_DIR, "results")
MODELS_DIR = os.path.join(BASE_DIR, "models")
os.makedirs(RESULTS_DIR, exist_ok=True)
os.makedirs(MODELS_DIR, exist_ok=True)

FEATURE_NAMES = [
    "length", "path_length", "query_length", "subdomain_count",
    "num_subdirectories", "uses_ip", "has_https", "special_char_count",
    "shannon_entropy", "num_digits", "digit_ratio", "num_hyphens",
    "has_at_symbol", "has_double_slash_redirect", "is_shortened",
    "has_suspicious_keywords",
]


def main():
    print("=" * 65)
    print("CYBERGUARDIAN DESK - DOMAIN-SEPARATED CANDIDATE EVALUATION")
    print("=" * 65)
    df = pd.read_csv(FEATURES_PATH)
    required = {"url", "label", "registrable_domain", *FEATURE_NAMES}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Missing columns: {sorted(missing)}")
    df[FEATURE_NAMES] = df[FEATURE_NAMES].apply(pd.to_numeric, errors="raise")
    df["label"] = pd.to_numeric(df["label"], errors="raise").astype(int)
    if df[FEATURE_NAMES].isna().any().any():
        raise ValueError("Feature matrix contains missing values.")
    if df["registrable_domain"].isna().any():
        raise ValueError("Missing registrable domains.")
    if set(df["label"].unique()) != {0, 1}:
        raise ValueError("Both labels 0 and 1 must exist.")

    X = df[FEATURE_NAMES]
    y = df["label"]
    groups = df["registrable_domain"].astype(str)
    print(f"URLs: {len(df)}; unique domains: {groups.nunique()}")
    print("Class counts:")
    print(y.value_counts().sort_index().rename(index={0: "Safe", 1: "Malicious"}))

    splitter = GroupShuffleSplit(n_splits=100, test_size=0.20, random_state=42)
    best_split = None
    best_score = float("inf")
    overall_malicious_fraction = float(y.mean())
    for train_idx, test_idx in splitter.split(X, y, groups):
        y_train_try, y_test_try = y.iloc[train_idx], y.iloc[test_idx]
        if y_train_try.nunique() != 2 or y_test_try.nunique() != 2:
            continue
        size_error = abs(len(test_idx) / len(df) - 0.20)
        class_error = abs(float(y_test_try.mean()) - overall_malicious_fraction)
        score = size_error + class_error
        if score < best_score:
            best_score = score
            best_split = (train_idx, test_idx)
    if best_split is None:
        raise RuntimeError("Unable to find a domain-separated split with both classes.")

    train_idx, test_idx = best_split
    X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
    y_train, y_test = y.iloc[train_idx], y.iloc[test_idx]
    train_domains = set(groups.iloc[train_idx])
    test_domains = set(groups.iloc[test_idx])
    overlap = train_domains & test_domains
    if overlap:
        raise RuntimeError(f"Domain leakage detected: {sorted(overlap)[:5]}")
    print(f"\nTraining URLs: {len(train_idx)}; Testing URLs: {len(test_idx)}")
    print(f"Training domains: {len(train_domains)}; Testing domains: {len(test_domains)}")
    print(f"Domain overlap: {len(overlap)}")
    print("Test labels:")
    print(y_test.value_counts().sort_index())

    models = {
        "Logistic Regression": Pipeline([
            ("scaler", StandardScaler()),
            ("model", LogisticRegression(max_iter=2000, random_state=42)),
        ]),
        "Random Forest": RandomForestClassifier(
            n_estimators=200, class_weight="balanced", random_state=42, n_jobs=-1
        ),
        "MLP": Pipeline([
            ("scaler", StandardScaler()),
            ("model", MLPClassifier(
                hidden_layer_sizes=(32, 16), max_iter=1500,
                early_stopping=True, random_state=42
            )),
        ]),
    }
    results = []
    test_predictions = pd.DataFrame({
        "url": df.iloc[test_idx]["url"].values,
        "registrable_domain": df.iloc[test_idx]["registrable_domain"].values,
        "actual_label": y_test.values,
        "url_shape": df.iloc[test_idx].get("url_shape", pd.Series([""]*len(test_idx))).values,
        "source_file": df.iloc[test_idx].get("source_file", pd.Series([""]*len(test_idx))).values,
    })
    for name, model in models.items():
        print("\n" + "=" * 65)
        print(f"MODEL: {name}")
        print("=" * 65)
        model.fit(X_train, y_train)
        pred = model.predict(X_test)
        test_predictions[name.replace(" ", "_").lower() + "_prediction"] = pred
        metrics = {
            "model": name,
            "accuracy": accuracy_score(y_test, pred),
            "precision_malicious": precision_score(y_test, pred, zero_division=0),
            "recall_malicious": recall_score(y_test, pred, zero_division=0),
            "f1_malicious": f1_score(y_test, pred, zero_division=0),
            "test_urls": len(test_idx),
            "test_domains": len(test_domains),
        }
        results.append(metrics)
        print(f"Accuracy : {metrics['accuracy']:.4f}")
        print(f"Precision: {metrics['precision_malicious']:.4f}")
        print(f"Recall   : {metrics['recall_malicious']:.4f}")
        print(f"F1-score : {metrics['f1_malicious']:.4f}")
        print(classification_report(
            y_test, pred, labels=[0, 1], target_names=["Safe", "Malicious"], zero_division=0
        ))
        print("Confusion matrix (rows=actual, columns=predicted):")
        print(confusion_matrix(y_test, pred, labels=[0, 1]))

    results_df = pd.DataFrame(results).sort_values("f1_malicious", ascending=False)
    metrics_path = os.path.join(RESULTS_DIR, "domain_model_results_candidate.csv")
    results_df.to_csv(metrics_path, index=False)
    test_predictions.to_csv(os.path.join(RESULTS_DIR, "domain_test_predictions_candidate.csv"), index=False)

    manifest = df.copy()
    manifest["split"] = "train"
    manifest.loc[test_idx, "split"] = "test"
    manifest.to_csv(os.path.join(RESULTS_DIR, "domain_split_manifest_candidate.csv"), index=False)

    rf = models["Random Forest"]
    joblib.dump(rf, os.path.join(MODELS_DIR, "url_classifier_domain_candidate_v2.pkl"))
    with open(os.path.join(MODELS_DIR, "feature_order_domain_candidate_v2.json"), "w", encoding="utf-8") as f:
        json.dump(FEATURE_NAMES, f, indent=2)
    importance = pd.DataFrame({
        "feature": FEATURE_NAMES,
        "importance": rf.feature_importances_,
    }).sort_values("importance", ascending=False)
    importance.to_csv(os.path.join(RESULTS_DIR, "domain_feature_importance_candidate.csv"), index=False)

    print("\n" + "=" * 65)
    print("CANDIDATE DOMAIN-SEPARATED COMPARISON")
    print("=" * 65)
    print(results_df.to_string(index=False))
    print(f"\nMetrics saved to: {metrics_path}")
    print("Existing baseline results and models were not overwritten.")
    print("CAUTION: This candidate is a resampling of existing source files, not independent validation.")
    print("CAUTION: It contains no query-bearing URLs; query handling remains untested.")

    # Display baseline metrics if the existing result file is present.
    old_path = os.path.join(RESULTS_DIR, "domain_model_results.csv")
    if os.path.exists(old_path):
        try:
            old = pd.read_csv(old_path)
            print("\nExisting baseline metrics (for context only; dataset composition differs):")
            print(old.to_string(index=False))
        except Exception as exc:
            print(f"Could not read existing baseline metrics: {exc}")


if __name__ == "__main__":
    main()
