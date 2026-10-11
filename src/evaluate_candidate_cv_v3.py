"""
CyberGuardian Desk - 5-Fold Domain-Separated Cross-Validation (v3)

Evaluates URL classification models using StratifiedGroupKFold on registrable domains.
Zero domain leakage between train and test splits.
Outputs fold metrics, aggregated out-of-fold metrics, and saves the final v3 production model.
"""

import os
import json
import warnings
import joblib
import pandas as pd
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)

warnings.filterwarnings("ignore", category=UserWarning)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FEATURES_PATH = os.path.join(BASE_DIR, "features", "features_v3.csv")
RESULTS_DIR = os.path.join(BASE_DIR, "results")
MODELS_DIR = os.path.join(BASE_DIR, "models")

os.makedirs(RESULTS_DIR, exist_ok=True)
os.makedirs(MODELS_DIR, exist_ok=True)

N_SPLITS = 5
RANDOM_STATE = 42

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


def make_models():
    return {
        "Logistic Regression": Pipeline([
            ("scaler", StandardScaler()),
            ("model", LogisticRegression(max_iter=2000, random_state=RANDOM_STATE)),
        ]),
        "Random Forest": RandomForestClassifier(
            n_estimators=200, class_weight="balanced",
            random_state=RANDOM_STATE, n_jobs=-1
        ),
        "HistGradientBoosting": HistGradientBoostingClassifier(
            max_iter=150, random_state=RANDOM_STATE
        ),
        "MLP": Pipeline([
            ("scaler", StandardScaler()),
            ("model", MLPClassifier(
                hidden_layer_sizes=(32, 16), max_iter=1500,
                early_stopping=True, random_state=RANDOM_STATE
            )),
        ]),
    }


def calculate_metrics(actual, predicted):
    return {
        "accuracy": accuracy_score(actual, predicted),
        "precision_malicious": precision_score(actual, predicted, zero_division=0),
        "recall_malicious": recall_score(actual, predicted, zero_division=0),
        "f1_malicious": f1_score(actual, predicted, zero_division=0),
    }


def main():
    print("=" * 70)
    print("CYBERGUARDIAN DESK - V3 DOMAIN GROUP CROSS-VALIDATION")
    print("=" * 70)

    if not os.path.exists(FEATURES_PATH):
        raise FileNotFoundError(f"Features file not found at {FEATURES_PATH}")

    df = pd.read_csv(FEATURES_PATH)
    required = {"url", "label", "registrable_domain", *FEATURE_NAMES}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Missing columns: {sorted(missing)}")

    df = df.dropna(subset=["url", "label", "registrable_domain"]).copy()
    df["label"] = pd.to_numeric(df["label"], errors="raise").astype(int)
    df["registrable_domain"] = df["registrable_domain"].astype(str).str.lower().str.strip()
    df[FEATURE_NAMES] = df[FEATURE_NAMES].apply(pd.to_numeric, errors="raise")

    X = df[FEATURE_NAMES]
    y = df["label"]
    groups = df["registrable_domain"]

    print(f"\nTotal URLs: {len(df)}")
    print(f"Unique Registrable Domains: {groups.nunique()}")
    print("\nClass distribution:")
    print(y.value_counts().sort_index().rename(index={0: "Safe", 1: "Malicious"}))

    cv = StratifiedGroupKFold(n_splits=N_SPLITS, shuffle=True, random_state=RANDOM_STATE)

    fold_records = []
    oof_records = []
    importance_records = []

    for fold, (train_idx, test_idx) in enumerate(cv.split(X, y, groups), start=1):
        train_domains = set(groups.iloc[train_idx])
        test_domains = set(groups.iloc[test_idx])
        overlap = train_domains.intersection(test_domains)

        if overlap:
            raise RuntimeError(f"Domain leakage detected in fold {fold}: {sorted(overlap)[:5]}")

        X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
        y_train, y_test = y.iloc[train_idx], y.iloc[test_idx]

        print("\n" + "-" * 70)
        print(f"FOLD {fold}/{N_SPLITS}")
        print("-" * 70)
        print(f"Train URLs: {len(train_idx)}; Test URLs: {len(test_idx)}")
        print(f"Train Domains: {len(train_domains)}; Test Domains: {len(test_domains)}")
        print(f"Test Class Counts: Safe={sum(y_test == 0)}, Malicious={sum(y_test == 1)}")

        models = make_models()
        for name, model in models.items():
            model.fit(X_train, y_train)
            preds = model.predict(X_test)
            metrics = calculate_metrics(y_test, preds)

            fold_records.append({
                "fold": fold,
                "model": name,
                "train_urls": len(train_idx),
                "test_urls": len(test_idx),
                "train_domains": len(train_domains),
                "test_domains": len(test_domains),
                **metrics,
            })

            for pos, row_idx in enumerate(test_idx):
                oof_records.append({
                    "url": df.iloc[row_idx]["url"],
                    "registrable_domain": groups.iloc[row_idx],
                    "label": int(y_test.iloc[pos]),
                    "fold": fold,
                    "model": name,
                    "prediction": int(preds[pos]),
                })

            if name == "Random Forest":
                for feat, imp in zip(FEATURE_NAMES, model.feature_importances_):
                    importance_records.append({
                        "fold": fold,
                        "feature": feat,
                        "importance": imp,
                    })

            print(
                f"{name:20}: Acc={metrics['accuracy']:.4f} | "
                f"Prec={metrics['precision_malicious']:.4f} | "
                f"Rec={metrics['recall_malicious']:.4f} | "
                f"F1={metrics['f1_malicious']:.4f}"
            )

    fold_df = pd.DataFrame(fold_records)
    oof_df = pd.DataFrame(oof_records)
    summary_rows = []

    print("\n" + "=" * 70)
    print("AGGREGATED OUT-OF-FOLD PERFORMANCE EVALUATION")
    print("=" * 70)

    for name in ["Random Forest", "HistGradientBoosting", "Logistic Regression", "MLP"]:
        mf = fold_df[fold_df["model"] == name]
        moof = oof_df[oof_df["model"] == name]
        metrics = calculate_metrics(moof["label"], moof["prediction"])
        cm = confusion_matrix(moof["label"], moof["prediction"], labels=[0, 1])

        summary_rows.append({
            "model": name,
            "accuracy_mean": mf["accuracy"].mean(),
            "accuracy_std": mf["accuracy"].std(ddof=1),
            "precision_mean": mf["precision_malicious"].mean(),
            "recall_mean": mf["recall_malicious"].mean(),
            "f1_mean": mf["f1_malicious"].mean(),
            "oof_accuracy": metrics["accuracy"],
            "oof_precision_malicious": metrics["precision_malicious"],
            "oof_recall_malicious": metrics["recall_malicious"],
            "oof_f1_malicious": metrics["f1_malicious"],
        })

        print(f"\nModel: {name}")
        print(f"OOF Accuracy : {metrics['accuracy']:.4f}")
        print(f"OOF Precision: {metrics['precision_malicious']:.4f}")
        print(f"OOF Recall   : {metrics['recall_malicious']:.4f}")
        print(f"OOF F1-Score : {metrics['f1_malicious']:.4f}")
        print("Confusion Matrix (rows=actual [Safe, Malicious], cols=pred [Safe, Malicious]):")
        print(cm)

    summary_df = pd.DataFrame(summary_rows).sort_values("oof_f1_malicious", ascending=False)

    # Save CSVs
    fold_path = os.path.join(RESULTS_DIR, "domain_cv_v3_fold_metrics.csv")
    oof_path = os.path.join(RESULTS_DIR, "domain_cv_v3_oof_predictions.csv")
    summary_path = os.path.join(RESULTS_DIR, "domain_cv_v3_summary.csv")
    importance_path = os.path.join(RESULTS_DIR, "random_forest_v3_cv_importance.csv")

    fold_df.to_csv(fold_path, index=False)
    oof_df.to_csv(oof_path, index=False)
    summary_df.to_csv(summary_path, index=False)

    imp_df = pd.DataFrame(importance_records)
    if not imp_df.empty:
        mean_imp = (
            imp_df.groupby("feature")["importance"]
            .agg(["mean", "std"])
            .reset_index()
            .rename(columns={"mean": "importance_mean", "std": "importance_std"})
            .sort_values("importance_mean", ascending=False)
        )
        mean_imp.to_csv(importance_path, index=False)
        print("\n" + "=" * 70)
        print("TOP V3 FEATURE IMPORTANCES (Across 5 Folds)")
        print("=" * 70)
        print(mean_imp.to_string(index=False))

    # Train final v3 Random Forest model on the complete dataset
    print("\n" + "=" * 70)
    print("TRAINING FINAL PRODUCTION MODEL (V3)")
    print("=" * 70)
    final_rf = RandomForestClassifier(
        n_estimators=250, class_weight="balanced", random_state=RANDOM_STATE, n_jobs=-1
    )
    final_rf.fit(X, y)

    v3_model_path = os.path.join(MODELS_DIR, "url_classifier_v3.pkl")
    v3_feature_order_path = os.path.join(MODELS_DIR, "feature_order_v3.json")

    joblib.dump(final_rf, v3_model_path)
    with open(v3_feature_order_path, "w", encoding="utf-8") as f:
        json.dump(FEATURE_NAMES, f, indent=2)

    print(f"Final Model saved: {v3_model_path}")
    print(f"Feature order saved: {v3_feature_order_path}")
    print(f"Summary metrics saved: {summary_path}")


if __name__ == "__main__":
    main()
