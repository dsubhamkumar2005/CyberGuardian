import os
import warnings

import pandas as pd
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report,
)

warnings.filterwarnings("ignore", category=UserWarning)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FEATURES_PATH = os.path.join(BASE_DIR, "features", "features_v2_candidate.csv")
RESULTS_DIR = os.path.join(BASE_DIR, "results")
os.makedirs(RESULTS_DIR, exist_ok=True)

N_SPLITS = 5
RANDOM_STATE = 42

FEATURE_NAMES = [
    "length", "path_length", "query_length", "subdomain_count",
    "num_subdirectories", "uses_ip", "has_https", "special_char_count",
    "shannon_entropy", "num_digits", "digit_ratio", "num_hyphens",
    "has_at_symbol", "has_double_slash_redirect", "is_shortened",
    "has_suspicious_keywords",
]


def make_models():
    return {
        "Logistic Regression": Pipeline([
            ("scaler", StandardScaler()),
            ("model", LogisticRegression(max_iter=2000, random_state=RANDOM_STATE)),
        ]),
        "Random Forest": RandomForestClassifier(
            n_estimators=200, class_weight="balanced",
            random_state=RANDOM_STATE, n_jobs=-1,
        ),
        "MLP": Pipeline([
            ("scaler", StandardScaler()),
            ("model", MLPClassifier(
                hidden_layer_sizes=(32, 16), max_iter=1500,
                early_stopping=True, random_state=RANDOM_STATE,
            )),
        ]),
    }


def get_metrics(actual, predicted):
    return {
        "accuracy": accuracy_score(actual, predicted),
        "precision_malicious": precision_score(actual, predicted, zero_division=0),
        "recall_malicious": recall_score(actual, predicted, zero_division=0),
        "f1_malicious": f1_score(actual, predicted, zero_division=0),
    }


def main():
    print("=" * 68)
    print("CYBERGUARDIAN DESK - V2 FIVE-FOLD DOMAIN CROSS-VALIDATION")
    print("=" * 68)

    if not os.path.exists(FEATURES_PATH):
        raise FileNotFoundError(
            f"Features file not found: {FEATURES_PATH}\n"
            "Run src/generate_features_v2.py first."
        )

    df = pd.read_csv(FEATURES_PATH)
    required = {"url", "label", "registrable_domain", *FEATURE_NAMES}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Missing columns: {sorted(missing)}")

    df = df.dropna(subset=["url", "label", "registrable_domain"]).copy()
    df["label"] = pd.to_numeric(df["label"], errors="raise").astype(int)
    df["registrable_domain"] = df["registrable_domain"].astype(str).str.lower().str.strip()
    df[FEATURE_NAMES] = df[FEATURE_NAMES].apply(pd.to_numeric, errors="raise")

    if not set(df["label"].unique()).issubset({0, 1}) or df["label"].nunique() != 2:
        raise ValueError("Dataset must include both labels: 0=safe, 1=malicious.")
    if df["url"].duplicated().any():
        raise ValueError("Duplicate URLs found in features_v2_candidate.csv.")
    if df[FEATURE_NAMES].isna().any().any():
        raise ValueError("Numeric features contain missing values.")

    X = df[FEATURE_NAMES]
    y = df["label"]
    groups = df["registrable_domain"]

    print(f"\nURLs: {len(df)}")
    print(f"Unique registrable domains: {groups.nunique()}")
    print("\nClass counts:")
    print(y.value_counts().sort_index().rename(index={0:"Safe",1:"Malicious"}))
    if "url_shape" in df and "https_group" in df:
        print("\nStructure/protocol balance:")
        print(pd.crosstab([df["url_shape"], df["https_group"]], y).rename(
            columns={0:"Safe",1:"Malicious"}
        ).to_string())

    splitter = StratifiedGroupKFold(
        n_splits=N_SPLITS, shuffle=True, random_state=RANDOM_STATE
    )

    fold_records = []
    oof_records = []
    importance_records = []

    for fold, (train_idx, test_idx) in enumerate(splitter.split(X, y, groups), start=1):
        train_domains = set(groups.iloc[train_idx])
        test_domains = set(groups.iloc[test_idx])
        overlap = train_domains & test_domains
        if overlap:
            raise RuntimeError(f"Domain overlap in fold {fold}: {sorted(overlap)[:5]}")

        X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
        y_train, y_test = y.iloc[train_idx], y.iloc[test_idx]
        if y_train.nunique() != 2 or y_test.nunique() != 2:
            raise RuntimeError(f"Fold {fold} doesn't contain both classes.")

        print("\n" + "-" * 68)
        print(f"FOLD {fold}/{N_SPLITS}")
        print("-" * 68)
        print(f"Train URLs: {len(train_idx)}; test URLs: {len(test_idx)}")
        print(f"Train domains: {len(train_domains)}; test domains: {len(test_domains)}")
        print(f"Domain overlap: {len(overlap)}")
        print("Test class counts:")
        print(y_test.value_counts().sort_index().rename(
            index={0:"Safe",1:"Malicious"}
        ))

        for name, model in make_models().items():
            model.fit(X_train, y_train)
            pred = model.predict(X_test)
            metrics = get_metrics(y_test, pred)

            fold_records.append({
                "fold": fold, "model": name,
                "train_urls": len(train_idx), "test_urls": len(test_idx),
                "train_domains": len(train_domains), "test_domains": len(test_domains),
                **metrics,
            })

            print(
                f"\n{name}: accuracy={metrics['accuracy']:.4f}, "
                f"precision={metrics['precision_malicious']:.4f}, "
                f"recall={metrics['recall_malicious']:.4f}, "
                f"F1={metrics['f1_malicious']:.4f}"
            )
            print(classification_report(
                y_test, pred, labels=[0,1],
                target_names=["Safe","Malicious"], zero_division=0,
            ))
            print("Confusion matrix (rows=actual, columns=predicted):")
            print(confusion_matrix(y_test, pred, labels=[0,1]))

            test_rows = df.iloc[test_idx]
            for pos, row_index in enumerate(test_idx):
                oof_records.append({
                    "url": df.iloc[row_index]["url"],
                    "registrable_domain": groups.iloc[row_index],
                    "label": int(y.iloc[row_index]),
                    "fold": fold,
                    "model": name,
                    "prediction": int(pred[pos]),
                })

            if name == "Random Forest":
                importance_records.extend([
                    {"fold": fold, "feature": feat, "importance": float(val)}
                    for feat, val in zip(FEATURE_NAMES, model.feature_importances_)
                ])

    fold_df = pd.DataFrame(fold_records)
    oof_df = pd.DataFrame(oof_records)
    summary_rows = []

    for name in ["Logistic Regression", "Random Forest", "MLP"]:
        mf = fold_df[fold_df["model"] == name]
        moof = oof_df[oof_df["model"] == name]
        aggregate = get_metrics(moof["label"], moof["prediction"])
        summary_rows.append({
            "model": name,
            "accuracy_mean": mf["accuracy"].mean(),
            "accuracy_std": mf["accuracy"].std(ddof=1),
            "precision_mean": mf["precision_malicious"].mean(),
            "recall_mean": mf["recall_malicious"].mean(),
            "f1_mean": mf["f1_malicious"].mean(),
            "oof_accuracy": aggregate["accuracy"],
            "oof_precision_malicious": aggregate["precision_malicious"],
            "oof_recall_malicious": aggregate["recall_malicious"],
            "oof_f1_malicious": aggregate["f1_malicious"],
        })

        cm = confusion_matrix(moof["label"], moof["prediction"], labels=[0,1])
        print("\n" + "=" * 68)
        print(f"AGGREGATED OUT-OF-FOLD RESULTS: {name}")
        print("=" * 68)
        print(
            f"Accuracy: {aggregate['accuracy']:.4f} | "
            f"Malicious precision: {aggregate['precision_malicious']:.4f} | "
            f"Malicious recall: {aggregate['recall_malicious']:.4f} | "
            f"Malicious F1: {aggregate['f1_malicious']:.4f}"
        )
        print("Confusion matrix (rows=actual, columns=predicted):")
        print(cm)

    summary_df = pd.DataFrame(summary_rows).sort_values(
        "oof_f1_malicious", ascending=False
    )

    fold_path = os.path.join(RESULTS_DIR, "domain_cv_v2_fold_metrics.csv")
    oof_path = os.path.join(RESULTS_DIR, "domain_cv_v2_oof_predictions.csv")
    summary_path = os.path.join(RESULTS_DIR, "domain_cv_v2_summary.csv")
    importance_path = os.path.join(RESULTS_DIR, "random_forest_v2_cv_importance.csv")

    fold_df.to_csv(fold_path, index=False)
    oof_df.to_csv(oof_path, index=False)
    summary_df.to_csv(summary_path, index=False)

    importance_df = pd.DataFrame(importance_records)
    if not importance_df.empty:
        imp = (
            importance_df.groupby("feature")["importance"]
            .agg(["mean", "std"])
            .reset_index()
            .rename(columns={"mean":"importance_mean","std":"importance_std"})
            .sort_values("importance_mean", ascending=False)
        )
        imp.to_csv(importance_path, index=False)

    print("\n" + "=" * 68)
    print("V2 FIVE-FOLD DOMAIN CROSS-VALIDATION SUMMARY")
    print("=" * 68)
    print(summary_df.to_string(index=False))
    print("\nSaved:")
    print(fold_path)
    print(oof_path)
    print(summary_path)
    print(importance_path)
    print("\nThese are preliminary development metrics, not independent real-world validation.")


if __name__ == "__main__":
    main()
