
import os
import json
import warnings

import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier

from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
)

from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.exceptions import ConvergenceWarning


# ============================================================
# PATHS
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

FEATURES_PATH = os.path.join(
    BASE_DIR, "features", "features_rebuilt.csv"
)

MODELS_DIR = os.path.join(BASE_DIR, "models")

RESULTS_DIR = os.path.join(BASE_DIR, "results")

os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)


# Save under new names so old models remain untouched.
MODEL_FILES = {
    "Logistic Regression": "logistic_regression_rebuilt.pkl",
    "Random Forest": "url_classifier_rebuilt.pkl",
    "MLP": "mlp_model_rebuilt.pkl",
}


# ============================================================
# LOAD DATASET
# ============================================================

print("=" * 65)
print("CYBERGUARDIAN DESK - MODEL TRAINING")
print("=" * 65)

print(f"\nLoading dataset: {FEATURES_PATH}")

if not os.path.exists(FEATURES_PATH):
    raise FileNotFoundError(
        f"Dataset not found: {FEATURES_PATH}\n"
        "Run generate_features.py first."
    )

df = pd.read_csv(FEATURES_PATH)

print(f"Loaded {len(df)} rows and {len(df.columns)} columns.")

if "label" not in df.columns:
    raise ValueError("Dataset must contain a 'label' column.")

# The feature-generation script should output 16 features + label.
if len(df.columns) != 17:
    raise ValueError(
        f"Expected 17 columns (16 features + label), "
        f"but found {len(df.columns)}."
    )

if df.isna().any().any():
    raise ValueError("Missing values found. Fix the dataset first.")

if not df["label"].isin([0, 1]).all():
    raise ValueError("Labels must be 0 (Safe) or 1 (Malicious).")

X = df.drop(columns=["label"])
y = df["label"].astype(int)

# Ensure every input feature is numeric.
X = X.apply(pd.to_numeric, errors="coerce")

if X.isna().any().any():
    raise ValueError("Non-numeric feature values found.")

feature_names = list(X.columns)

print(f"\nNumber of features: {len(feature_names)}")
print("Features:", feature_names)

print("\nClass distribution:")
print(
    y.value_counts()
    .sort_index()
    .rename(index={0: "Safe", 1: "Malicious"})
)

# This is a diagnostic split only, not the final evaluation.
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y,
)

print(f"\nTraining rows: {len(X_train)}")
print(f"Testing rows : {len(X_test)}")


# ============================================================
# DEFINE MODELS
# ============================================================

models = {
    "Logistic Regression": Pipeline([
        ("scaler", StandardScaler()),
        ("model", LogisticRegression(
            max_iter=2000,
            random_state=42,
        )),
    ]),

    "Random Forest": RandomForestClassifier(
        n_estimators=200,
        random_state=42,
        class_weight="balanced",
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


# ============================================================
# TRAIN AND EVALUATE
# ============================================================

results = []
trained_models = {}

for name, model in models.items():

    print("\n" + "=" * 65)
    print(f"MODEL: {name}")
    print("=" * 65)

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")

        model.fit(X_train, y_train)

        for warning in caught:
            if issubclass(warning.category, ConvergenceWarning):
                print("WARNING: Model did not converge fully.")

    predictions = model.predict(X_test)

    accuracy = accuracy_score(y_test, predictions)

    # Positive class = Malicious (label 1).
    precision = precision_score(
        y_test, predictions, pos_label=1, zero_division=0
    )

    recall = recall_score(
        y_test, predictions, pos_label=1, zero_division=0
    )

    f1 = f1_score(
        y_test, predictions, pos_label=1, zero_division=0
    )

    cm = confusion_matrix(
        y_test, predictions, labels=[0, 1]
    )

    print(f"\nAccuracy : {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall   : {recall:.4f}")
    print(f"F1-score : {f1:.4f}")

    print("\nClassification report:")
    print(
        classification_report(
            y_test,
            predictions,
            labels=[0, 1],
            target_names=["Safe", "Malicious"],
            zero_division=0,
        )
    )

    print("Confusion matrix (rows = actual, columns = predicted):")
    print("                 Pred Safe  Pred Malicious")
    print(f"Actual Safe      {cm[0, 0]:9d}  {cm[0, 1]:14d}")
    print(f"Actual Malicious {cm[1, 0]:9d}  {cm[1, 1]:14d}")

    results.append({
        "model": name,
        "accuracy": accuracy,
        "precision_malicious": precision,
        "recall_malicious": recall,
        "f1_malicious": f1,
        "true_safe": int(cm[0, 0]),
        "false_positive": int(cm[0, 1]),
        "false_negative": int(cm[1, 0]),
        "true_malicious": int(cm[1, 1]),
    })

    trained_models[name] = model


# ============================================================
# COMPARE MODELS
# ============================================================

results_df = pd.DataFrame(results)

print("\n" + "=" * 65)
print("MODEL COMPARISON - DIAGNOSTIC SPLIT")
print("=" * 65)

print(
    results_df[
        [
            "model",
            "accuracy",
            "precision_malicious",
            "recall_malicious",
            "f1_malicious",
        ]
    ].to_string(index=False)
)

results_path = os.path.join(
    RESULTS_DIR, "diagnostic_model_results.csv"
)

results_df.to_csv(results_path, index=False)

print(f"\nMetrics saved to: {results_path}")


# ============================================================
# RANDOM FOREST FEATURE IMPORTANCE
# ============================================================

rf_model = trained_models["Random Forest"]

importance_df = pd.DataFrame({
    "feature": feature_names,
    "importance": rf_model.feature_importances_,
}).sort_values("importance", ascending=False)

importance_path = os.path.join(
    RESULTS_DIR, "diagnostic_feature_importance.csv"
)

importance_df.to_csv(importance_path, index=False)

print("\nRandom Forest feature importance:")
print(importance_df.to_string(index=False))


# ============================================================
# SAVE MODELS AS DIAGNOSTIC MODELS
# ============================================================

print("\n" + "=" * 65)
print("SAVING DIAGNOSTIC MODELS")
print("=" * 65)

for name, model in trained_models.items():

    filename = MODEL_FILES[name]
    model_path = os.path.join(MODELS_DIR, filename)

    joblib.dump(model, model_path)

    print(f"{name}: {model_path}")

# Save feature order to help enforce consistency during inference.
feature_order_path = os.path.join(
    MODELS_DIR, "feature_order_rebuilt.json"
)

with open(feature_order_path, "w", encoding="utf-8") as file:
    json.dump(feature_names, file, indent=2)

print(f"Feature order saved to: {feature_order_path}")

print("\n" + "=" * 65)
print("DIAGNOSTIC TRAINING COMPLETED")
print("These results are NOT final validated performance.")
print("=" * 65)
