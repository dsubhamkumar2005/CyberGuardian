import os
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline


# ============================================================
# PATHS
# ============================================================

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

FEATURES_PATH = os.path.join(BASE_DIR, "features", "features.csv")
MODELS_DIR = os.path.join(BASE_DIR, "models")

os.makedirs(MODELS_DIR, exist_ok=True)


print("=" * 60)
print("TRAINING MALICIOUS URL CLASSIFIERS")
print("=" * 60)

print(f"Loading dataset: {FEATURES_PATH}")

df = pd.read_csv(FEATURES_PATH)

print(f"Loaded {len(df)} samples across {len(df.columns)} columns.")


# ============================================================
# SEPARATE FEATURES AND TARGET
# ============================================================

X = df.drop(columns=["label"])
y = df["label"]

feature_names = list(X.columns)

print(f"Features ({len(feature_names)}): {feature_names}")


# ============================================================
# TRAIN-TEST SPLIT
# ============================================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

print(f"Training set: {X_train.shape[0]} samples")
print(f"Testing set : {X_test.shape[0]} samples")


# ============================================================
# 1. LOGISTIC REGRESSION
# ============================================================

print("\n" + "=" * 60)
print("<< 1. LOGISTIC REGRESSION MODEL >>")
print("=" * 60)

lr_model = LogisticRegression(
    max_iter=1000,
    random_state=42
)

lr_model.fit(X_train, y_train)

lr_predictions = lr_model.predict(X_test)

lr_accuracy = accuracy_score(
    y_test,
    lr_predictions
)

print(f"Logistic Regression Accuracy: {lr_accuracy:.4f}")

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        lr_predictions,
        target_names=["Safe (0)", "Malicious (1)"]
    )
)


# ============================================================
# 2. RANDOM FOREST
# ============================================================

print("\n" + "=" * 60)
print("<< 2. RANDOM FOREST MODEL >>")
print("=" * 60)

rf_model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)

rf_model.fit(X_train, y_train)

rf_predictions = rf_model.predict(X_test)

rf_accuracy = accuracy_score(
    y_test,
    rf_predictions
)

print(f"Random Forest Accuracy: {rf_accuracy:.4f}")

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        rf_predictions,
        target_names=["Safe (0)", "Malicious (1)"]
    )
)


# ============================================================
# RANDOM FOREST CONFUSION MATRIX
# ============================================================

print("\nConfusion Matrix:")

cm = confusion_matrix(
    y_test,
    rf_predictions
)

print(
    f"True Safe / Pred Safe       : {cm[0][0]:3d} | "
    f"True Safe / Pred Malicious : {cm[0][1]:3d}"
)

print(
    f"True Mal / Pred Safe        : {cm[1][0]:3d} | "
    f"True Mal / Pred Malicious  : {cm[1][1]:3d}"
)


# ============================================================
# 3. MLP NEURAL NETWORK
# ============================================================

print("\n" + "=" * 60)
print("<< 3. MLP NEURAL NETWORK >>")
print("=" * 60)

mlp_model = Pipeline([
    ("scaler", StandardScaler()),

    ("mlp", MLPClassifier(
        hidden_layer_sizes=(32, 16),
        max_iter=1000,
        random_state=42
    ))
])

mlp_model.fit(X_train, y_train)

mlp_predictions = mlp_model.predict(X_test)

mlp_accuracy = accuracy_score(
    y_test,
    mlp_predictions
)

print(f"MLP Accuracy: {mlp_accuracy:.4f}")

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        mlp_predictions,
        target_names=["Safe (0)", "Malicious (1)"]
    )
)


# ============================================================
# 4. MODEL COMPARISON
# ============================================================

print("\n" + "=" * 60)
print("<< MODEL COMPARISON >>")
print("=" * 60)

print(f"Logistic Regression Accuracy : {lr_accuracy * 100:.2f}%")
print(f"Random Forest Accuracy       : {rf_accuracy * 100:.2f}%")
print(f"MLP Accuracy                 : {mlp_accuracy * 100:.2f}%")


# ============================================================
# 5. RANDOM FOREST FEATURE IMPORTANCE
# ============================================================

print("\n" + "=" * 60)
print("<< RANDOM FOREST FEATURE IMPORTANCE >>")
print("=" * 60)

feature_importance = pd.DataFrame({
    "Feature": feature_names,
    "Importance": rf_model.feature_importances_
})

feature_importance = feature_importance.sort_values(
    by="Importance",
    ascending=False
).reset_index(drop=True)

for i, row in feature_importance.iterrows():

    bar = "#" * int(row["Importance"] * 50)

    print(
        f"{i + 1:2d}. "
        f"{row['Feature']:26} : "
        f"{row['Importance']:.4f} | {bar}"
    )


# ============================================================
# 6. SAVE MODELS
# ============================================================

print("\n" + "=" * 60)
print("<< SAVING MODEL ARTIFACTS >>")
print("=" * 60)

lr_model_path = os.path.join(
    MODELS_DIR,
    "logistic_regression_model.pkl"
)

rf_model_path = os.path.join(
    MODELS_DIR,
    "url_classifier.pkl"
)

rf_backup_path = os.path.join(
    MODELS_DIR,
    "random_forest_model.pkl"
)

mlp_model_path = os.path.join(
    MODELS_DIR,
    "mlp_model.pkl"
)


joblib.dump(
    lr_model,
    lr_model_path
)

joblib.dump(
    rf_model,
    rf_model_path
)

joblib.dump(
    rf_model,
    rf_backup_path
)

joblib.dump(
    mlp_model,
    mlp_model_path
)


print(f"Logistic Regression saved to: {lr_model_path}")
print(f"Random Forest saved to       : {rf_model_path}")
print(f"Random Forest backup saved   : {rf_backup_path}")
print(f"MLP saved to                 : {mlp_model_path}")

print("\nTraining workflow completed successfully!")