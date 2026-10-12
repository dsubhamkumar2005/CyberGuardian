import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report
from sklearn.ensemble import RandomForestClassifier

df = pd.read_csv("features/features.csv")

# print(df.head())
# basically splitting the table into 2: X= everything without label and Y = everything with label.
X = df.drop(columns=["label"])
y = df["label"]

# print(X.head)
# print(y.head)

# What does this do? Suppose you have 200 rows Then 80% goes into training. 160 rows 20% goes into testing.
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

print("Training: ", X_train.shape)
print("Testing: ", X_test.shape)
# from o/p - 6 is the number of feature columns.

# model.fit() - imagine giving the model these data:  
# URL 1 Length = 75 Entropy = 4.5 Uses IP = 1 Label = Malicious
# another: Length = 15 Entropy = 2.8 Uses IP = 0 Label = Safe  
# The model studies all training rows and learns patterns that separate safe from malicious URLs.
model = LogisticRegression(max_iter=1000)
model.fit(X_train, y_train)
print("Model Trained Successfully haha!")

predictions = model.predict(X_test)
accuracy = accuracy_score(y_test, predictions)
print("Accuracy: ", accuracy)
# if accuracy = 0.80, then 80% predictions were right
print(classification_report(y_test, predictions))

# now to train using the same using random forest 
print("\n")
print("<< R A N D O M   F O R E S T >>")
rf_model = RandomForestClassifier(
    n_estimators=100, #Random Forest will build 100 decision trees.
    random_state=42 # Keeps the results the same every time you run the program.
)
rf_model.fit(X_train, y_train)
print("Random forest trained successfully haha")

rf_predictions = rf_model.predict(X_test)
rf_accuracy = accuracy_score(y_test, rf_predictions)
print("Accuracy:", rf_accuracy)
print(classification_report(y_test, rf_predictions))

print("\n")
print("<< M O D E L   C O M P A R I S O N >>")
print(f"Logistic Regression Accuracy : {accuracy:.4f}")
print(f"Random Forest Accuracy       : {rf_accuracy:.4f}")

# ============================================================
# 7. RANDOM FOREST FEATURE IMPORTANCE
# ============================================================
print("\n")
print("<< R A N D O M   F O R E S T   F E A T U R E   I M P O R T A N C E >>")

feature_importance = pd.DataFrame({
    "feature": X.columns,
    "importance": rf_model.feature_importances_
})

feature_importance = feature_importance.sort_values(
    by="importance",
    ascending=False
)

print(feature_importance)
print("\n<< SAVING BEST MODEL >>")
joblib.dump(rf_model, "models/url_classifier.pkl")
print("Random Forest model saved successfully!")

joblib.dump(rf_model, "models/random_forest_model.pkl")
print("Random Forest model saved successfully!")