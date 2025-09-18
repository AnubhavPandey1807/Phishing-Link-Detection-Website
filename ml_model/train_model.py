import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import joblib
from feature_extractor import extract_features

# ✅ Import selected features list from feature_extractor.py
from ml_model.feature_extractor import selected_features

# Load dataset (e.g. phishing vs benign URLs CSV from Kaggle)
data = pd.read_csv("Phishing_Legitimate_full.csv")

# Extract features
X = data[selected_features]
# X = data.drop(columns=["CLASS_LABEL", "id"])   # drop label + id
y = data["CLASS_LABEL"]  # 1 = phishing, 0 = safe

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

# Train model
clf = RandomForestClassifier(n_estimators=100, random_state=42,  n_jobs=-1)
clf.fit(X_train, y_train)

print("Accuracy:", clf.score(X_test, y_test))
# print(classification_report(y_test, y_pred))


# Evaluate
# y_pred = clf.predict(X_test)
# print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred))
# print("\nClassification Report:\n", classification_report(y_test, y_pred))

# Save model
joblib.dump(clf, "phishing_model.pkl")
print("✅ Model saved as phishing_model.pkl")
