"""
Step 6: Train ML model for vulnerability severity prediction
Uses RandomForestClassifier to learn from CVE–CPE data.
"""

import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix
)
from pathlib import Path
import matplotlib.pyplot as plt
import seaborn as sns

# -------------------------------------------------------
# 1️⃣ Load ML-ready dataset
# -------------------------------------------------------
data_path = Path("data/processed/ml_ready_dataset.csv")
df = pd.read_csv(data_path)

print(f"✅ Loaded dataset with {len(df)} records.")
print(df.head(3))

# -------------------------------------------------------
# 2️⃣ Define features and labels
# -------------------------------------------------------
X = df[["vendor_encoded", "product_encoded", "cvss_base_score"]]
y = df["severity_encoded"]

# Split dataset
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print(f"📊 Training samples: {len(X_train)}, Test samples: {len(X_test)}")

# -------------------------------------------------------
# 3️⃣ Train RandomForest model
# -------------------------------------------------------
model = RandomForestClassifier(
    n_estimators=200,
    max_depth=10,
    random_state=42,
    class_weight="balanced"
)
model.fit(X_train, y_train)

# -------------------------------------------------------
# 4️⃣ Evaluate model
# -------------------------------------------------------
y_pred = model.predict(X_test)

print("\n📈 Model Evaluation:")
print("Accuracy:", round(accuracy_score(y_test, y_pred), 3))
print("\nClassification Report:")
print(classification_report(y_test, y_pred))

# Confusion matrix visualization
plt.figure(figsize=(6, 4))
sns.heatmap(confusion_matrix(y_test, y_pred), annot=True, fmt="d", cmap="Blues")
plt.title("Confusion Matrix - Severity Prediction")
plt.xlabel("Predicted")
plt.ylabel("Actual")
plt.tight_layout()
plt.show()

# -------------------------------------------------------
# 5️⃣ Save model
# -------------------------------------------------------
model_dir = Path("data/processed/model")
model_dir.mkdir(parents=True, exist_ok=True)

model_path = model_dir / "trained_model.pkl"
joblib.dump(model, model_path)

print(f"\n✅ Model saved successfully at: {model_path}")
