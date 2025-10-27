"""
Step 8: Advanced ML Model for Severity Prediction
-------------------------------------------------
Uses both structured features (vendor, product, cvss)
and unstructured features (description text).
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from scipy.sparse import hstack
from pathlib import Path
import joblib
import matplotlib.pyplot as plt
import seaborn as sns

# -------------------------------------------------------
# 1️⃣ Load data
# -------------------------------------------------------
data_path = Path("data/processed/ml_ready_dataset.csv")

if not data_path.exists():
    raise FileNotFoundError("❌ ml_ready_dataset.csv not found. Run ml_preprocess.py first.")

df = pd.read_csv(data_path)

# Optional: add description if available
if "description" not in df.columns:
    print("⚠️ No description found — merging from original dataset.")
    base_csv = Path("data/processed/cve_cpe.csv")
    if base_csv.exists():
        base_df = pd.read_csv(base_csv, usecols=["description"])
        df["description"] = base_df["description"].fillna("No description provided.")
    else:
        df["description"] = "No description provided."

print(f"✅ Loaded dataset: {len(df)} records.")
print(df.head(3))

# -------------------------------------------------------
# 2️⃣ Prepare features and labels
# -------------------------------------------------------
df["description"] = df["description"].fillna("No description provided.")
df["cvss_base_score"] = pd.to_numeric(df["cvss_base_score"], errors="coerce").fillna(0)

# Encode vendor & product
vendor_enc = LabelEncoder()
product_enc = LabelEncoder()
df["vendor_encoded"] = vendor_enc.fit_transform(df["cpe_vendor"].astype(str))
df["product_encoded"] = product_enc.fit_transform(df["cpe_product"].astype(str))

# Encode labels (severity)
label_enc = LabelEncoder()
df["severity_encoded"] = label_enc.fit_transform(df["severity"].astype(str))

# -------------------------------------------------------
# 3️⃣ TF-IDF feature extraction from descriptions
# -------------------------------------------------------
print("🔤 Extracting TF-IDF features from CVE descriptions...")
tfidf = TfidfVectorizer(
    max_features=5000,
    ngram_range=(1, 2),
    stop_words="english"
)
X_text = tfidf.fit_transform(df["description"])

# -------------------------------------------------------
# 4️⃣ Combine structured + text features
# -------------------------------------------------------
X_struct = df[["vendor_encoded", "product_encoded", "cvss_base_score"]].values
X_combined = hstack([X_struct, X_text])  # sparse + numeric
y = df["severity_encoded"]

# -------------------------------------------------------
# 5️⃣ Split dataset
# -------------------------------------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X_combined, y, test_size=0.2, random_state=42, stratify=y
)

print(f"📊 Training samples: {X_train.shape[0]}, Test samples: {X_test.shape[0]}")

# -------------------------------------------------------
# 6️⃣ Train enhanced RandomForest model
# -------------------------------------------------------
model = RandomForestClassifier(
    n_estimators=300,
    max_depth=20,
    class_weight="balanced",
    random_state=42,
    n_jobs=-1
)
print("🚀 Training advanced severity prediction model...")
model.fit(X_train, y_train)

# -------------------------------------------------------
# 7️⃣ Evaluate model
# -------------------------------------------------------
y_pred = model.predict(X_test)
acc = accuracy_score(y_test, y_pred)
print(f"\n✅ Model Accuracy: {acc:.3f}")
print("\nClassification Report:")
print(classification_report(y_test, y_pred))

# Confusion matrix visualization
plt.figure(figsize=(6, 4))
sns.heatmap(confusion_matrix(y_test, y_pred), annot=True, fmt="d", cmap="Blues")
plt.title("Confusion Matrix - Severity Prediction (v2)")
plt.xlabel("Predicted")
plt.ylabel("Actual")
plt.tight_layout()
plt.show()

# -------------------------------------------------------
# 8️⃣ Save model + encoders + vectorizer
# -------------------------------------------------------
model_dir = Path("data/processed/model")
model_dir.mkdir(parents=True, exist_ok=True)

joblib.dump(model, model_dir / "trained_model_v2.pkl")
joblib.dump(tfidf, model_dir / "tfidf_vectorizer.pkl")
joblib.dump(vendor_enc, model_dir / "vendor_encoder.pkl")
joblib.dump(product_enc, model_dir / "product_encoder.pkl")
joblib.dump(label_enc, model_dir / "severity_encoder.pkl")

print(f"\n✅ Advanced model and encoders saved to {model_dir}")
