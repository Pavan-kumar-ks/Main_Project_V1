"""
Step 7: Use trained model to predict vulnerability severity
"""

import pandas as pd
import joblib
from sklearn.preprocessing import LabelEncoder
from pathlib import Path

# -------------------------------------------------------
# 1️⃣ Load trained model and encoders
# -------------------------------------------------------
model_path = Path("data/processed/model/trained_model.pkl")
if not model_path.exists():
    raise FileNotFoundError("❌ Trained model not found. Run ml_train.py first.")

model = joblib.load(model_path)
print("✅ Model loaded successfully.")

# -------------------------------------------------------
# 2️⃣ Example input data (you can replace or load dynamically)
# -------------------------------------------------------
# You can modify this list to include your own dependencies
data = [
    {"cpe_vendor": "code-projects", "cpe_product": "chat_system", "cvss_base_score": 6.3},
    {"cpe_vendor": "djangoproject", "cpe_product": "django", "cvss_base_score": 7.5},
    {"cpe_vendor": "anisha", "cpe_product": "online_shop", "cvss_base_score": 3.5},
    {"cpe_vendor": "optimizely", "cpe_product": "configured_commerce", "cvss_base_score": 9.1},
    {"cpe_vendor": "unknown_vendor", "cpe_product": "unknown_product", "cvss_base_score": 0.0}
]

new_df = pd.DataFrame(data)
print("\n📦 Input dependencies for prediction:")
print(new_df)

# -------------------------------------------------------
# 3️⃣ Encode categorical features
# -------------------------------------------------------
# We’ll refit encoders from known data (since we’re not using a persistent one)
from sklearn.preprocessing import LabelEncoder

# Simulate fitting from past data — in production, you’d save these encoders
vendor_enc = LabelEncoder()
product_enc = LabelEncoder()

# Load your ML dataset to restore encoder fitting
base_df = pd.read_csv("data/processed/ml_ready_dataset.csv")

vendor_enc.fit(base_df["cpe_vendor"])
product_enc.fit(base_df["cpe_product"])

new_df["vendor_encoded"] = new_df["cpe_vendor"].apply(
    lambda x: vendor_enc.transform([x])[0] if x in vendor_enc.classes_ else -1
)
new_df["product_encoded"] = new_df["cpe_product"].apply(
    lambda x: product_enc.transform([x])[0] if x in product_enc.classes_ else -1
)

# -------------------------------------------------------
# 4️⃣ Predict severity
# -------------------------------------------------------
X_new = new_df[["vendor_encoded", "product_encoded", "cvss_base_score"]]
preds = model.predict(X_new)

# Map encoded severity to human-readable labels
severity_map = {0: "CRITICAL", 1: "HIGH", 2: "LOW", 3: "MEDIUM", 4: "UNKNOWN"}
new_df["predicted_severity"] = [severity_map.get(p, "UNKNOWN") for p in preds]

# -------------------------------------------------------
# 5️⃣ Output predictions
# -------------------------------------------------------
output_path = Path("data/processed/predicted_vulnerabilities.csv")
new_df.to_csv(output_path, index=False)

print("\n✅ Predictions complete!")
print(new_df)
print(f"\n📁 Saved results to: {output_path}")
