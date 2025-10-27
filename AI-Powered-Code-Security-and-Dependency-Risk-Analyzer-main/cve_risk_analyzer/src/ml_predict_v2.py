"""
Step 9: Predict Severity Using Advanced v2 Model
------------------------------------------------
Uses TF-IDF + structured features to predict severity
for new CVEs or dependency descriptions.
"""

import pandas as pd
import joblib
from scipy.sparse import hstack
from pathlib import Path

# -------------------------------------------------------
# 1️⃣ Load trained model and encoders
# -------------------------------------------------------
model_dir = Path("data/processed/model")

model = joblib.load(model_dir / "trained_model_v2.pkl")
tfidf = joblib.load(model_dir / "tfidf_vectorizer.pkl")
vendor_enc = joblib.load(model_dir / "vendor_encoder.pkl")
product_enc = joblib.load(model_dir / "product_encoder.pkl")
severity_enc = joblib.load(model_dir / "severity_encoder.pkl")

print("✅ Model and encoders loaded successfully.")

# -------------------------------------------------------
# 2️⃣ Define new samples for prediction
# -------------------------------------------------------
# You can replace or extend these examples
samples = [
    {
        "cpe_vendor": "code-projects",
        "cpe_product": "chat_system",
        "cvss_base_score": 0.0,
        "description": "SQL injection vulnerability allows attackers to modify database queries through the login form."
    },
    {
        "cpe_vendor": "djangoproject",
        "cpe_product": "django",
        "cvss_base_score": 0.0,
        "description": "Cross-site scripting vulnerability in template rendering may allow attackers to inject scripts."
    },
    {
        "cpe_vendor": "anisha",
        "cpe_product": "online_shop",
        "cvss_base_score": 0.0,
        "description": "Local privilege escalation due to insecure file permissions in payment module."
    },
    {
        "cpe_vendor": "unknown_vendor",
        "cpe_product": "test_app",
        "cvss_base_score": 0.0,
        "description": "Buffer overflow in image parsing component allows remote code execution."
    }
]

df = pd.DataFrame(samples)
print("\n📦 New vulnerabilities for prediction:")
print(df[["cpe_product", "description"]])

# -------------------------------------------------------
# 3️⃣ Encode structured features
# -------------------------------------------------------
def safe_encode(encoder, value):
    if value in encoder.classes_:
        return encoder.transform([value])[0]
    else:
        return -1  # unseen category

df["vendor_encoded"] = df["cpe_vendor"].apply(lambda x: safe_encode(vendor_enc, x))
df["product_encoded"] = df["cpe_product"].apply(lambda x: safe_encode(product_enc, x))

# -------------------------------------------------------
# 4️⃣ Generate TF-IDF vectors for descriptions
# -------------------------------------------------------
X_text = tfidf.transform(df["description"])
X_struct = df[["vendor_encoded", "product_encoded", "cvss_base_score"]].values
X_combined = hstack([X_struct, X_text])

# -------------------------------------------------------
# 5️⃣ Predict severity
# -------------------------------------------------------
y_pred_encoded = model.predict(X_combined)
y_pred = severity_enc.inverse_transform(y_pred_encoded)
df["predicted_severity"] = y_pred

# -------------------------------------------------------
# 6️⃣ Save results
# -------------------------------------------------------
output_path = Path("data/processed/ai_predicted_report_v2.csv")
df.to_csv(output_path, index=False)

print("\n✅ Prediction complete!")
print(df[["cpe_vendor", "cpe_product", "predicted_severity", "description"]])
print(f"\n📁 Results saved to: {output_path}")
