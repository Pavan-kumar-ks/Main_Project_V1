"""
Final Step: AI-Powered Dependency Vulnerability Analyzer
--------------------------------------------------------
This script:
- Reads project dependencies from requirements.txt
- Loads your trained RandomForest model
- Predicts severity (LOW / MEDIUM / HIGH / CRITICAL)
- Saves a detailed AI vulnerability report
"""

import pandas as pd
import joblib
from pathlib import Path
from sklearn.preprocessing import LabelEncoder

# -------------------------------------------------------
# 1️⃣ Paths & Model Loading
# -------------------------------------------------------
model_path = Path("data/processed/model/trained_model.pkl")
data_path = Path("data/processed/ml_ready_dataset.csv")
req_path = Path("requirements.txt")

if not model_path.exists():
    raise FileNotFoundError("❌ Model not found. Run ml_train.py first.")
if not data_path.exists():
    raise FileNotFoundError("❌ ml_ready_dataset.csv missing. Run ml_preprocess.py first.")
if not req_path.exists():
    raise FileNotFoundError("❌ requirements.txt missing. Add dependencies first.")

model = joblib.load(model_path)
base_df = pd.read_csv(data_path)
print("✅ Loaded trained model and base dataset.")

# -------------------------------------------------------
# 2️⃣ Prepare encoders (fit from existing dataset)
# -------------------------------------------------------
vendor_enc = LabelEncoder()
product_enc = LabelEncoder()

vendor_enc.fit(base_df["cpe_vendor"].astype(str))
product_enc.fit(base_df["cpe_product"].astype(str))

# -------------------------------------------------------
# 3️⃣ Parse requirements.txt
# -------------------------------------------------------
deps = []
with open(req_path, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Split package and version (if available)
        if "==" in line:
            pkg, ver = line.split("==")
        elif ">" in line:
            pkg, ver = line.split(">")
        elif ">=" in line:
            pkg, ver = line.split(">=")
        else:
            pkg, ver = line, "unknown"
        deps.append({"cpe_vendor": "unknown_vendor", "cpe_product": pkg.lower(), "cvss_base_score": 0.0})

req_df = pd.DataFrame(deps)
print(f"📦 Loaded {len(req_df)} dependencies from requirements.txt")

# -------------------------------------------------------
# 4️⃣ Encode using known encoders
# -------------------------------------------------------
req_df["vendor_encoded"] = req_df["cpe_vendor"].apply(
    lambda x: vendor_enc.transform([x])[0] if x in vendor_enc.classes_ else -1
)
req_df["product_encoded"] = req_df["cpe_product"].apply(
    lambda x: product_enc.transform([x])[0] if x in product_enc.classes_ else -1
)

# -------------------------------------------------------
# 5️⃣ Predict severity
# -------------------------------------------------------
X_new = req_df[["vendor_encoded", "product_encoded", "cvss_base_score"]]
preds = model.predict(X_new)

# Map encoded predictions to human-readable labels
severity_map = {0: "CRITICAL", 1: "HIGH", 2: "LOW", 3: "MEDIUM", 4: "UNKNOWN"}
req_df["predicted_severity"] = [severity_map.get(p, "UNKNOWN") for p in preds]

# -------------------------------------------------------
# 6️⃣ Save the final AI vulnerability report
# -------------------------------------------------------
output_path = Path("data/processed/ai_predicted_report.csv")
req_df.to_csv(output_path, index=False)

print("\n✅ AI Vulnerability Report Generated Successfully!")
print(f"📁 Saved to: {output_path}")
print(req_df.head(10))
