import pandas as pd
import numpy as np
import joblib
import difflib
import re
from pathlib import Path
from sklearn.preprocessing import LabelEncoder

# -----------------------
# 1️⃣ File Paths
# -----------------------
BASE_DIR = Path(__file__).resolve().parents[1]
MODEL_PATH = BASE_DIR / "data" / "processed" / "model" / "trained_model.pkl"
CPE_DATA_PATH = BASE_DIR / "data" / "processed" / "unique_cpes.csv"
REQ_PATH = BASE_DIR / "requirements_test.txt"

# -----------------------
# 2️⃣ Load Model + Data
# -----------------------
print("📦 Loading trained ML model...")
model = joblib.load(MODEL_PATH)

print("📄 Loading unique CPE dataset...")
cpe_df = pd.read_csv(CPE_DATA_PATH)
cpe_df = cpe_df.fillna("unknown")
cpe_df.columns = [c.strip().lower() for c in cpe_df.columns]

print(f"✅ Loaded {len(cpe_df)} CPE entries")

# -----------------------
# 3️⃣ Helper Functions
# -----------------------
def read_requirements(req_path: Path):
    """Read requirements.txt and extract package name + version."""
    packages = []
    pattern = re.compile(r"([a-zA-Z0-9_.-]+)==?([0-9a-zA-Z_.-]*)")
    with open(req_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = pattern.match(line)
            if match:
                pkg, version = match.groups()
                packages.append((pkg.lower(), version))
            else:
                packages.append((line.lower(), ""))
    return pd.DataFrame(packages, columns=["package", "version"])


def get_best_match(package_name, cpe_products, cutoff=0.75):
    """Fuzzy match package name to closest CPE product."""
    matches = difflib.get_close_matches(package_name, cpe_products, n=1, cutoff=cutoff)
    return matches[0] if matches else None


# -----------------------
# 4️⃣ Safe Label Encoder Wrapper
# -----------------------
class SafeLabelEncoder(LabelEncoder):
    def transform_safe(self, values):
        values = np.array(values)
        known_classes = set(self.classes_)
        transformed = []
        for v in values:
            if v in known_classes:
                transformed.append(super().transform([v])[0])
            else:
                transformed.append(super().transform([self.classes_[0]])[0])  # fallback to first known
        return np.array(transformed)


# -----------------------
# 5️⃣ Prepare Encoders
# -----------------------
vendor_encoder = SafeLabelEncoder()
product_encoder = SafeLabelEncoder()
severity_encoder = SafeLabelEncoder()

vendor_encoder.fit(list(cpe_df["cpe_vendor"].astype(str)) + ["unknown_vendor"])
product_encoder.fit(list(cpe_df["cpe_product"].astype(str)) + ["unknown_product"])
severity_encoder.fit(["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"])

# -----------------------
# 6️⃣ Predict Severity
# -----------------------
req_df = read_requirements(REQ_PATH)
print(f"📥 Loaded {len(req_df)} dependencies to analyze")

predictions = []

for _, row in req_df.iterrows():
    pkg = row["package"]
    version = row["version"] or "unknown"

    best_match = get_best_match(pkg, cpe_df["cpe_product"].astype(str).tolist(), cutoff=0.6)
    if best_match:
        matched_row = cpe_df[cpe_df["cpe_product"] == best_match].iloc[0]
        vendor = matched_row["cpe_vendor"]
        product = matched_row["cpe_product"]
        base_score = matched_row.get("cvss_base_score", np.nan)
    else:
        vendor, product, base_score = "unknown_vendor", "unknown_product", np.nan

    # Prepare features for prediction
    input_df = pd.DataFrame([{
        "cpe_vendor": vendor,
        "cpe_product": product,
        "cvss_base_score": base_score if not pd.isna(base_score) else 0.0
    }])

    input_df["vendor_encoded"] = vendor_encoder.transform_safe(input_df["cpe_vendor"].astype(str))
    input_df["product_encoded"] = product_encoder.transform_safe(input_df["cpe_product"].astype(str))

    X_test = input_df[["vendor_encoded", "product_encoded", "cvss_base_score"]]
    severity_pred = model.predict(X_test)[0]
    pred_label = severity_encoder.inverse_transform([severity_pred])[0]

    predictions.append({
        "dependency": f"{pkg}=={version}",
        "matched_vendor": vendor,
        "matched_product": product,
        "cvss_score": base_score,
        "predicted_severity": pred_label
    })

# -----------------------
# 7️⃣ Save & Display Results
# -----------------------
output_df = pd.DataFrame(predictions)
output_path = BASE_DIR / "data" / "processed" / "severity_predictions.csv"
output_df.to_csv(output_path, index=False)

print("\n✅ Severity Prediction Completed!")
print(f"📊 Results saved at: {output_path}")
print(output_df)
