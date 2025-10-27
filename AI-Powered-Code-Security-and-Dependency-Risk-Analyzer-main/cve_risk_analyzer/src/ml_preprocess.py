# """
# Step 5: Data Preparation for ML
# This script loads the preprocessed NVD CSV file, cleans it,
# encodes severity levels, and outputs a ready-to-train dataset.
# """

# import pandas as pd
# import numpy as np
# from sklearn.preprocessing import LabelEncoder
# from pathlib import Path

# # -------------------------------------------------------
# # 1️⃣ Load the dataset
# # -------------------------------------------------------
# data_path = Path("data/processed/cve_cpe.csv")
# df = pd.read_csv(data_path)

# print("✅ Loaded dataset:")
# print(f"Total records: {len(df)}")
# print(df.head(3))

# # -------------------------------------------------------
# # 2️⃣ Basic cleaning
# # -------------------------------------------------------
# # Drop completely empty rows
# df = df.dropna(how="all")

# # Fill empty text fields
# df["description"] = df["description"].fillna("No description provided.")
# df["cpe_vendor"] = df["cpe_vendor"].fillna("unknown_vendor")
# df["cpe_product"] = df["cpe_product"].fillna("unknown_product")
# df["cpe_version"] = df["cpe_version"].fillna("unknown")

# # Replace missing CVSS scores with 0
# df["cvss_base_score"] = pd.to_numeric(df["cvss_base_score"], errors="coerce").fillna(0)

# # Standardize severity
# df["severity"] = df["severity"].fillna("UNKNOWN").str.upper()
# df.loc[df["cvss_base_score"] >= 9.0, "severity"] = "CRITICAL"
# df.loc[(df["cvss_base_score"] >= 7.0) & (df["cvss_base_score"] < 9.0), "severity"] = "HIGH"
# df.loc[(df["cvss_base_score"] >= 4.0) & (df["cvss_base_score"] < 7.0), "severity"] = "MEDIUM"
# df.loc[(df["cvss_base_score"] > 0) & (df["cvss_base_score"] < 4.0), "severity"] = "LOW"

# # -------------------------------------------------------
# # 3️⃣ Encode categorical values
# # -------------------------------------------------------
# label_enc = LabelEncoder()
# df["vendor_encoded"] = label_enc.fit_transform(df["cpe_vendor"])
# df["product_encoded"] = label_enc.fit_transform(df["cpe_product"])
# df["severity_encoded"] = label_enc.fit_transform(df["severity"])

# # -------------------------------------------------------
# # 4️⃣ Select useful features
# # -------------------------------------------------------
# ml_df = df[[
#     "cpe_vendor", "cpe_product", "cpe_version",
#     "cvss_base_score", "severity", "vendor_encoded",
#     "product_encoded", "severity_encoded"
# ]]

# # -------------------------------------------------------
# # 5️⃣ Save cleaned dataset
# # -------------------------------------------------------
# output_path = Path("data/processed/ml_ready_dataset.csv")
# ml_df.to_csv(output_path, index=False)
# print(f"\n✅ ML-ready dataset saved to: {output_path}")
# print(f"Total records: {len(ml_df)}")
# print(ml_df.head(5))

















"""
Step 5: Data Preparation for ML (Fixed Version)
This script loads the preprocessed NVD CSV file, cleans it,
adds a severity column if missing, encodes features,
and saves an ML-ready dataset.
"""

import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder
from pathlib import Path

# -------------------------------------------------------
# 1️⃣ Load the dataset
# -------------------------------------------------------
data_path = Path("data/processed/cve_cpe.csv")

if not data_path.exists():
    raise FileNotFoundError(f"❌ Could not find {data_path}")

df = pd.read_csv(data_path)

print("✅ Loaded dataset:")
print(f"Total records: {len(df)}")
print(df.columns.tolist())
print(df.head(2))

# -------------------------------------------------------
# 2️⃣ Basic cleaning
# -------------------------------------------------------
df = df.dropna(how="all")

# Ensure consistent columns
expected_cols = [
    "cve_id", "description", "cpe_vendor", "cpe_product",
    "cpe_version", "cvss_version", "cvss_base_score",
    "cvss_vector", "published", "last_modified"
]

for col in expected_cols:
    if col not in df.columns:
        df[col] = np.nan

# Fill missing data
df["description"] = df["description"].fillna("No description provided.")
df["cpe_vendor"] = df["cpe_vendor"].fillna("unknown_vendor")
df["cpe_product"] = df["cpe_product"].fillna("unknown_product")
df["cpe_version"] = df["cpe_version"].fillna("unknown")

# Convert CVSS to numeric safely
df["cvss_base_score"] = pd.to_numeric(df["cvss_base_score"], errors="coerce").fillna(0)

# -------------------------------------------------------
# 3️⃣ Add/Derive Severity column if missing
# -------------------------------------------------------
if "severity" not in df.columns:
    print("🧩 Severity column not found — generating from CVSS base score...")
    def derive_severity(score):
        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        elif score > 0:
            return "LOW"
        else:
            return "UNKNOWN"
    df["severity"] = df["cvss_base_score"].apply(derive_severity)
else:
    df["severity"] = df["severity"].fillna("UNKNOWN").str.upper()

# -------------------------------------------------------
# 4️⃣ Encode categorical values
# -------------------------------------------------------
label_enc = LabelEncoder()
df["vendor_encoded"] = label_enc.fit_transform(df["cpe_vendor"].astype(str))
df["product_encoded"] = label_enc.fit_transform(df["cpe_product"].astype(str))
df["severity_encoded"] = label_enc.fit_transform(df["severity"].astype(str))

# -------------------------------------------------------
# 5️⃣ Select useful ML features
# -------------------------------------------------------
ml_df = df[[
    "cpe_vendor", "cpe_product", "cpe_version",
    "cvss_base_score", "severity",
    "vendor_encoded", "product_encoded", "severity_encoded"
]]

# -------------------------------------------------------
# 6️⃣ Save the ML-ready dataset
# -------------------------------------------------------
output_path = Path("data/processed/ml_ready_dataset.csv")
ml_df.to_csv(output_path, index=False)

print("\n✅ ML-ready dataset saved successfully!")
print(f"📁 Path: {output_path}")
print(f"📊 Total records: {len(ml_df)}")
print(ml_df.head(5))
