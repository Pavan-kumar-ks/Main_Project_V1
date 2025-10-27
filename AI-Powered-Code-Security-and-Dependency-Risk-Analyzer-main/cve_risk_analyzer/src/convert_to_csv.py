# src/convert_to_csv.py
import pandas as pd
from pathlib import Path

# Paths
BASE_DIR = Path(__file__).resolve().parents[1]
PARQUET_PATH = BASE_DIR / "data" / "processed" / "cve_cpe.parquet"
CSV_PATH = BASE_DIR / "data" / "processed" / "cve_cpe.csv"

print("📂 Reading processed Parquet file...")
try:
    df = pd.read_parquet(PARQUET_PATH)
except Exception as e:
    print(f"❌ Error reading Parquet file: {e}")
    raise SystemExit

# --- Clean & reorder columns for readability ---
columns_order = [
    "cve_id", "description", "cpe_vendor", "cpe_product", "cpe_version",
    "cvss_version", "cvss_base_score", "cvss_vector",
    "published", "last_modified"
]

# Keep only valid columns that exist
df = df[[c for c in columns_order if c in df.columns]]

# Optional: fill blanks for better CSV display
df.fillna("", inplace=True)

# --- Save as CSV ---
print("💾 Saving CSV file...")
df.to_csv(CSV_PATH, index=False, encoding="utf-8")

print(f"✅ CSV saved successfully at:\n{CSV_PATH}")
print(f"Total rows written: {len(df):,}")
