"""
Dependency Vulnerability Mapper
--------------------------------
This script:
1. Reads project dependencies from requirements.txt
2. Maps each dependency to CPE entries in your preprocessed NVD dataset
3. Retrieves related CVEs, CVSS scores, and calculates severity
4. Outputs a vulnerability report as CSV inside data/processed/
"""

import pandas as pd
from pathlib import Path

# ---------------- Utility: severity mapping ----------------
def score_to_severity(score):
    try:
        score = float(score)
    except (TypeError, ValueError):
        return "UNKNOWN"
    if score < 4.0:
        return "LOW"
    elif score < 7.0:
        return "MEDIUM"
    elif score < 9.0:
        return "HIGH"
    else:
        return "CRITICAL"

# ---------------- Load dependencies ----------------
def load_requirements(req_path):
    pkgs = []
    with open(req_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "==" in line:
                name, version = line.split("==", 1)
            elif "=" in line:
                name, version = line.split("=", 1)
            else:
                name, version = line, ""
            pkgs.append({"package": name.lower().strip(), "version": version.strip()})
    return pd.DataFrame(pkgs)

# ---------------- Load CVE–CPE dataset ----------------
def load_cve_data(base_dir):
    path = base_dir / "data" / "processed" / "cve_cpe.csv"
    if not path.exists():
        raise FileNotFoundError(f"CVE data not found at {path}")
    df = pd.read_csv(path)
    # Normalize product names
    df["cpe_product"] = df["cpe_product"].fillna("").str.lower()
    df["cpe_vendor"] = df["cpe_vendor"].fillna("").str.lower()
    return df

# ---------------- Map dependencies to CVEs ----------------
def map_dependencies(req_df, cve_df):
    mapped_rows = []
    for _, dep in req_df.iterrows():
        pkg = dep["package"]
        version = dep["version"]
        # Find matching CPE entries by partial match
        matches = cve_df[cve_df["cpe_product"].str.contains(pkg, case=False, na=False)]
        if not matches.empty:
            matches = matches.copy()
            matches["req_package"] = pkg
            matches["req_version"] = version
            matches["severity"] = matches["cvss_base_score"].apply(score_to_severity)
            mapped_rows.append(matches)
        else:
            # No CVE found for this dependency
            mapped_rows.append(pd.DataFrame([{
                "req_package": pkg,
                "req_version": version,
                "cve_id": None,
                "cpe_vendor": None,
                "cpe_product": None,
                "cpe_version": None,
                "cvss_base_score": None,
                "severity": "UNKNOWN",
                "description": "No known CVEs found for this dependency."
            }]))
    return pd.concat(mapped_rows, ignore_index=True)

# ---------------- Main ----------------
def main():
    base_dir = Path(__file__).resolve().parents[1]
    req_path = base_dir / "requirements.txt"
    out_path = base_dir / "data" / "processed" / "dependency_vulnerability_report.csv"

    print("📦 Loading project dependencies...")
    req_df = load_requirements(req_path)
    print(f"Found {len(req_df)} dependencies.")

    print("🧠 Loading CVE–CPE dataset...")
    cve_df = load_cve_data(base_dir)
    print(f"Loaded {len(cve_df)} CVE entries from processed data.")

    print("🔍 Mapping dependencies to vulnerabilities...")
    mapped_df = map_dependencies(req_df, cve_df)

    # Reorder and save
    columns_order = [
        "req_package", "req_version", "cve_id", "cpe_vendor", "cpe_product", "cpe_version",
        "cvss_base_score", "severity", "description", "published", "last_modified"
    ]
    mapped_df = mapped_df[[c for c in columns_order if c in mapped_df.columns]]

    mapped_df.to_csv(out_path, index=False, encoding="utf-8")
    print(f"\n✅ Vulnerability report saved at:\n{out_path}")
    print(f"Total matched vulnerabilities: {mapped_df['cve_id'].notna().sum()}")
    print(f"Total dependencies scanned: {len(req_df)}")

# ---------------- Run ----------------
if __name__ == "__main__":
    main()
