import pandas as pd
from src.cpe_mapper import to_cpe_format

def analyze_dependencies(deps, nvd_csv="data/processed/nvd_processed.csv"):
    df = pd.read_csv(nvd_csv)

    results = []
    for pkg, ver in deps:
        dep_cpe = to_cpe_format(pkg, ver)

        for _, row in df.iterrows():
            cpes = row["affected_cpes"]
            if isinstance(cpes, str) and pkg in cpes.lower():
                if ver and ver in cpes:
                    results.append({
                        "dependency": f"{pkg}=={ver}",
                        "cve_id": row["cve_id"],
                        "severity": row["severity"],
                        "score": row["cvss_score"],
                        "description": row["description"]
                    })
                elif not ver:
                    results.append({
                        "dependency": pkg,
                        "cve_id": row["cve_id"],
                        "severity": row["severity"],
                        "score": row["cvss_score"],
                        "description": row["description"]
                    })
            elif dep_cpe in str(cpes):
                results.append({
                    "dependency": f"{pkg}=={ver}" if ver else pkg,
                    "cve_id": row["cve_id"],
                    "severity": row["severity"],
                    "score": row["cvss_score"],
                    "description": row["description"]
                })

    return pd.DataFrame(results)
