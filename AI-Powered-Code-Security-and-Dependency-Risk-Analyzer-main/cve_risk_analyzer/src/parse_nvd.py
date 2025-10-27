import json, pandas as pd, os

def parse_nvd_feed(json_file, output="data/processed/nvd_processed.csv"):
    with open(json_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    records = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})

        # CVE ID
        cve_id = cve.get("id", "")

        # Description (English only)
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break

        # CWE(s)
        cwe = ""
        try:
            weaknesses = cve.get("weaknesses", [])
            cwe = ";".join([w["description"][0]["value"] for w in weaknesses if "description" in w])
        except:
            pass

        # Severity & Score (CVSS v3.1 preferred, fallback v2 or v4)
        severity, score = "", None
        metrics = cve.get("metrics", {})

        if "cvssMetricV31" in metrics:
            m = metrics["cvssMetricV31"][0]["cvssData"]
            severity, score = m.get("baseSeverity", ""), m.get("baseScore", None)
        elif "cvssMetricV40" in metrics:
            m = metrics["cvssMetricV40"][0]["cvssData"]
            severity, score = m.get("baseSeverity", ""), m.get("baseScore", None)
        elif "cvssMetricV2" in metrics:
            m = metrics["cvssMetricV2"][0]["cvssData"]
            severity, score = metrics["cvssMetricV2"][0].get("baseSeverity", ""), m.get("baseScore", None)

        # Affected software (CPEs)
        cpes = []
        for conf in cve.get("configurations", []):
            for node in conf.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    cpes.append(match.get("criteria"))

        records.append({
            "cve_id": cve_id,
            "description": desc,
            "cwe": cwe,
            "severity": severity,
            "cvss_score": score,
            "affected_cpes": "; ".join(cpes)
        })

    df = pd.DataFrame(records)
    os.makedirs("data/processed", exist_ok=True)
    df.to_csv(output, index=False)
    print(f"✅ Saved {len(df)} CVEs to {output}")
    return df
