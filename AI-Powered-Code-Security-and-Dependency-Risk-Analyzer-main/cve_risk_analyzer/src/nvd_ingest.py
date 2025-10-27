# # src/nvd_ingest.py
# import gzip
# import ijson
# import pandas as pd
# from pathlib import Path
# import re
# from datetime import datetime
# from tqdm import tqdm

# # Output locations
# RAW_DIR = Path(__file__).resolve().parents[1] / "data" / "raw"
# OUT_DIR = Path(__file__).resolve().parents[1] / "data" / "processed"
# OUT_DIR.mkdir(parents=True, exist_ok=True)

# CPE_REGEX = re.compile(r"^cpe:2\.3:[aho]\:([^:]+)\:([^:]+)\:?([^:]*)")  # vendor,product,version (version optional)

# def parse_cpe_components(cpe_uri: str):
#     m = CPE_REGEX.match(cpe_uri)
#     if not m:
#         return None, None, None
#     vendor = m.group(1)
#     product = m.group(2)
#     version = m.group(3) if m.group(3) else None
#     return vendor, product, version

# def stream_cve_items(gzpath):
#     with gzip.open(gzpath, "rt", encoding="utf-8") as fh:
#         for item in ijson.items(fh, "CVE_Items.item"):
#             yield item

# def normalize_item_to_rows(item):
#     # returns list of rows (one per CPE) as dicts
#     cve_meta = item.get("cve", {}).get("CVE_data_meta", {})
#     cve_id = cve_meta.get("ID")
#     descs = item.get("cve", {}).get("description", {}).get("description_data", [])
#     desc = ""
#     for d in descs:
#         if d.get("lang", "").lower().startswith("en"):
#             desc = d.get("value", "")
#             break
#     if not desc and descs:
#         desc = descs[0].get("value", "")

#     # prefer CVSS v3
#     impact = item.get("impact", {})
#     cvss_ver = None; base_score = None; vector = None
#     if "baseMetricV3" in impact:
#         cvss_ver = "3"
#         base_score = impact["baseMetricV3"]["cvssV3"].get("baseScore")
#         vector = impact["baseMetricV3"]["cvssV3"].get("vectorString")
#     elif "baseMetricV2" in impact:
#         cvss_ver = "2"
#         base_score = impact["baseMetricV2"]["cvssV2"].get("baseScore")
#         vector = impact["baseMetricV2"]["cvssV2"].get("vectorString")

#     pub_date = item.get("publishedDate")
#     mod_date = item.get("lastModifiedDate")

#     # collect CPEs from configurations.nodes
#     cpe_uris = set()
#     def walk_node(node):
#         for m in node.get("cpe_match", []) or []:
#             cpe = m.get("cpe23Uri")
#             if cpe:
#                 cpe_uris.add(cpe)
#         for child in node.get("children", []) or []:
#             walk_node(child)

#     for node in item.get("configurations", {}).get("nodes", []):
#         walk_node(node)

#     if not cpe_uris:
#         # yield single row without cpe
#         return [{
#             "cve_id": cve_id,
#             "description": desc,
#             "cpe_uri": None,
#             "cpe_vendor": None,
#             "cpe_product": None,
#             "cpe_version": None,
#             "cvss_version": cvss_ver,
#             "cvss_base_score": base_score,
#             "cvss_vector": vector,
#             "published": pub_date,
#             "last_modified": mod_date
#         }]
#     rows = []
#     for c in cpe_uris:
#         vendor, product, version = parse_cpe_components(c)
#         rows.append({
#             "cve_id": cve_id,
#             "description": desc,
#             "cpe_uri": c,
#             "cpe_vendor": vendor,
#             "cpe_product": product,
#             "cpe_version": version,
#             "cvss_version": cvss_ver,
#             "cvss_base_score": base_score,
#             "cvss_vector": vector,
#             "published": pub_date,
#             "last_modified": mod_date
#         })
#     return rows

# def ingest_all(input_dir=RAW_DIR, out_parquet=OUT_DIR/"cve_cpe.parquet", cpe_csv=OUT_DIR/"unique_cpes.csv", batch_size=20000):
#     # glob may return directories (e.g. a folder named 'nvdcve-2.0-2025.json/'),
#     # so only include regular files to avoid PermissionError when opening.
#     gz_files = sorted([p for p in Path(input_dir).glob("*.json*") if p.is_file()])
#     if not gz_files:
#         raise SystemExit(f"No files in {input_dir} - place nvdcve JSON(.gz) files there.")
#     first_write = True
#     buffer = []
#     unique_cpes = set()

#     for gz in gz_files:
#         print("Processing", gz.name)
#         for item in tqdm(stream_cve_items(gz), desc=gz.name):
#             rows = normalize_item_to_rows(item)
#             for r in rows:
#                 buffer.append(r)
#                 if r.get("cpe_uri"):
#                     unique_cpes.add(r["cpe_uri"])
#             if len(buffer) >= batch_size:
#                 df = pd.DataFrame(buffer)
#                 if first_write:
#                     df.to_parquet(out_parquet, index=False)
#                     first_write = False
#                 else:
#                     # append by reading and concatenating (simple approach)
#                     existing = pd.read_parquet(out_parquet)
#                     pd.concat([existing, df], ignore_index=True).to_parquet(out_parquet, index=False)
#                 buffer = []

#     # flush remainder
#     if buffer:
#         df = pd.DataFrame(buffer)
#         if first_write:
#             df.to_parquet(out_parquet, index=False)
#         else:
#             existing = pd.read_parquet(out_parquet)
#             pd.concat([existing, df], ignore_index=True).to_parquet(out_parquet, index=False)

#     # write unique cpes
#     pd.DataFrame(sorted(unique_cpes), columns=["cpe_uri"]).to_csv(cpe_csv, index=False)
#     print("Wrote", out_parquet, "and", cpe_csv)

# if __name__ == "__main__":
#     ingest_all()





















# src/nvd_ingest.py  (updated version supporting NVD 1.1 + 2.0)
# import gzip, ijson, pandas as pd, re
# from pathlib import Path
# from tqdm import tqdm

# RAW_DIR = Path(__file__).resolve().parents[1] / "data" / "raw"
# OUT_DIR = Path(__file__).resolve().parents[1] / "data" / "processed"
# OUT_DIR.mkdir(parents=True, exist_ok=True)

# CPE_REGEX = re.compile(r"^cpe:2\.3:[aho]\:([^:]+)\:([^:]+)\:?([^:]*)")

# def parse_cpe_components(cpe_uri: str):
#     m = CPE_REGEX.match(cpe_uri or "")
#     if not m: return None, None, None
#     return m.group(1), m.group(2), m.group(3) if m.group(3) else None

# def detect_feed_type(gzpath):
#     open_func = gzip.open if str(gzpath).endswith(".gz") else open
#     with open_func(gzpath, "rt", encoding="utf-8") as fh:
#         first_kv = ijson.kvitems(fh, "", 1)
#         for k, v in first_kv:
#             if k == "CVE_Items":
#                 return "1.1"
#             if k == "vulnerabilities":
#                 return "2.0"
#     return "unknown"

# def iterate_items(gzpath, feed_type):
#     open_func = gzip.open if str(gzpath).endswith(".gz") else open
#     with open_func(gzpath, "rt", encoding="utf-8") as fh:

#         prefix = "CVE_Items.item" if feed_type == "1.1" else "vulnerabilities.item"
#         for item in ijson.items(fh, prefix):
#             yield item

# def normalize_item(item, feed_type):
#     if feed_type == "2.0":
#         cve = item.get("cve", {})
#         cve_id = cve.get("id")
#         desc = cve.get("descriptions", [{}])[0].get("value", "")
#         metrics = cve.get("metrics", {})
#         base_score = None; cvss_ver = None; vector = None
#         if "cvssMetricV31" in metrics:
#             m = metrics["cvssMetricV31"][0]["cvssData"]
#             base_score, cvss_ver, vector = m["baseScore"], "3.1", m["vectorString"]
#         elif "cvssMetricV30" in metrics:
#             m = metrics["cvssMetricV30"][0]["cvssData"]
#             base_score, cvss_ver, vector = m["baseScore"], "3.0", m["vectorString"]
#         elif "cvssMetricV2" in metrics:
#             m = metrics["cvssMetricV2"][0]["cvssData"]
#             base_score, cvss_ver, vector = m["baseScore"], "2.0", m["vectorString"]
#         pub_date = cve.get("published")
#         mod_date = cve.get("lastModified")
#         configs = cve.get("configurations", [])
#         cpe_uris = set()
#         for node in configs:
#             for match in node.get("nodes", []):
#                 for cpe in match.get("cpeMatch", []):
#                     uri = cpe.get("criteria")
#                     if uri: cpe_uris.add(uri)
#         rows = []
#         if not cpe_uris:
#             rows.append(dict(cve_id=cve_id, description=desc, cpe_uri=None,
#                              cpe_vendor=None, cpe_product=None, cpe_version=None,
#                              cvss_version=cvss_ver, cvss_base_score=base_score,
#                              cvss_vector=vector, published=pub_date,
#                              last_modified=mod_date))
#         else:
#             for c in cpe_uris:
#                 v, p, ver = parse_cpe_components(c)
#                 rows.append(dict(cve_id=cve_id, description=desc, cpe_uri=c,
#                                  cpe_vendor=v, cpe_product=p, cpe_version=ver,
#                                  cvss_version=cvss_ver, cvss_base_score=base_score,
#                                  cvss_vector=vector, published=pub_date,
#                                  last_modified=mod_date))
#         return rows

#     # ---- legacy v1.1 ----
#     cve_meta = item.get("cve", {}).get("CVE_data_meta", {})
#     cve_id = cve_meta.get("ID")
#     desc = ""
#     for d in item.get("cve", {}).get("description", {}).get("description_data", []):
#         if d.get("lang", "").lower().startswith("en"):
#             desc = d.get("value", "")
#             break
#     impact = item.get("impact", {})
#     base_score = None; cvss_ver = None; vector = None
#     if "baseMetricV3" in impact:
#         m = impact["baseMetricV3"]["cvssV3"]
#         base_score, cvss_ver, vector = m.get("baseScore"), "3.0", m.get("vectorString")
#     elif "baseMetricV2" in impact:
#         m = impact["baseMetricV2"]["cvssV2"]
#         base_score, cvss_ver, vector = m.get("baseScore"), "2.0", m.get("vectorString")
#     pub_date = item.get("publishedDate")
#     mod_date = item.get("lastModifiedDate")
#     cpe_uris = set()
#     def collect_nodes(node):
#         for m in node.get("cpe_match", []) or []:
#             uri = m.get("cpe23Uri")
#             if uri: cpe_uris.add(uri)
#         for child in node.get("children", []) or []:
#             collect_nodes(child)
#     for n in item.get("configurations", {}).get("nodes", []):
#         collect_nodes(n)
#     rows = []
#     if not cpe_uris:
#         rows.append(dict(cve_id=cve_id, description=desc, cpe_uri=None,
#                          cpe_vendor=None, cpe_product=None, cpe_version=None,
#                          cvss_version=cvss_ver, cvss_base_score=base_score,
#                          cvss_vector=vector, published=pub_date,
#                          last_modified=mod_date))
#     else:
#         for c in cpe_uris:
#             v, p, ver = parse_cpe_components(c)
#             rows.append(dict(cve_id=cve_id, description=desc, cpe_uri=c,
#                              cpe_vendor=v, cpe_product=p, cpe_version=ver,
#                              cvss_version=cvss_ver, cvss_base_score=base_score,
#                              cvss_vector=vector, published=pub_date,
#                              last_modified=mod_date))
#     return rows

# def ingest_all():
#     gz_files = sorted(RAW_DIR.glob("*.json*"))
#     if not gz_files:
#         print("No NVD files found in", RAW_DIR)
#         return
#     all_rows = []
#     unique_cpes = set()
#     for gz in gz_files:
#         ftype = detect_feed_type(gz)
#         print(f"Processing {gz.name} (detected schema {ftype})")
#         for item in tqdm(iterate_items(gz, ftype), desc=gz.name):
#             rows = normalize_item(item, ftype)
#             for r in rows:
#                 all_rows.append(r)
#                 if r["cpe_uri"]: unique_cpes.add(r["cpe_uri"])
#     if all_rows:
#         df = pd.DataFrame(all_rows)
#         out_parquet = OUT_DIR / "cve_cpe.parquet"
#         out_csv = OUT_DIR / "unique_cpes.csv"
#         df.to_parquet(out_parquet, index=False)
#         pd.DataFrame(sorted(unique_cpes), columns=["cpe_uri"]).to_csv(out_csv, index=False)
#         print("✅ Wrote", out_parquet, "and", out_csv)
#     else:
#         print("⚠️ No CVE items parsed. Check feed format or script logic.")

# if __name__ == "__main__":
#     ingest_all()












# import gzip
# import ijson
# import pandas as pd
# import re
# from pathlib import Path
# from tqdm import tqdm

# # ---------- PATH CONFIG ----------
# RAW_DIR = Path(__file__).resolve().parents[1] / "data" / "raw"
# OUT_DIR = Path(__file__).resolve().parents[1] / "data" / "processed"
# OUT_DIR.mkdir(parents=True, exist_ok=True)

# CPE_REGEX = re.compile(r"^cpe:2\.3:[aho]\:([^:]+)\:([^:]+)\:?([^:]*)")

# # ---------- SAFE OPEN FUNCTION ----------
# def safe_open(gzpath):
#     """
#     Automatically detect and open JSON or JSON.GZ safely.
#     Prevents PermissionError on Windows.
#     """
#     gzpath = Path(gzpath)
#     if str(gzpath).endswith(".gz"):
#         return gzip.open(gzpath, "rt", encoding="utf-8")
#     else:
#         return open(gzpath, "r", encoding="utf-8")

# # ---------- CPE PARSER ----------
# def parse_cpe_components(cpe_uri: str):
#     m = CPE_REGEX.match(cpe_uri or "")
#     if not m:
#         return None, None, None
#     return m.group(1), m.group(2), m.group(3) if m.group(3) else None

# # ---------- DETECT FEED TYPE ----------
# def detect_feed_type(json_path):
#     with safe_open(json_path) as fh:
#         try:
#             for k, _ in ijson.kvitems(fh, "", 1):
#                 if k == "CVE_Items":
#                     return "1.1"
#                 elif k == "vulnerabilities":
#                     return "2.0"
#         except Exception:
#             pass
#     return "unknown"

# # ---------- ITERATE ITEMS ----------
# def iterate_items(json_path, feed_type):
#     with safe_open(json_path) as fh:
#         prefix = "CVE_Items.item" if feed_type == "1.1" else "vulnerabilities.item"
#         for item in ijson.items(fh, prefix):
#             yield item

# # ---------- NORMALIZE A SINGLE ITEM ----------
# def normalize_item(item, feed_type):
#     # ---------- For NVD 2.0 feed ----------
#     if feed_type == "2.0":
#         cve = item.get("cve", {})
#         cve_id = cve.get("id")
        
#         # --- Description ---
#         desc = ""
#         for d in cve.get("descriptions", []):
#             if d.get("lang") == "en":
#                 desc = d.get("value", "")
#                 break

#         # --- CVSS metrics ---
#         metrics = cve.get("metrics", {})
#         base_score, cvss_ver, vector = None, None, None
#         if "cvssMetricV31" in metrics:
#             m = metrics["cvssMetricV31"][0]["cvssData"]
#             base_score, cvss_ver, vector = m["baseScore"], "3.1", m["vectorString"]
#         elif "cvssMetricV30" in metrics:
#             m = metrics["cvssMetricV30"][0]["cvssData"]
#             base_score, cvss_ver, vector = m["baseScore"], "3.0", m["vectorString"]
#         elif "cvssMetricV2" in metrics:
#             m = metrics["cvssMetricV2"][0]["cvssData"]
#             base_score, cvss_ver, vector = m["baseScore"], "2.0", m["vectorString"]

#         pub_date = cve.get("published")
#         mod_date = cve.get("lastModified")

#         # --- Configurations / CPE URIs ---
#         cpe_uris = set()
#         configs = cve.get("configurations", [])
#         for config in configs:
#             for node in config.get("nodes", []):
#                 # Some nodes have cpeMatch directly
#                 for match in node.get("cpeMatch", []):
#                     if match.get("criteria"):
#                         cpe_uris.add(match["criteria"])
#                 # Some nodes have nested children
#                 for child in node.get("children", []):
#                     for match in child.get("cpeMatch", []):
#                         if match.get("criteria"):
#                             cpe_uris.add(match["criteria"])

#         # Build rows
#         rows = []
#         if not cpe_uris:
#             rows.append({
#                 "cve_id": cve_id, "description": desc, "cpe_uri": None,
#                 "cpe_vendor": None, "cpe_product": None, "cpe_version": None,
#                 "cvss_version": cvss_ver, "cvss_base_score": base_score,
#                 "cvss_vector": vector, "published": pub_date,
#                 "last_modified": mod_date
#             })
#         else:
#             for c in cpe_uris:
#                 v, p, ver = parse_cpe_components(c)
#                 rows.append({
#                     "cve_id": cve_id, "description": desc, "cpe_uri": c,
#                     "cpe_vendor": v, "cpe_product": p, "cpe_version": ver,
#                     "cvss_version": cvss_ver, "cvss_base_score": base_score,
#                     "cvss_vector": vector, "published": pub_date,
#                     "last_modified": mod_date
#                 })
#         return rows

#     # ---------- For NVD 1.1 feed ----------
#     cve_meta = item.get("cve", {}).get("CVE_data_meta", {})
#     cve_id = cve_meta.get("ID")
#     desc = ""
#     for d in item.get("cve", {}).get("description", {}).get("description_data", []):
#         if d.get("lang", "").lower().startswith("en"):
#             desc = d.get("value", "")
#             break

#     impact = item.get("impact", {})
#     base_score, cvss_ver, vector = None, None, None
#     if "baseMetricV3" in impact:
#         m = impact["baseMetricV3"]["cvssV3"]
#         base_score, cvss_ver, vector = m.get("baseScore"), "3.0", m.get("vectorString")
#     elif "baseMetricV2" in impact:
#         m = impact["baseMetricV2"]["cvssV2"]
#         base_score, cvss_ver, vector = m.get("baseScore"), "2.0", m.get("vectorString")

#     pub_date = item.get("publishedDate")
#     mod_date = item.get("lastModifiedDate")

#     cpe_uris = set()
#     def collect_nodes(node):
#         for m in node.get("cpe_match", []) or []:
#             uri = m.get("cpe23Uri")
#             if uri:
#                 cpe_uris.add(uri)
#         for child in node.get("children", []) or []:
#             collect_nodes(child)

#     for n in item.get("configurations", {}).get("nodes", []):
#         collect_nodes(n)

#     rows = []
#     if not cpe_uris:
#         rows.append({
#             "cve_id": cve_id, "description": desc, "cpe_uri": None,
#             "cpe_vendor": None, "cpe_product": None, "cpe_version": None,
#             "cvss_version": cvss_ver, "cvss_base_score": base_score,
#             "cvss_vector": vector, "published": pub_date,
#             "last_modified": mod_date
#         })
#     else:
#         for c in cpe_uris:
#             v, p, ver = parse_cpe_components(c)
#             rows.append({
#                 "cve_id": cve_id, "description": desc, "cpe_uri": c,
#                 "cpe_vendor": v, "cpe_product": p, "cpe_version": ver,
#                 "cvss_version": cvss_ver, "cvss_base_score": base_score,
#                 "cvss_vector": vector, "published": pub_date,
#                 "last_modified": mod_date
#             })
#     return rows


#     # ---------- LEGACY 1.1 ----------
#     cve_meta = item.get("cve", {}).get("CVE_data_meta", {})
#     cve_id = cve_meta.get("ID")
#     desc = ""
#     for d in item.get("cve", {}).get("description", {}).get("description_data", []):
#         if d.get("lang", "").lower().startswith("en"):
#             desc = d.get("value", "")
#             break

#     impact = item.get("impact", {})
#     base_score, cvss_ver, vector = None, None, None
#     if "baseMetricV3" in impact:
#         m = impact["baseMetricV3"]["cvssV3"]
#         base_score, cvss_ver, vector = m.get("baseScore"), "3.0", m.get("vectorString")
#     elif "baseMetricV2" in impact:
#         m = impact["baseMetricV2"]["cvssV2"]
#         base_score, cvss_ver, vector = m.get("baseScore"), "2.0", m.get("vectorString")

#     pub_date = item.get("publishedDate")
#     mod_date = item.get("lastModifiedDate")

#     cpe_uris = set()

#     def collect_nodes(node):
#         for m in node.get("cpe_match", []) or []:
#             uri = m.get("cpe23Uri")
#             if uri:
#                 cpe_uris.add(uri)
#         for child in node.get("children", []) or []:
#             collect_nodes(child)

#     for n in item.get("configurations", {}).get("nodes", []):
#         collect_nodes(n)

#     rows = []
#     if not cpe_uris:
#         rows.append(dict(
#             cve_id=cve_id, description=desc, cpe_uri=None,
#             cpe_vendor=None, cpe_product=None, cpe_version=None,
#             cvss_version=cvss_ver, cvss_base_score=base_score,
#             cvss_vector=vector, published=pub_date,
#             last_modified=mod_date
#         ))
#     else:
#         for c in cpe_uris:
#             v, p, ver = parse_cpe_components(c)
#             rows.append(dict(
#                 cve_id=cve_id, description=desc, cpe_uri=c,
#                 cpe_vendor=v, cpe_product=p, cpe_version=ver,
#                 cvss_version=cvss_ver, cvss_base_score=base_score,
#                 cvss_vector=vector, published=pub_date,
#                 last_modified=mod_date
#             ))
#     return rows

# # ---------- MAIN INGEST ----------
# def ingest_all():
#     gz_files = sorted(RAW_DIR.glob("*.json*"))
#     if not gz_files:
#         print(f"No files found in {RAW_DIR}")
#         return

#     all_rows = []
#     unique_cpes = set()

#     for gz in gz_files:
#         ftype = detect_feed_type(gz)
#         print(f"Processing {gz.name} (detected schema {ftype})")
#         for item in tqdm(iterate_items(gz, ftype), desc=gz.name):
#             rows = normalize_item(item, ftype)
#             for r in rows:
#                 all_rows.append(r)
#                 if r["cpe_uri"]:
#                     unique_cpes.add(r["cpe_uri"])

#     if all_rows:
#         df = pd.DataFrame(all_rows)
#         out_parquet = OUT_DIR / "cve_cpe.parquet"
#         out_csv = OUT_DIR / "unique_cpes.csv"
#         df.to_parquet(out_parquet, index=False)
#         pd.DataFrame(sorted(unique_cpes), columns=["cpe_uri"]).to_csv(out_csv, index=False)
#         print(f"\n✅ Wrote:\n{out_parquet}\n{out_csv}")
#         print(f"Total CVE entries: {len(df):,}")
#     else:
#         print("⚠️ No CVE items parsed. Check feed format or file content.")

# # ---------- ENTRY POINT ----------
# if __name__ == "__main__":
#     ingest_all()


























import json
import gzip
import pandas as pd
from pathlib import Path
from tqdm import tqdm

# ---------------- Utility: Safe open for .gz or .json ----------------
def safe_open(gzpath):
    if str(gzpath).endswith(".gz"):
        return gzip.open(gzpath, "rt", encoding="utf-8")
    return open(gzpath, "r", encoding="utf-8")

# ---------------- Parse CPE URI into components ----------------
def parse_cpe_components(cpe_uri):
    # Example: cpe:2.3:a:microsoft:edge:124.0.1:*:*:*:*:*:*:*
    try:
        parts = cpe_uri.split(":")
        vendor = parts[3] if len(parts) > 3 else ""
        product = parts[4] if len(parts) > 4 else ""
        version = parts[5] if len(parts) > 5 else ""
        return vendor, product, version
    except Exception:
        return "", "", ""

# ---------------- Detect feed version ----------------
def detect_feed_type(json_path):
    with safe_open(json_path) as fh:
        data = json.load(fh)
    if "vulnerabilities" in data:
        return "2.0"
    elif "CVE_Items" in data:
        return "1.1"
    else:
        return "unknown"

# ---------------- Iterate through items ----------------
def iterate_items(json_path, feed_type):
    with safe_open(json_path) as fh:
        data = json.load(fh)

    if "CVE_Items" in data:
        items = data["CVE_Items"]
    elif "vulnerabilities" in data:
        items = data["vulnerabilities"]
    else:
        print(f"⚠️ Unknown feed structure in {json_path}")
        return

    for item in tqdm(items, desc=json_path.name):
        yield item

# ---------------- Normalize single CVE entry ----------------
def normalize_item(item, feed_type="auto"):
    # --- NVD 2.0 feeds ---
    if "cve" in item and "id" in item["cve"]:
        cve = item["cve"]
        cve_id = cve.get("id", "")
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break

        # CVSS metrics
        metrics = cve.get("metrics", {})
        base_score, cvss_ver, vector = None, None, None
        for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if key in metrics:
                metric = metrics[key][0]["cvssData"]
                base_score = metric.get("baseScore")
                vector = metric.get("vectorString")
                cvss_ver = (
                    "3.1" if "V31" in key else "3.0" if "V30" in key else "2.0"
                )
                break

        pub_date = cve.get("published")
        mod_date = cve.get("lastModified")

        # Collect CPEs
        cpe_uris = set()
        for cfg in cve.get("configurations", []):
            for node in cfg.get("nodes", []):
                for m in node.get("cpeMatch", []):
                    uri = m.get("criteria")
                    if uri:
                        cpe_uris.add(uri)
                for child in node.get("children", []):
                    for m in child.get("cpeMatch", []):
                        uri = m.get("criteria")
                        if uri:
                            cpe_uris.add(uri)

        rows = []
        if not cpe_uris:
            rows.append({
                "cve_id": cve_id,
                "description": desc,
                "cpe_vendor": "",
                "cpe_product": "",
                "cpe_version": "",
                "cvss_version": cvss_ver,
                "cvss_base_score": base_score,
                "cvss_vector": vector,
                "published": pub_date,
                "last_modified": mod_date
            })
        else:
            for uri in cpe_uris:
                v, p, ver = parse_cpe_components(uri)
                rows.append({
                    "cve_id": cve_id,
                    "description": desc,
                    "cpe_vendor": v,
                    "cpe_product": p,
                    "cpe_version": ver,
                    "cvss_version": cvss_ver,
                    "cvss_base_score": base_score,
                    "cvss_vector": vector,
                    "published": pub_date,
                    "last_modified": mod_date
                })
        return rows

    # --- NVD 1.1 feeds (legacy) ---
    cve_meta = item.get("cve", {}).get("CVE_data_meta", {})
    cve_id = cve_meta.get("ID", "")
    desc = ""
    for d in item.get("cve", {}).get("description", {}).get("description_data", []):
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break

    impact = item.get("impact", {})
    base_score, cvss_ver, vector = None, None, None
    if "baseMetricV3" in impact:
        m = impact["baseMetricV3"]["cvssV3"]
        base_score, cvss_ver, vector = m.get("baseScore"), "3.0", m.get("vectorString")
    elif "baseMetricV2" in impact:
        m = impact["baseMetricV2"]["cvssV2"]
        base_score, cvss_ver, vector = m.get("baseScore"), "2.0", m.get("vectorString")

    pub_date = item.get("publishedDate")
    mod_date = item.get("lastModifiedDate")

    cpe_uris = set()
    for n in item.get("configurations", {}).get("nodes", []):
        for m in n.get("cpe_match", []):
            uri = m.get("cpe23Uri")
            if uri:
                cpe_uris.add(uri)
        for child in n.get("children", []):
            for m in child.get("cpe_match", []):
                uri = m.get("cpe23Uri")
                if uri:
                    cpe_uris.add(uri)

    rows = []
    for uri in cpe_uris:
        v, p, ver = parse_cpe_components(uri)
        rows.append({
            "cve_id": cve_id,
            "description": desc,
            "cpe_vendor": v,
            "cpe_product": p,
            "cpe_version": ver,
            "cvss_version": cvss_ver,
            "cvss_base_score": base_score,
            "cvss_vector": vector,
            "published": pub_date,
            "last_modified": mod_date
        })
    return rows

# ---------------- Main ingest function ----------------
def ingest_all():
    base_dir = Path(__file__).resolve().parents[1]
    raw_dir = base_dir / "data" / "raw"
    processed_dir = base_dir / "data" / "processed"
    processed_dir.mkdir(parents=True, exist_ok=True)

    all_rows = []

    for gzpath in raw_dir.glob("nvdcve-*.json*"):
        print(f"Processing {gzpath.name}")
        ftype = detect_feed_type(gzpath)
        for item in iterate_items(gzpath, ftype):
            try:
                rows = normalize_item(item, ftype)
                if rows:
                    all_rows.extend(rows)
            except Exception as e:
                print(f"⚠️ Skipping item due to error: {e}")

    # Build DataFrame
    df = pd.DataFrame(all_rows)
    print(f"\n✅ Total CVE entries: {len(df):,}")

    # Save Parquet
    parquet_path = processed_dir / "cve_cpe.parquet"
    df.to_parquet(parquet_path, index=False)

    # Save CSV
    csv_path = processed_dir / "cve_cpe.csv"
    df.to_csv(csv_path, index=False, encoding="utf-8")

    # Save unique CPEs
    unique_cpes = df[["cpe_vendor", "cpe_product", "cpe_version"]].drop_duplicates()
    unique_csv = processed_dir / "unique_cpes.csv"
    unique_cpes.to_csv(unique_csv, index=False)

    print(f"\n✅ Wrote:\n{parquet_path}\n{csv_path}\n{unique_csv}")

# ---------------- Entry point ----------------
if __name__ == "__main__":
    ingest_all()
