import streamlit as st
import pandas as pd
import joblib
from scipy.sparse import hstack
from pathlib import Path

# -------------------------------------------------------------
# Load Model and Encoders
# -------------------------------------------------------------
@st.cache_resource
def load_model_components():
    model_dir = Path("data/processed/model")
    model = joblib.load(model_dir / "trained_model_v2.pkl")
    tfidf = joblib.load(model_dir / "tfidf_vectorizer.pkl")
    vendor_enc = joblib.load(model_dir / "vendor_encoder.pkl")
    product_enc = joblib.load(model_dir / "product_encoder.pkl")
    severity_enc = joblib.load(model_dir / "severity_encoder.pkl")
    return model, tfidf, vendor_enc, product_enc, severity_enc

model, tfidf, vendor_enc, product_enc, severity_enc = load_model_components()

st.set_page_config(page_title="AI-Powered CVE Severity Analyzer", layout="wide")
st.title("🧠 AI-Powered CVE & Dependency Severity Analyzer")
st.markdown("Analyze project dependencies or predict severity for new vulnerabilities using the trained ML model.")

# -------------------------------------------------------------
# Helper Encoding Function
# -------------------------------------------------------------
def safe_encode(encoder, value):
    if value in encoder.classes_:
        return encoder.transform([value])[0]
    else:
        return -1  # unseen category

# -------------------------------------------------------------
# Section 1: Upload and Analyze Dependencies
# -------------------------------------------------------------
st.header("📦 Analyze Dependencies from `requirements.txt`")

uploaded_file = st.file_uploader("Upload your requirements.txt file", type=["txt"])
if uploaded_file:
    content = uploaded_file.read().decode("utf-8").splitlines()
    df_req = pd.DataFrame({"dependency": content})
    st.write("Detected dependencies:", df_req)

    # Dummy mapping for now (can link to dependency_mapper output)
    df_req["cpe_vendor"] = "unknown_vendor"
    df_req["cpe_product"] = df_req["dependency"]
    df_req["cvss_base_score"] = 0.0
    df_req["description"] = "No description available. Model will predict severity based on name only."

    # Encode
    df_req["vendor_encoded"] = df_req["cpe_vendor"].apply(lambda x: safe_encode(vendor_enc, x))
    df_req["product_encoded"] = df_req["cpe_product"].apply(lambda x: safe_encode(product_enc, x))

    X_text = tfidf.transform(df_req["description"])
    X_struct = df_req[["vendor_encoded", "product_encoded", "cvss_base_score"]].values
    X_combined = hstack([X_struct, X_text])

    preds = model.predict(X_combined)
    df_req["predicted_severity"] = severity_enc.inverse_transform(preds)

    st.subheader("🛡️ Predicted Severity for Dependencies")
    st.dataframe(df_req[["dependency", "predicted_severity"]], use_container_width=True)

# -------------------------------------------------------------
# Section 2: Manual Vulnerability Prediction
# -------------------------------------------------------------
st.header("🧩 Predict Severity for a New Vulnerability")

col1, col2 = st.columns(2)
with col1:
    vendor = st.text_input("Vendor", "djangoproject")
    product = st.text_input("Product", "django")
    cvss_score = st.number_input("Base CVSS Score (optional)", 0.0, 10.0, 0.0)
with col2:
    description = st.text_area("Vulnerability Description", 
        "SQL injection in login module allows attackers to modify database queries.")

if st.button("🔮 Predict Severity"):
    v_enc = safe_encode(vendor_enc, vendor)
    p_enc = safe_encode(product_enc, product)
    X_text = tfidf.transform([description])
    X_struct = [[v_enc, p_enc, cvss_score]]
    X_combined = hstack([X_struct, X_text])

    pred_encoded = model.predict(X_combined)
    severity = severity_enc.inverse_transform(pred_encoded)[0]

    st.success(f"### 🧠 Predicted Severity: **{severity}**")

# -------------------------------------------------------------
# Footer
# -------------------------------------------------------------
st.markdown("---")
st.markdown("Developed with ❤️ using AI-Powered Code Security & Dependency Risk Analyzer")
