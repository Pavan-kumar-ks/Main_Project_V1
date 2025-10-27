"""
Streamlit Dashboard: AI-Powered Code Security & Dependency Risk Analyzer
------------------------------------------------------------------------
Visualizes AI predictions and allows interactive vulnerability analysis.
"""

import streamlit as st
import pandas as pd
import plotly.express as px
from pathlib import Path

# -------------------------------------------------------
# 1️⃣ Load the AI-predicted vulnerability report
# -------------------------------------------------------
data_path = Path("data/processed/ai_predicted_report.csv")

st.set_page_config(page_title="AI Code Security Dashboard", layout="wide")

st.title("🧠 AI-Powered Code Security & Dependency Risk Analyzer")
st.markdown("#### Visualize and analyze dependency vulnerabilities with AI-driven severity predictions")

if not data_path.exists():
    st.error("❌ Report file not found! Run `ai_dependency_analyzer.py` first.")
    st.stop()

df = pd.read_csv(data_path)

# Clean up and fill missing values
df = df.fillna("Unknown")
if "predicted_severity" not in df.columns:
    st.error("⚠️ No 'predicted_severity' column found in the dataset.")
    st.stop()

st.success(f"✅ Loaded {len(df)} dependencies for analysis.")

# -------------------------------------------------------
# 2️⃣ Filters and search
# -------------------------------------------------------
st.sidebar.header("🔍 Filters")
severity_filter = st.sidebar.multiselect(
    "Filter by Severity",
    options=sorted(df["predicted_severity"].unique()),
    default=sorted(df["predicted_severity"].unique())
)

search_query = st.sidebar.text_input("Search Dependency Name (product):", "")

filtered_df = df[df["predicted_severity"].isin(severity_filter)]
if search_query:
    filtered_df = filtered_df[filtered_df["cpe_product"].str.contains(search_query, case=False, na=False)]

# -------------------------------------------------------
# 3️⃣ Overview Stats
# -------------------------------------------------------
st.subheader("📊 Overview Metrics")
col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Dependencies", len(filtered_df))
col2.metric("Critical", (filtered_df["predicted_severity"] == "CRITICAL").sum())
col3.metric("High", (filtered_df["predicted_severity"] == "HIGH").sum())
col4.metric("Medium", (filtered_df["predicted_severity"] == "MEDIUM").sum())

# -------------------------------------------------------
# 4️⃣ Visualizations
# -------------------------------------------------------
st.subheader("📈 Vulnerability Severity Distribution")

severity_counts = filtered_df["predicted_severity"].value_counts().reset_index()
severity_counts.columns = ["Severity", "Count"]

fig_pie = px.pie(
    severity_counts,
    names="Severity",
    values="Count",
    color="Severity",
    color_discrete_sequence=px.colors.qualitative.Bold,
    title="Severity Distribution"
)
st.plotly_chart(fig_pie, use_container_width=True)

st.subheader("📊 Dependencies by Severity")
fig_bar = px.bar(
    severity_counts,
    x="Severity",
    y="Count",
    color="Severity",
    text="Count",
    color_discrete_sequence=px.colors.qualitative.Set2,
    title="Number of Dependencies by Severity"
)
fig_bar.update_traces(textposition="outside")
st.plotly_chart(fig_bar, use_container_width=True)

# -------------------------------------------------------
# 5️⃣ Data Table
# -------------------------------------------------------
st.subheader("📋 Detailed Dependency Report")
st.dataframe(filtered_df, use_container_width=True, height=450)

# -------------------------------------------------------
# 6️⃣ Export Options
# -------------------------------------------------------
st.subheader("💾 Export Results")
csv = filtered_df.to_csv(index=False).encode("utf-8")
st.download_button("⬇️ Download Filtered Report as CSV", csv, "filtered_vulnerability_report.csv", "text/csv")

st.caption("Developed by ⚙️ AI-Powered Code Security & Dependency Risk Analyzer Team")
