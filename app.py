
import io
import json
from pathlib import Path

import pandas as pd
import streamlit as st
from scapy.all import rdpcap, IP, UDP, ESP

from analyzer import analyze_ipsec_capture, extract_flow_features, assess_ipsec_security_evidence
from report import build_html_report, build_pdf_report

st.set_page_config(page_title="IPsecGuard", page_icon="🛡️", layout="wide")
# IPsecGuard visual theme
st.markdown("""
<style>

    /* ===== IPSECGUARD COLOR SYSTEM =====
       Ultra Violet: #5B2A86
       Dark Violet:  #3E1F5B
       Soft Apricot: #F6B48F
       Light Apricot: #FDE4D4
       Background:   #FAF7FC
    */

    /* Main application background */
    .stApp {
        background: #FAF7FC;
        color: #211A26;
    }

    /* Main content */
    [data-testid="stAppViewContainer"] {
        background: #FAF7FC;
    }

    [data-testid="stMain"] {
        background: #FAF7FC;
    }

    /* Header */
    [data-testid="stHeader"] {
        background: rgba(250, 247, 252, 0.96);
    }

    /* Main title */
    h1 {
        color: #5B2A86 !important;
        font-weight: 700 !important;
        letter-spacing: -0.5px;
    }

    /* Section headings */
    h2, h3 {
        color: #3E1F5B !important;
        font-weight: 650 !important;
    }

    /* Normal text */
    p, li, label {
        color: #211A26;
    }

    /* Caption / secondary text */
    [data-testid="stCaptionContainer"] {
        color: #6F6575 !important;
    }

    /* Primary buttons */
    .stButton > button {
        border: 1px solid #5B2A86;
        border-radius: 8px;
        font-weight: 600;
        transition: all 0.2s ease;
    }

    .stButton > button[kind="primary"] {
        background: #5B2A86;
        color: white;
        border: 1px solid #5B2A86;
    }

    .stButton > button[kind="primary"]:hover {
        background: #3E1F5B;
        border-color: #3E1F5B;
    }

    /* Metric blocks */
    [data-testid="stMetric"] {
        background: white;
        border: 1px solid #DED3E8;
        border-left: 4px solid #5B2A86;
        border-radius: 8px;
        padding: 14px 16px;
    }

    [data-testid="stMetricLabel"] {
        color: #6F6575 !important;
    }

    [data-testid="stMetricValue"] {
        color: #5B2A86 !important;
        font-weight: 700 !important;
    }

    /* Expanders */
    [data-testid="stExpander"] {
        background: white;
        border: 1px solid #DED3E8;
        border-radius: 8px;
    }

    [data-testid="stExpander"] summary {
        color: #3E1F5B;
        font-weight: 600;
    }

    /* File uploader */
    [data-testid="stFileUploader"] {
        background: white;
        border: 1px dashed #BFA8D0;
        border-radius: 8px;
        padding: 8px;
    }

    /* Info message */
    [data-testid="stAlert"] {
        border-radius: 8px;
    }

    /* Code / endpoint areas */
    [data-testid="stCode"] {
        border-left: 3px solid #F6B48F;
    }

    /* Dataframes */
    [data-testid="stDataFrame"] {
        border: 1px solid #DED3E8;
        border-radius: 8px;
    }

    /* Download buttons */
    [data-testid="stDownloadButton"] button {
        background: #F6B48F;
        color: #3E1F5B;
        border: 1px solid #E8A078;
        border-radius: 8px;
        font-weight: 600;
    }

    [data-testid="stDownloadButton"] button:hover {
        background: #EFA477;
        border-color: #D98E68;
        color: #3E1F5B;
    }

    /* Links */
    a {
        color: #5B2A86 !important;
    }

    /* Horizontal separators */
    hr {
        border-color: #DED3E8;
    }

</style>
""", unsafe_allow_html=True)

BASE = Path(__file__).parent
DEMO_PCAP = BASE / "test_fixtures" / "capture.pcapng"

def analyze_bytes(data: bytes, filename: str):
    packets = rdpcap(io.BytesIO(data))
    if len(packets) == 0:
        raise ValueError("The capture is empty.")
    result = analyze_ipsec_capture(packets)
    result["filename"] = filename
    result["packet_count"] = len(packets)
    result["flow_features"] = extract_flow_features(packets)
    result["security_assessment"] = {
        "findings": assess_ipsec_security_evidence(result)
    }
    return result

def show_result(result):
    a = result
    ml = result.get("ml_classification", {})
    findings = result["security_assessment"]["findings"]

    st.success("Analysis complete.")

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Packets", result["packet_count"])
    c2.metric("IKE / ISAKMP", a["ike"]["packet_count"])
    c3.metric("ESP", a["esp"]["packet_count"])
    c4.metric("Observed SAs", len(a["security_associations"]))

    st.subheader("IPsec Overview")
    o1, o2 = st.columns(2)
    with o1:
        st.write("**IPsec detected:**", "YES" if a["ipsec_detected"] else "NO")
        st.write("**NAT-T detected:**", "YES" if a["transport"]["nat_t_detected"] else "NO")
        st.write("**UDP/4500 packets:**", a["transport"]["udp_4500_packets"])
    with o2:
        st.write("**Endpoints:**")
        for e in a["endpoints"]:
            st.code(f'{e["source"]}  →  {e["destination"]}')

    st.subheader("Protocol Composition")
    chart = pd.DataFrame({
        "Protocol": ["IKE / ISAKMP", "ESP", "Other"],
        "Packets": [
            a["ike"]["packet_count"],
            a["esp"]["packet_count"],
            max(result["packet_count"] - a["ike"]["packet_count"] - a["esp"]["packet_count"], 0)
        ]
    }).set_index("Protocol")
    st.bar_chart(chart)

    st.subheader("Security Assessment")
    for f in findings:
        icon = {"PASS":"✅", "WARNING":"⚠️", "UNKNOWN":"❔"}.get(f["status"], "•")
        with st.expander(f'{icon} {f["status"]} — {f["check"]}'):
            st.write(f["evidence"])

    st.subheader("Observed Security Associations")
    sa_rows = []
    for sa in a["security_associations"]:
        sa_rows.append({
            "Source": sa["source"],
            "Destination": sa["destination"],
            "SPI": sa["spi"],
            "Packets": sa["packet_count"],
            "Sequences": ", ".join(map(str, sa["sequence_numbers"]))
        })
    st.dataframe(pd.DataFrame(sa_rows), use_container_width=True, hide_index=True)

    st.subheader("Traffic Features")
    feats = result["flow_features"]
    for k in ["esp_packets","average_packet_size","min_packet_size","max_packet_size",
              "average_inter_arrival","flow_duration","flow_packets_per_second","flow_bytes_per_second"]:
        if k in feats:
            st.write(f"**{k.replace('_',' ').title()}:** {feats[k]}")

    st.subheader("ML Analysis")
    st.info(
        "Live ML inference is not enabled in this PoC. "
        "The results below are the recorded Colab experiment and are shown separately "
        "from the live packet analysis."
    )
    ml1, ml2 = st.columns(2)
    ml1.metric("Recorded status", ml.get("status", "UNKNOWN"))
    ml2.metric("Recorded confidence", f'{ml.get("confidence", 0.41):.0%}')
    st.write(ml.get("message", "Recorded Colab result: traffic class was not assigned because confidence was below the 60% threshold."))

    st.subheader("Report")
    html_bytes = build_html_report(result).encode("utf-8")
    pdf_bytes = build_pdf_report(result)
    r1, r2 = st.columns(2)
    r1.download_button("Download HTML Report", html_bytes, "ipsecguard_report.html", "text/html")
    r2.download_button("Download PDF Report", pdf_bytes, "ipsecguard_report.pdf", "application/pdf")

st.title("IPsecGuard")
st.caption("IPsec VPN Protocol Analyzer & Security Assessment Platform")
st.write("Analyze IPsec VPN captures, extract observable protocol evidence, assess security characteristics, and generate a report.")

with st.expander("How it works", expanded=True):
    st.write("**1. Provide a capture → 2. Analyze IPsec evidence → 3. Review security assessment → 4. Export report**")
    st.caption("Demo mode uses the bundled real IPsec/NAT-T sample capture. No external file is required.")

c1, c2 = st.columns(2)
with c1:
    if st.button("▶ TRY DEMO", use_container_width=True, type="primary"):
        if not DEMO_PCAP.exists():
            st.error("Bundled demo capture is missing.")
        else:
            st.session_state["result"] = analyze_bytes(DEMO_PCAP.read_bytes(), "capture.pcapng")
with c2:
    uploaded = st.file_uploader("Upload your own PCAP / PCAPNG", type=["pcap", "pcapng"])

if uploaded is not None:
    if st.button("Analyze Uploaded Capture", use_container_width=True):
        try:
            st.session_state["result"] = analyze_bytes(uploaded.getvalue(), uploaded.name)
        except Exception as e:
            st.error(f"Could not analyze the capture: {e}")

if "result" in st.session_state:
    show_result(st.session_state["result"])
else:
    st.info("Choose **TRY DEMO** to explore IPsecGuard immediately, or upload your own capture.")
