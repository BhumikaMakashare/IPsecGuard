
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

.stApp {
    background:
        radial-gradient(
            ellipse 55% 38% at 8% 8%,
            rgba(80, 45, 85, 0.13),
            transparent 72%
        ),
        radial-gradient(
            ellipse 48% 42% at 92% 18%,
            rgba(147, 80, 115, 0.10),
            transparent 72%
        ),
        radial-gradient(
            ellipse 55% 45% at 72% 82%,
            rgba(80, 45, 85, 0.08),
            transparent 75%
        ),
        radial-gradient(
            ellipse 42% 38% at 18% 88%,
            rgba(147, 80, 115, 0.07),
            transparent 75%
        ),
        #F8F4E9;

    color: #502D55;
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
