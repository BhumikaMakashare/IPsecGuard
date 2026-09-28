
from html import escape
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from io import BytesIO

def build_html_report(result):
    a = result["ipsec_analysis"]
    rows = "".join(
        f"<tr><td>{escape(f['status'])}</td><td>{escape(f['check'])}</td><td>{escape(f['evidence'])}</td></tr>"
        for f in result["security_assessment"]["findings"]
    )
    sas = "".join(
        f"<tr><td>{escape(sa['source'])}</td><td>{escape(sa['destination'])}</td><td>{escape(sa['spi'])}</td><td>{sa['packet_count']}</td><td>{escape(', '.join(map(str, sa['sequence_numbers'])))}</td></tr>"
        for sa in a["security_associations"]
    )
    return f"""<!doctype html><html><head><meta charset='utf-8'><title>IPsecGuard Report</title>
<style>body{{font-family:Arial;margin:40px;color:#222}}h1{{margin-bottom:4px}}table{{border-collapse:collapse;width:100%;margin:14px 0}}th,td{{border:1px solid #ccc;padding:8px;text-align:left}}th{{background:#eee}}</style></head>
<body><h1>IPsecGuard Security Assessment Report</h1><p><b>Capture:</b> {escape(result.get('filename','unknown'))}</p>
<h2>Observed Summary</h2><p>Total packets: <b>{result['packet_count']}</b> | IKE: <b>{a['ike']['packet_count']}</b> | ESP: <b>{a['esp']['packet_count']}</b> | UDP/4500: <b>{a['transport']['udp_4500_packets']}</b> | Observed SAs: <b>{len(a['security_associations'])}</b></p>
<h2>Security Assessment</h2><table><tr><th>Status</th><th>Check</th><th>Evidence</th></tr>{rows}</table>
<h2>Security Associations</h2><table><tr><th>Source</th><th>Destination</th><th>SPI</th><th>Packets</th><th>Sequences</th></tr>{sas}</table>
<h2>ML Note</h2><p>Live ML inference is not enabled in this PoC. Any displayed ML result is a recorded Colab experiment and is not treated as live evidence from this capture.</p>
</body></html>"""

def build_pdf_report(result):
    a = result["ipsec_analysis"]
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, rightMargin=36,leftMargin=36,topMargin=36,bottomMargin=36)
    styles = getSampleStyleSheet()
    story = [Paragraph("IPsecGuard Security Assessment Report", styles["Title"]),
             Paragraph(f"Capture: {result.get('filename','unknown')}", styles["Normal"]),
             Spacer(1,12),
             Paragraph("Observed Summary", styles["Heading2"]),
             Paragraph(f"Total packets: {result['packet_count']} | IKE: {a['ike']['packet_count']} | ESP: {a['esp']['packet_count']} | UDP/4500: {a['transport']['udp_4500_packets']} | Observed SAs: {len(a['security_associations'])}", styles["Normal"]),
             Spacer(1,12), Paragraph("Security Assessment", styles["Heading2"])]
    data = [["Status","Check","Evidence"]] + [[f["status"], f["check"], f["evidence"]] for f in result["security_assessment"]["findings"]]
    t=Table(data,colWidths=[55,130,335])
    t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.lightgrey),("GRID",(0,0),(-1,-1),0.5,colors.grey),("VALIGN",(0,0),(-1,-1),"TOP"),("FONTSIZE",(0,0),(-1,-1),8)]))
    story += [t, Spacer(1,12), Paragraph("Security Associations", styles["Heading2"])]
    sa_data=[["Source","Destination","SPI","Packets","Sequences"]]+[[sa["source"],sa["destination"],sa["spi"],str(sa["packet_count"]),", ".join(map(str,sa["sequence_numbers"]))] for sa in a["security_associations"]]
    st=Table(sa_data,colWidths=[105,105,80,55,95])
    st.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.lightgrey),("GRID",(0,0),(-1,-1),0.5,colors.grey),("FONTSIZE",(0,0),(-1,-1),7)]))
    story += [st, Spacer(1,12), Paragraph("ML Note", styles["Heading2"]), Paragraph("Live ML inference is not enabled in this PoC. Recorded Colab ML results are kept separate from live packet evidence.", styles["Normal"])]
    doc.build(story)
    return buf.getvalue()
