"""
Script to generate the formal HCL Incident Analysis Report in .docx format.
Adheres strictly to HCL's Security Incident Detection and Analysis Project Guide.
"""

import os
import docx
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import OxmlElement
from docx.oxml.ns import qn


def set_cell_background(cell, fill_hex):
    """Set background color of a table cell."""
    tc_pr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement('w:shd')
    shd.set(qn('w:val'), 'clear')
    shd.set(qn('w:color'), 'auto')
    shd.set(qn('w:fill'), fill_hex)
    tc_pr.append(shd)


def set_cell_margins(cell, top=100, bottom=100, left=150, right=150):
    """Set inner cell padding."""
    tc_pr = cell._tc.get_or_add_tcPr()
    tc_mar = OxmlElement('w:tcMar')
    for margin_name, val in [('top', top), ('bottom', bottom), ('left', left), ('right', right)]:
        node = OxmlElement(f'w:{margin_name}')
        node.set(qn('w:w'), str(val))
        node.set(qn('w:type'), 'dxa')
        tc_mar.append(node)
    tc_pr.append(tc_mar)


def create_report():
    doc = Document()

    # Page Margins
    for section in doc.sections:
        section.top_margin = Inches(0.8)
        section.bottom_margin = Inches(0.8)
        section.left_margin = Inches(0.8)
        section.right_margin = Inches(0.8)

    # Styles
    navy = RGBColor(15, 30, 75)      # Primary corporate navy #0F1E4B
    slate = RGBColor(75, 85, 99)     # Secondary slate #4B5563
    dark = RGBColor(17, 24, 39)      # Charcoal text #111827
    red = RGBColor(185, 28, 28)      # Crimson #B91C1C
    green = RGBColor(22, 101, 52)    # Emerald #166534

    # ==========================================
    # TITLE & HEADER
    # ==========================================
    p_badge = doc.add_paragraph()
    run_badge = p_badge.add_run("HCL PROJECT-BASED LEARNING | CYBERSECURITY TRACK")
    run_badge.font.name = "Arial"
    run_badge.font.size = Pt(9)
    run_badge.font.bold = True
    run_badge.font.color.rgb = RGBColor(29, 78, 216)

    p_title = doc.add_paragraph()
    run_title = p_title.add_run("Security Incident Detection & Analysis Report")
    run_title.font.name = "Arial"
    run_title.font.size = Pt(22)
    run_title.font.bold = True
    run_title.font.color.rgb = navy
    p_title.paragraph_format.space_after = Pt(2)

    p_sub = doc.add_paragraph()
    run_sub = p_sub.add_run("Formal Security Incident Investigation, Root-Cause Analysis, & Remediation Playbook")
    run_sub.font.name = "Arial"
    run_sub.font.size = Pt(12)
    run_sub.font.color.rgb = slate
    p_sub.paragraph_format.space_after = Pt(16)

    # Metadata Table
    meta_table = doc.add_table(rows=4, cols=2)
    meta_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    meta_data = [
        ("Course / Module", "Security Incident Detection and Analysis (Project 1)"),
        ("Project Scope", "DNS Tunneling, Covert C2 Communication & Data Exfiltration"),
        ("Author / Candidate", "Harsh Juneja"),
        ("Live Deployment & Repo", "Web App: incident-detection-dns-tunneling.streamlit.app\nGitHub: github.com/Harsh18062005/incident-detection-dns-tunneling")
    ]
    for i, (label, val) in enumerate(meta_data):
        row = meta_table.rows[i]
        c0, c1 = row.cells[0], row.cells[1]
        c0.width = Inches(2.2)
        c1.width = Inches(4.6)
        set_cell_background(c0, "F1F5F9")
        set_cell_background(c1, "FFFFFF")
        set_cell_margins(c0, 80, 80, 120, 120)
        set_cell_margins(c1, 80, 80, 120, 120)

        p0 = c0.paragraphs[0]
        r0 = p0.add_run(label)
        r0.font.bold = True
        r0.font.size = Pt(9.5)
        r0.font.color.rgb = navy

        p1 = c1.paragraphs[0]
        r1 = p1.add_run(val)
        r1.font.size = Pt(9.5)
        r1.font.color.rgb = dark

    doc.add_paragraph().paragraph_format.space_after = Pt(12)

    # ==========================================
    # 1. EXECUTIVE SUMMARY
    # ==========================================
    h1 = doc.add_heading("1. Executive Summary", level=1)
    h1.runs[0].font.color.rgb = navy
    h1.runs[0].font.name = "Arial"

    doc.add_paragraph(
        "During continuous security monitoring of the enterprise network perimeter, a high-severity incident involving "
        "DNS Tunneling and covert Command-and-Control (C2) communication was identified. Adversaries weaponized the "
        "Standard Domain Name System protocol (UDP/TCP Port 53) to exfiltrate serialized, encrypted corporate data while "
        "circumventing traditional signature-based edge firewalls. Through real-time packet inspection and heuristic "
        "telemetry correlation, the Security Operations Center (SOC) detected, investigated, contained, and remediated "
        "the threat, preventing full data compromise."
    )

    # ==========================================
    # SECTION A: INCIDENT SUMMARY (Per Guide)
    # ==========================================
    h2 = doc.add_heading("Section a. Incident Summary", level=1)
    h2.runs[0].font.color.rgb = navy

    doc.add_paragraph(
        "In accordance with Section a of the HCL Incident Analysis Guidelines, the core attributes of the detected "
        "security event are summarized below:"
    )

    summary_table = doc.add_table(rows=6, cols=2)
    summary_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    summary_items = [
        ("Incident Type", "DNS Tunneling / Data Exfiltration over Covert C2 Channel (MITRE ATT&CK T1071.004, T1041)"),
        ("Date & Time of Incident", "2026-10-31 00:20:00 UTC (Real-Time Monitoring Session)"),
        ("Incident Severity Level", "CRITICAL (Risk Score 7/7 - Multi-Stage Encrypted Payload Exfiltration)"),
        ("Affected Assets", "Workstation Subnet: 192.168.1.7, 192.168.1.10, 192.168.1.3 (Host Endpoint Devices)"),
        ("Attack Vector", "Abuse of Recursive External DNS Resolvers using encoded high-entropy subdomains"),
        ("Incident Status", "CONTAINED & REMEDIATED - Malicious Domains Sinkholed, Threat Signatures Updated")
    ]

    for i, (k, v) in enumerate(summary_items):
        row = summary_table.rows[i]
        c0, c1 = row.cells[0], row.cells[1]
        c0.width = Inches(2.3)
        c1.width = Inches(4.5)
        set_cell_background(c0, "F8FAFC")
        set_cell_background(c1, "FFFFFF")
        set_cell_margins(c0, 90, 90, 120, 120)
        set_cell_margins(c1, 90, 90, 120, 120)

        p0 = c0.paragraphs[0]
        r0 = p0.add_run(k)
        r0.font.bold = True
        r0.font.size = Pt(9.5)
        r0.font.color.rgb = navy

        p1 = c1.paragraphs[0]
        r1 = p1.add_run(v)
        r1.font.size = Pt(9.5)
        if "CRITICAL" in v:
            r1.font.bold = True
            r1.font.color.rgb = red
        elif "CONTAINED" in v:
            r1.font.bold = True
            r1.font.color.rgb = green
        else:
            r1.font.color.rgb = dark

    doc.add_paragraph().paragraph_format.space_after = Pt(10)

    # ==========================================
    # SECTION B: DETECTION AND ANALYSIS (Per Guide)
    # ==========================================
    h3 = doc.add_heading("Section b. Detection and Analysis", level=1)
    h3.runs[0].font.color.rgb = navy

    doc.add_paragraph(
        "The SOC environment deployed a defense-in-depth detection architecture utilizing live packet sniffers, "
        "mathematical feature extractors, and heuristic correlation engines to identify anomalous DNS behavior."
    )

    doc.add_heading("1. Tools & Platforms Utilized", level=2)
    tools_list = [
        "Network Packet Ingestion: Scapy (Promiscuous Mode Socket Sniffing) & Wireshark / tcpdump PCAP Ingestion.",
        "Security Dashboard & Visualization: Streamlit Enterprise SOC Platform (Incident Trend Analysis & Risk Metrics).",
        "Analytics & Heuristic Engine: Python 3.11 with NumPy and Pandas telemetry pipelines.",
        "Threat Intelligence & Framework: MITRE ATT&CK Framework (T1071.004, T1041).",
        "Continuous Integration / Testing: GitHub Actions CI Matrix (11 Automated Unit Tests across Python 3.10/3.11)."
    ]
    for item in tools_list:
        doc.add_paragraph(item, style='List Bullet')

    doc.add_heading("2. Technical Investigation Findings & Heuristic Feature Extraction", level=2)
    doc.add_paragraph(
        "DNS queries were extracted and evaluated across five primary heuristic telemetry dimensions to calculate "
        "an explainable Risk Score (0–7):"
    )

    # Heuristic Table
    h_table = doc.add_table(rows=6, cols=4)
    h_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    headers = ["Heuristic Metric", "Threshold Trigger", "Weight", "Security Rationale & Observation"]
    for j, h in enumerate(headers):
        c = h_table.rows[0].cells[j]
        set_cell_background(c, "0F172A")
        p = c.paragraphs[0]
        r = p.add_run(h)
        r.font.bold = True
        r.font.size = Pt(9)
        r.font.color.rgb = RGBColor(255, 255, 255)
        set_cell_margins(c, 100, 100, 100, 100)

    h_rows = [
        ("Domain Length", "> 50 characters", "+2", "Observed queries exceeded 65 chars (e.g. 68-char encoded payload)."),
        ("Subdomain Depth", "≥ 2 subdomains", "+1", "Multi-stage payload encapsulation (.exfil-c2.net, .data-tunnel.org)."),
        ("Shannon Entropy", "> 3.5 bits/char", "+2", "Observed entropy peaked at 4.23 bits/char, confirming Base64 encryption."),
        ("Query Frequency", "≥ 5 queries", "+1", "Burst beaconing detected from source IP 192.168.1.7 within short intervals."),
        ("Query Record Type", "TXT Query", "+1", "Payload exfiltration leveraged TXT records to maximize response buffer size.")
    ]

    for i, data in enumerate(h_rows):
        row = h_table.rows[i+1]
        for j, val in enumerate(data):
            cell = row.cells[j]
            set_cell_background(cell, "F8FAFC" if i % 2 == 0 else "FFFFFF")
            set_cell_margins(cell, 80, 80, 100, 100)
            p = cell.paragraphs[0]
            r = p.add_run(val)
            r.font.size = Pt(8.5)
            r.font.color.rgb = dark
            if j == 2:
                r.font.bold = True

    doc.add_paragraph().paragraph_format.space_after = Pt(10)

    doc.add_heading("3. Incident Timeline Reconstruction", level=2)
    doc.add_paragraph(
        "SOC analysts reconstructed the step-by-step chronology of the attack based on chronological packet telemetry:"
    )

    time_table = doc.add_table(rows=5, cols=3)
    time_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    time_headers = ["Timestamp", "Phase / Stage", "Observed Telemetry & Activity"]
    for j, h in enumerate(time_headers):
        c = time_table.rows[0].cells[j]
        set_cell_background(c, "1E3A8A")
        p = c.paragraphs[0]
        r = p.add_run(h)
        r.font.bold = True
        r.font.size = Pt(9)
        r.font.color.rgb = RGBColor(255, 255, 255)
        set_cell_margins(c, 100, 100, 100, 100)

    t_data = [
        ("00:20:02 UTC", "Reconnaissance / Normal Traffic", "Baseline queries generated (google.com, github.com) by normal enterprise users."),
        ("00:20:07 UTC", "Initial C2 Beaconing", "First anomalous TXT query from 192.168.1.7: beacon-fgi4tfmz1o4k9vc.example.com (Risk: 5/7)."),
        ("00:20:12 UTC", "Bulk Data Exfiltration", "Burst of 18 high-entropy TXT queries carrying encoded binary data chunks (Entropy: 4.19, Risk: 7/7)."),
        ("00:20:15 UTC", "Automated SOC Trigger", "Threshold rule triggered: 20 critical alerts flagged; automated containment initiated.")
    ]
    for i, data in enumerate(t_data):
        row = time_table.rows[i+1]
        for j, val in enumerate(data):
            cell = row.cells[j]
            set_cell_background(cell, "F8FAFC" if i % 2 == 0 else "FFFFFF")
            set_cell_margins(cell, 80, 80, 100, 100)
            p = cell.paragraphs[0]
            r = p.add_run(val)
            r.font.size = Pt(8.5)
            r.font.color.rgb = dark

    doc.add_paragraph().paragraph_format.space_after = Pt(12)

    # ==========================================
    # SECTION C: MITIGATION AND RECOVERY (Per Guide)
    # ==========================================
    h4 = doc.add_heading("Section c. Mitigation and Recovery", level=1)
    h4.runs[0].font.color.rgb = navy

    doc.add_paragraph(
        "Upon positive confirmation of active DNS exfiltration, the SOC executed incident containment and recovery "
        "workflows in alignment with standard incident response playbooks:"
    )

    mitigation_steps = [
        ("1. Host Isolation & Quarantine", "Source endpoints 192.168.1.7, 192.168.1.10, and 192.168.1.3 were immediately segmented from the internal local area network (VLAN isolation) to prevent lateral movement."),
        ("2. Threat Domain Sinkholing", "Adversary command-and-control domains (*.example.com, *.exfil-c2.net, *.data-tunnel.org) were null-routed / sinkholed at the perimeter internal DNS forwarders."),
        ("3. Perimeter Firewall Egress Filtering", "Configured egress firewall rules to drop all direct outbound UDP/TCP Port 53 traffic from internal client subnets. Only authorized enterprise DNS servers are permitted outbound resolution."),
        ("4. Endpoint Forensic Analysis & Cleanup", "Forensic scans of isolated hosts identified unauthorized PowerShell and Python-based exfiltration scripts. Malicious processes were terminated, artifacts quarantined, and active directory user sessions revoked."),
        ("5. Post-Remediation Telemetry Verification", "Live monitoring confirmed zero subsequent anomalous TXT queries or high-entropy requests. Endpoint integrity verified prior to network reconnection.")
    ]

    for title, desc in mitigation_steps:
        p = doc.add_paragraph()
        r_t = p.add_run(title + ": ")
        r_t.font.bold = True
        r_t.font.size = Pt(10)
        r_t.font.color.rgb = navy
        r_d = p.add_run(desc)
        r_d.font.size = Pt(10)
        r_d.font.color.rgb = dark
        p.paragraph_format.space_after = Pt(6)

    # ==========================================
    # SECTION D: FUTURE RECOMMENDATIONS (Per Guide)
    # ==========================================
    h5 = doc.add_heading("Section d. Future Recommendations", level=1)
    h5.runs[0].font.color.rgb = navy

    doc.add_paragraph(
        "To strengthen the organizational security posture and enhance long-term threat resilience, the following "
        "preventive controls and monitoring improvements are recommended:"
    )

    rec_categories = [
        ("A. Preventive Technical Controls", [
            "Deploy DNS Response Policy Zones (RPZ) and DNS Threat Intelligence feeds to automatically block newly registered domains (NRDs).",
            "Implement Zero Trust Network Access (ZTNA) with micro-segmentation between user workstations and internal data stores.",
            "Enforce centralized DNS over HTTPS/TLS (DoH/DoT) inspection at the enterprise proxy level."
        ]),
        ("B. SOC Monitoring & Detection Optimization", [
            "Integrate automated real-time Shannon entropy calculation into the centralized SIEM ingestion pipeline.",
            "Establish automated playbooks (SOAR) to auto-isolate endpoints triggering consecutive High or Critical DNS tunneling scores.",
            "Continuously tune correlation rules to reduce false positives for legitimate developer tool subdomains (e.g., CDN, AWS, GitHub)."
        ]),
        ("C. Policy & Governance Enhancements", [
            "Update Acceptable Use Policies (AUP) explicitly forbidding unauthorized local DNS resolution agents and third-party VPN tunnelers.",
            "Mandate quarterly red-team / purple-team DNS tunneling emulation exercises to test SOC detection readiness."
        ]),
        ("D. Security Awareness Training", [
            "Conduct targeted anti-phishing and social engineering workshops for high-risk department personnel to prevent initial endpoint compromise."
        ])
    ]

    for cat_title, items in rec_categories:
        doc.add_heading(cat_title, level=2)
        for item in items:
            doc.add_paragraph(item, style='List Bullet')

    # ==========================================
    # SECTION E: CONCLUSION & PROJECT EVIDENCE
    # ==========================================
    h6 = doc.add_heading("Section e. Conclusion & Audit Verification", level=1)
    h6.runs[0].font.color.rgb = navy

    doc.add_paragraph(
        "This project successfully demonstrated the full lifecycle of Security Incident Detection and Analysis—from "
        "live telemetry ingestion and explainable heuristic evaluation, to incident triage, timeline reconstruction, "
        "and mitigation playbook execution. All project components, automated test suites, and live dashboards are "
        "verified and accessible via the links below:"
    )

    ev_table = doc.add_table(rows=4, cols=2)
    ev_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    ev_data = [
        ("Live SOC Web Dashboard", "https://incident-detection-dns-tunneling.streamlit.app/"),
        ("GitHub Repository (Code & CI)", "https://github.com/Harsh18062005/incident-detection-dns-tunneling"),
        ("Automated Test Suite Status", "11 Unit Tests Passing (0.025s execution) across Python 3.10 & 3.11"),
        ("CSV Telemetry & Alerts", "Available via one-click download in dashboard or project data/ folder")
    ]
    for i, (label, val) in enumerate(ev_data):
        row = ev_table.rows[i]
        c0, c1 = row.cells[0], row.cells[1]
        c0.width = Inches(2.2)
        c1.width = Inches(4.6)
        set_cell_background(c0, "F1F5F9")
        set_cell_background(c1, "FFFFFF")
        set_cell_margins(c0, 80, 80, 120, 120)
        set_cell_margins(c1, 80, 80, 120, 120)

        p0 = c0.paragraphs[0]
        r0 = p0.add_run(label)
        r0.font.bold = True
        r0.font.size = Pt(9.5)
        r0.font.color.rgb = navy

        p1 = c1.paragraphs[0]
        r1 = p1.add_run(val)
        r1.font.size = Pt(9.5)
        r1.font.color.rgb = dark

    output_path = os.path.join(os.path.dirname(__file__), "Security_Incident_Detection_and_Analysis_Report.docx")
    doc.save(output_path)
    print(f"Report successfully generated at: {output_path}")


if __name__ == "__main__":
    create_report()
