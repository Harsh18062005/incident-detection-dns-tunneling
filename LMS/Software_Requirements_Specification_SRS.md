# DEPARTMENT OF COMPUTER SCIENCE & ENGINEERING
## ABES ENGINEERING COLLEGE, GHAZIABAD
### SOFTWARE REQUIREMENTS SPECIFICATION (SRS)
**Project Title**: Incident Detection for a DNS Tunneling Attack (P_210)  
**Standard Academic Compliance**: IEEE Std 830-1998  

| SUBMITTED BY: | UNDER THE GUIDANCE OF: |
| :--- | :--- |
| **Harsh Juneja** (Roll No: 2400320100487)<br>Degree: Bachelor of Technology (B.Tech)<br>Status: 3rd Year Major Project Specification | **Mr. Priyan S**<br>Department of Computer Science & Engineering<br>Academic Year: 2026 - 2027<br>Date of Submission: 31-10-2026 |

---

### Document Revision & Approval History

| Version | Date | Description / Major Changes | Prepared By | Reviewed By |
| :---: | :---: | :--- | :---: | :---: |
| **0.1** | 15-Sep-2026 | Initial Draft & Scope Definition | Harsh Juneja | Mr. Priyan S |
| **1.0** | 30-Sep-2026 | Final 3rd Year Mid-Term SRS Baseline | Harsh Juneja | Mr. Priyan S |
| **2.0** | 31-Oct-2026 | **Major Production Upgrade**: Interactive Live Dashboard Sniffing UI with safe timeouts, Cloud-Friendly Live Traffic Simulation Stream, PCAP/PCAPNG File Upload Parser, Heuristic Policy Dataclass (`DetectionConfig`), Threat Severity Tiers (CRITICAL/HIGH/MEDIUM/LOW), 1-Click CSV Incident & Traffic Reporting, Executive Corporate Light Theme SOC Dashboard, 1-Click Windows Desktop Launcher, and Automated GitHub Actions CI/CD Test Pipeline (11 unit tests). | Harsh Juneja | Mr. Priyan S |

> **Guidance Note**: This Software Requirements Specification document conforms strictly to the **IEEE Std 830-1998** recommended practice. All functional modules, external interfaces, non-functional attributes, and system models represent the updated production baseline for 3rd-year university evaluation and lab review.

---

## 1. Introduction

### 1.1 Purpose
The purpose of this Software Requirements Specification (SRS) document is to provide a complete, clear, and unambiguous definition of the functionality, external interfaces, performance targets, and constraints of the proposed system: **'Incident Detection for a DNS Tunneling Attack (P_210)'**. This specification serves as a binding reference between student developers, project evaluators, academic supervisors, and prospective end users during the 3rd-year engineering curriculum.

### 1.2 Scope of the System
The proposed application is designed to identify and triage suspicious DNS tunneling and covert data exfiltration patterns by delivering an end-to-end detection, analysis, and monitoring workflow. The system has evolved from a script-driven prototype into an enterprise-grade Security Operations Center (SOC) dashboard. Key boundary guidelines include:

- **In-Scope Capabilities**:
  - **Multi-Vector Telemetry Ingestion**: Synthetic benchmark datasets, direct local packet capture over UDP/TCP Port 53 via Scapy with configurable timeouts, cloud-friendly live traffic simulation streams (benign sites + tunneling attacks), and Wireshark `.pcap`/`.pcapng` file uploads.
  - **Mathematical Feature Extraction**: Calculation of Shannon entropy ($H = -\sum p \log_2 p$), domain length, subdomain depth, query frequency, and record types (e.g., TXT queries).
  - **Explainable Rule-Based Detection Engine**: Granular heuristic risk score calculation (0–7 scale) using a centralized, tunable policy configuration (`DetectionConfig`).
  - **Threat Severity Classification**: Standardized SOC triage categorization into **CRITICAL** (6–7), **HIGH** (4–5), **MEDIUM** (2–3), and **LOW** (0–1).
  - **Executive SOC Dashboard**: Formal corporate light-themed Streamlit user interface featuring real-time KPI metrics, alert status banners, traffic tables, and threat distribution charts.
  - **1-Click Data Reporting**: Direct CSV export for both raw DNS traffic logs and categorized incident reports.
  - **Developer Tools & CI/CD**: 1-click Windows desktop batch launcher (`run_dashboard.bat`), VS Code launch profiles, and automated GitHub Actions CI/CD pipeline verifying 11 unit tests across Python 3.10 and 3.11.

- **Out-of-Scope Boundaries**:
  - Automatic kernel-level firewall blocking or active host isolation (to prevent accidental enterprise service disruption).
  - Multi-tenant enterprise SIEM infrastructure installations.
  - Relational database backends (CSV streaming and in-memory session states are utilized for maximum portability and rapid forensic review).
  - Live malware detonation.
  - Direct decryption of encrypted DNS layers (DoH/DoT) in the current prototype.

- **Expected Benefits**:
  - Safe, repeatable academic testing.
  - Deep forensic visibility into Port 53 DNS query payloads.
  - Transparent, explainable alerting to alleviate SOC alert fatigue.
  - Zero-configuration deployment via Streamlit Community Cloud.
  - 1-click execution for evaluators without terminal dependencies.

### 1.3 Definitions, Acronyms, and Abbreviations

| Category | Term / Acronym | Definition / Standard Context |
| :--- | :--- | :--- |
| **Standard** | **SRS** | Software Requirements Specification (IEEE Std 830-1998 format). |
| **Network** | **DNS** | Domain Name System; standard hierarchical protocol operating over UDP/TCP Port 53. |
| **Network** | **QNAME** | DNS query name; contains the fully qualified domain name (FQDN) requested by the client. |
| **Network** | **QTYPE** | DNS query record type, such as A (IPv4), AAAA (IPv6), TXT, MX, or CNAME. |
| **Security** | **DNS Tunneling** | Covert cyberattack technique weaponizing DNS queries/responses to encapsulate unauthorized C2 instructions or exfiltrate sensitive corporate data. |
| **Security** | **Shannon Entropy** | A mathematical measure of character randomness; values $> 3.5\text{ bits/char}$ identify encoded/encrypted Base32/Base64 payloads. |
| **Security** | **Severity Tiers** | Standardized SOC triage classification: CRITICAL (6–7), HIGH (4–5), MEDIUM (2–3), and LOW (0–1). |
| **Security** | **MITRE ATT&CK** | Globally accessible knowledge base of adversary tactics; maps to T1071.004 (DNS C2) and T1041 (Exfiltration). |
| **Project Specific**| **Scapy** | Powerful Python packet manipulation and network sniffing engine utilized for Port 53 socket interception. |
| **Project Specific**| **PCAP / PCAPNG** | Standard packet capture file formats generated by network analyzers such as Wireshark and tcpdump. |
| **Project Specific**| **Streamlit** | Modern Python application framework powering the interactive SOC monitoring dashboard. |
| **Project Specific**| **Risk Score** | Granular composite heuristic score (0–7) derived from weighted evaluation of 5 independent telemetry features. |
| **Project Specific**| **CI/CD** | Continuous Integration / Continuous Deployment; automated GitHub Actions test execution matrix on Python 3.10 and 3.11. |
| **Project Specific**| **Streamlit Cloud**| Public serverless cloud hosting platform hosting the live deployed application. |

### 1.4 References
1. **IEEE Std 830-1998**: IEEE Recommended Practice for Software Requirements Specifications.
2. **RFC 1035**: Domain Names - Implementation and Specification (*Mockapetris, P.*).
3. **NIST SP 800-81r3**: Secure Domain Name System (DNS) Deployment Guide.
4. **MITRE ATT&CK Framework**: Technique [T1071.004](https://attack.mitre.org/techniques/T1071/004/) (*Application Layer Protocol: DNS*) & [T1041](https://attack.mitre.org/techniques/T1041/) (*Exfiltration Over C2 Channel*).
5. **Scapy Documentation**: Packet Sniffing, Promiscuous Socket Filtering, and Dissection.
6. **Streamlit Documentation**: Session State Management, Layout Theming, and Data Visualization.

### 1.5 Document Overview
The remainder of this specification is partitioned into structural IEEE sections: Section 2 outlines the product perspective, target user personas, operational context, and updated design constraints. Section 3 specifies detailed functional requirements partitioned by subsystem modules with unique requirement IDs. Section 4 defines external user, hardware, software, and communication interfaces. Section 5 articulates non-functional attributes (Performance, Reliability, Security). Section 6 presents academic system design and behavioral models. Finally, Section 7 provides university review and approval sign-off.

---

## 2. Overall Description

### 2.1 Product Perspective
The Incident Detection System (P_210) is architected as an autonomous, self-contained Python cybersecurity platform. It bridges network telemetry capture, mathematical feature extraction, explainable heuristic inference, and web-based SOC visualization. Unlike monolithic enterprise SIEMs requiring heavy infrastructure, this system provides modular zero-friction execution locally via Windows/Linux environments and remotely via Streamlit Community Cloud.

### 2.2 User Classes and Characteristics

| User Role / Persona | Technical Proficiency | Core Responsibilities & Rights |
| :--- | :--- | :--- |
| **SOC Analyst / SME** | Intermediate to High | Monitor real-time DNS telemetry, evaluate risk scores and detection rationale, triage alerts, download incident CSV reports, and initiate quarantine procedures. |
| **Developer / Student** | Intermediate | Maintain codebase, calibrate heuristic policy thresholds in `config.py`, run automated unit test suites, trigger packet simulation pipelines, and push updates. |
| **Academic Evaluator** | Basic to Intermediate | Review project compliance against IEEE standards, evaluate live demonstration via web link, inspect test results, and assess scoring accuracy. |

### 2.3 Operating Environment
- **Client Interface**: Modern HTML5 web browsers (Google Chrome, Mozilla Firefox, Microsoft Edge, Safari) accessing `localhost:8501` or the deployed cloud URL.
- **Local Host Environment**: Microsoft Windows 10/11 or Ubuntu Linux running Python 3.10, 3.11, or 3.12 with an isolated virtual environment (`venv`).
- **Cloud Hosting Environment**: Streamlit Community Cloud (Linux container) continuously synced with the GitHub repository `main` branch.
- **Software Libraries**: Pandas, Streamlit, Scapy, Openpyxl, and Python-docx.
- **Packet Sniffing Support**: Local live NIC packet capture utilizes Scapy, requiring Npcap (on Windows) or libpcap with raw socket permissions.
- **Automated CI/CD Environment**: GitHub Actions runners executing automated matrix tests on `ubuntu-latest`.

### 2.4 Design and Implementation Constraints
1. **Browser Sandboxing Constraint**: Web browsers strictly prevent web applications from sniffing raw network interfaces on a visitor's PC. The updated design resolves this constraint by providing: (1) Local Scapy sniffing with safe timeouts, (2) One-click live cloud traffic stream simulation, and (3) Client-side PCAP file upload.
2. **Tunable Heuristic Constraint**: Detection parameters are decoupled into `detection/config.py` (`DetectionConfig` dataclass) rather than hardcoded magic constants, allowing dynamic calibration.
3. **Explainability Constraint**: The inference engine must remain 100% explainable; black-box ML models are excluded to provide clear audit trails for SOC triage.
4. **Execution Performance Constraint**: Live packet sniffing enforces configurable timeouts (3s–20s) and packet sliders (10–100 packets) to prevent dashboard thread blocking.

### 2.5 Assumptions and Dependencies
- **Network Visibility**: For local live capture, the host machine must have active UDP/TCP Port 53 DNS traffic passing through the selected network interface.
- **Dependency Integrity**: Python packages specified in `requirements.txt` (`pandas`, `streamlit`, `scapy`) must be installed.
- **Safe Sandbox Guarantee**: Synthetic datasets and simulation generators represent controlled, safe educational data and contain no weaponized exploit payloads.

---

## 3. System Features and Functional Requirements

### 3.1 Module 1: Telemetry Ingestion & Packet Processing

| Req ID | Feature Description | Input / Validation Rule | Priority |
| :---: | :--- | :--- | :---: |
| **FR-1.1** | Synthetic Dataset Ingestion | System shall read pre-generated CSV datasets (`dns_traffic.csv`) containing benign and suspicious DNS query records. | **High** |
| **FR-1.2** | Live Network Sniffing | System shall capture live UDP/TCP Port 53 DNS packets from physical NICs using Scapy with configurable packet counts (10–100) and timeouts (3–20s). | **High** |
| **FR-1.3** | Cloud Traffic Simulation Stream | System shall generate a live burst of realistic DNS queries (benign enterprise domains + tunneling attacks) to enable interactive live testing on deployed cloud servers without raw socket privileges. | **High** |
| **FR-1.4** | PCAP Capture File Upload | System shall allow users to upload `.pcap` and `.pcapng` files captured from Wireshark, parsing DNS records into tabular telemetry for offline inspection. | **Medium** |

### 3.2 Module 2: Feature Extraction & Detection Engine

| Req ID | Feature Description | Input / Validation Rule | Priority |
| :---: | :--- | :--- | :---: |
| **FR-2.1** | Mathematical Feature Extraction | System shall extract domain length, subdomain count, Shannon entropy, query frequency, and query type for every query record. | **High** |
| **FR-2.2** | Shannon Entropy Computation | System shall compute entropy using the formula: $H = -\sum p \log_2(p)$. Queries with entropy $> 3.5\text{ bits/char}$ shall be flagged as high-entropy payloads. | **High** |
| **FR-2.3** | Heuristic Rule Evaluation | System shall apply weighted scoring: Length $>50$ (+2), Subdomains $\ge 2$ (+1), Entropy $>3.5$ (+2), Frequency $\ge 5$ (+1), and TXT query (+1). | **High** |
| **FR-2.4** | Tunable Configuration Constants | System shall encapsulate detection policy thresholds in a `DetectionConfig` dataclass, supporting runtime customization without altering source logic. | **Medium** |
| **FR-2.5** | Threat Severity Classification | System shall categorize risk scores (0–7) into standard SOC severity tiers: **CRITICAL** (6–7), **HIGH** (4–5), **MEDIUM** (2–3), and **LOW** (0–1). | **High** |

### 3.3 Module 3: SOC Visualization, Alerting & Reporting

| Req ID | Feature Description | Input / Validation Rule | Priority |
| :---: | :--- | :--- | :---: |
| **FR-3.1** | Enterprise SOC Dashboard | System shall render a formal corporate light-themed dashboard with real-time KPI metric cards, status alert banners, and interactive controls. | **High** |
| **FR-3.2** | Interactive Mode Switching | System shall toggle seamlessly between Live DNS Monitoring and Synthetic Dataset Testing modes via responsive radio selectors. | **High** |
| **FR-3.3** | Threat Distribution Analytics | System shall render interactive bar charts visualizing suspicious query frequencies by source IP and risk score breakdown. | **Medium** |
| **FR-3.4** | One-Click Incident CSV Export | System shall provide direct download buttons allowing analysts to export raw DNS traffic logs and categorized incident reports as CSV files. | **High** |
| **FR-3.5** | 1-Click Desktop Launcher | System shall provide a Windows batch launcher (`run_dashboard.bat`) enabling 1-click execution without terminal command entry. | **Medium** |

### 3.4 Module 4: Verification, Testing & CI/CD Pipeline

| Req ID | Feature Description | Input / Validation Rule | Priority |
| :---: | :--- | :--- | :---: |
| **FR-4.1** | Automated Unit Test Suite | System shall maintain an automated test suite (`tests/`) covering entropy math, domain parsing, heuristic scoring, and packet pipelines. | **High** |
| **FR-4.2** | GitHub Actions CI Matrix | System shall trigger automated CI workflows on push/PR to `main`, testing test execution across Python 3.10 and 3.11 with zero failures. | **High** |
| **FR-4.3** | Zero-Regression Baseline | All 11 unit tests shall execute and pass in under 0.05 seconds prior to any release or commit deployment. | **High** |

---

## 4. External Interface Requirements

### 4.1 User Interfaces (UI)
The interface adheres to formal executive SOC ergonomics utilizing a corporate light theme: background `#F8FAFC`, crisp white container cards `#FFFFFF` with subtle `#E2E8F0` borders, and high-contrast charcoal `#0F172A` typography. The dashboard presents:
1. **Enterprise Header**: Displays project identity, scope, and SOC status badges.
2. **Interactive Live Controls**: Includes tabs for Local Sniffing, Cloud Traffic Simulation, and PCAP Upload.
3. **4 High-Impact KPI Metric Cards**: Total DNS Queries, Tunneling Alerts, Suspicious Traffic %, and Highest Risk Score.
4. **Incident Alert Banner**: Dynamic status color coding (Emerald for Normal, Crimson for Critical).
5. **Interactive Data Tables**: Displaying full DNS telemetry and categorized incident alerts.
6. **Action Export Buttons**: One-click CSV report generation.
7. **Visual Analytics**: Interactive bar charts for Source IP threat distribution and Risk Score breakdown.

### 4.2 Hardware Interfaces
Standard PC hardware: Display resolution $\ge 1280 \times 720$; Keyboard and Mouse; and a standard network interface card (NIC) (Ethernet or 802.11 Wi-Fi) supporting promiscuous socket capture via Scapy/Npcap for local live testing.

### 4.3 Software Interfaces
- **Operating System**: Windows 10/11 or Ubuntu Linux.
- **Runtime**: Python 3.10 / 3.11 / 3.12.
- **Network Sniffing**: Scapy 2.6+ with Npcap.
- **Analytical Layer**: Pandas 2.2+.
- **Frontend Framework**: Streamlit 1.39+.
- **Continuous Integration**: GitHub Actions (`ubuntu-latest` runners).

### 4.4 Communication Interfaces
- **Web Transport**: HTTP/HTTPS over Port 8501 locally, and standard Port 443 on Streamlit Community Cloud.
- **DNS Packet Telemetry**: Ingestion filtered for UDP Port 53 and TCP Port 53.
- **Data Persistence**: Tabular CSV file streaming.

---

## 5. Non-Functional Requirements (NFRs)

| Attribute | Target Metric / Standard | Verification & Testing Method |
| :--- | :--- | :--- |
| **5.1 Performance** | Feature calculation and risk evaluation shall complete in $< 30\text{ms}$ for 100 queries. Live packet capture timeout enforced between 3s–20s to ensure zero dashboard UI freeze. | Benchmarked via automated test execution (11 tests pass in 0.025s); verified on Streamlit Community Cloud. |
| **5.2 Security & Containment** | System operates strictly as a read-only telemetry sensor and analytical alerting tool; does not execute captured payloads or disrupt corporate DNS traffic. | Code review verifying read-only parsing and safe string sanitization on decoded QNAME packets. |
| **5.3 Reliability & Correctness** | 100% deterministic mathematical calculations for Shannon entropy and heuristic scoring for identical inputs. | Automated unit tests (`test_feature_extractor`, `test_detection_engine`) executing via GitHub Actions CI on every commit. |
| **5.4 Portability & Usability** | Zero-install access for evaluators via public cloud URL; 1-click execution on local Windows machines via `run_dashboard.bat`. | Verified multi-environment execution across local Windows 11 and cloud Linux container deployment. |

---

## 6. System Design and Analysis Models

### 6.1 Architectural Workflow Diagram

```
┌────────────────────────────────────────────────────────────────────────┐
│                      Multi-Vector Ingestion Layer                      │
│  [Local Scapy Sniffer]  [Cloud Simulation Stream]  [PCAP File Upload]  │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Raw DNS Telemetry (QNAME, QTYPE, IP)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   Feature Extraction & Math Pipeline                   │
│    Domain Length  •  Subdomain Depth  •  Shannon Entropy  •  Frequency │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Extracted Feature Vector
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│               Heuristic Rule Engine (DetectionConfig)                  │
│       Calculate Risk Score (0-7) & Classify Severity (Low-Critical)    │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Scored Incidents & Reasons
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                  Enterprise SOC Streamlit Dashboard                    │
│  KPI Cards • Status Alerts • Data Tables • Threat Charts • CSV Export   │
└────────────────────────────────────────────────────────────────────────┘
```

### 6.2 Analysis Models Summary

| Diagram Model | Objective & Operational Scope | Deliverable Architecture |
| :--- | :--- | :--- |
| **System Context Diagram** | Illustrates external data boundaries (Network NIC, Synthetic Data, PCAP Files, Cloud Simulator) interacting with the Detection System Boundary and SOC Dashboard. | Multi-source Ingestion $\to$ Detection Core $\to$ Streamlit Web Dashboard. |
| **Data Flow Diagram (Level 0/1)** | Depicts telemetry pipeline: Raw Packets $\to$ Feature Extraction (Entropy, Length, Depth) $\to$ Heuristic Scoring Engine $\to$ Alerts & CSV Persistence $\to$ Dashboard. | Modular Data Pipeline Flow. |
| **Use Case Diagram** | Maps actor interactions (SOC Analyst, Student Developer, Academic Evaluator) across Live Capture, Cloud Simulation, PCAP Upload, Alert Review, and CSV Export. | Comprehensive UML Actor-Interaction Model. |
| **Sequence Diagram** | Chronological message exchanges between User, Streamlit Frontend, Scapy/Simulation Engine, Detection Core, and CSV Export Controllers. | End-to-end interactive sequence workflow. |

---

## 7. Academic Review & Sign-Off

This updated Software Requirements Specification (**SRS v2.0**) has been formally submitted for evaluation and project review by the Department of Computer Science & Engineering, ABES Engineering College:

| Project Coordinator / Guide | Internal Examiner | Head of Department (HOD) |
| :--- | :--- | :--- |
| <br>___________________________<br>**Mr. Priyan S**<br>Department of CSE<br>Date: 31-10-2026 | <br>___________________________<br>**Internal Examiner**<br>Department Evaluation Panel<br>Date: 31-10-2026 | <br>___________________________<br>**Head of Department**<br>Computer Science & Engineering<br>Date: 31-10-2026 |
