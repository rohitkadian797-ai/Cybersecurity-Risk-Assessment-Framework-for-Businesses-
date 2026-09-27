# PRESENTATION SLIDES & DEFENSE CONTENT
## Project Title: Cybersecurity Risk Assessment Framework for Small Businesses (SMEs)
**Aligned with NIST Cybersecurity Framework (CSF 2.0)**  
**Audience:** Academic Evaluation Committee / Project Viva / Executive Stakeholders  

---

### SLIDE 1: TITLE SLIDE
- **Title:** Cybersecurity Risk Assessment Framework for Small Businesses (SMEs)
- **Subtitle:** A Quantitative Decision-Support System Aligned with NIST CSF 2.0
- **Domain:** Cybersecurity, Information Security & Risk Management
- **Key Focus:** Quantitative Threat Evaluation, 5×5 Risk Matrices, and Prioritized Mitigation Roadmaps

---

### SLIDE 2: INTRODUCTION & BACKGROUND
- **SME Economic Significance:**
  - Represent >90% of global businesses and >50% of employment.
  - Essential contributors to supply chain integrity.
- **The Reality of Modern Cyber Threats:**
  - 43% of all cyber attacks globally target small businesses.
  - 60% of attacked SMEs go out of business within 6 months.
  - Average cost of an SME data breach: ~$2.98 Million.
- **The Core Paradox:**
  - SMEs hold enterprise-grade data (PII, IP, financial records) but operate with minimal security defenses.

---

### SLIDE 3: PROBLEM STATEMENT
- **The SME Cybersecurity Dilemma:**
  - **Budget & Talent Deficit:** Cannot afford dedicated SOC teams, full-time CISOs, or expensive third-party audits ($15k–$50k).
  - **Enterprise Tool Mismatch:** Frameworks like FAIR, ISO 27005, and OCTAVE require complex statistical inputs that SMEs lack.
  - **Subjective "Checklist Fatigue":** Traditional audits provide vague "High/Medium/Low" ratings with no mathematical transparency.
  - **Lack of Actionable Roadmaps:** Audits overwhelm owners with raw CVEs instead of prioritized, cost-effective action steps.

---

### SLIDE 4: PROJECT OBJECTIVES
1. **Catalog & Research:** Identify the 10 most damaging SME cyber threat vectors.
2. **Formulate Quantitative Metric:** Develop a transparent 3-variable scoring algorithm:  
   $$\text{Risk Score} = \text{Likelihood} \times \text{Severity} \times \text{Business Impact} \quad (\text{Max 125})$$
3. **Audit Baseline Security Controls:** Evaluate 10 fundamental safeguards to compute a 0–100% Security Posture Score.
4. **NIST CSF 2.0 Mapping:** Align all threats and controls with Identify, Protect, Detect, Respond, and Recover.
5. **Interactive Decision-Support:** Build dynamic Chart.js analytics, a 5×5 Risk Matrix, and a filterable Risk Register.
6. **Rule-Based Mitigation Engine:** Automatically generate prioritized action roadmaps (Priority 1 to 5).
7. **Empirical Validation:** Demonstrate end-to-end efficacy using a realistic case study (*TechNova Solutions*).

---

### SLIDE 5: EXISTING AUDIT PITFALLS VS. PROPOSED SOLUTION
| Criteria | Traditional Enterprise Audits | Ad-hoc Online Checklists | Our Proposed Framework |
|---|---|---|---|
| **Cost & Setup** | Very High ($15k+) / Weeks to complete | Free / Static & generic | Free & Open Source / Instant self-service |
| **Scoring Rigor** | Complex statistical distributions | Arbitrary qualitative labels | Mathematical 3D scoring (1–125 scale) |
| **Framework Alignment** | Complex ISO/NIST manual cross-walks | Rare or absent | Strict 100% NIST CSF 2.0 mapping |
| **Usability** | Requires certified risk analyst | Basic non-interactive forms | Interactive wizard, live preview, 5x5 matrix |
| **Output** | 100-page static PDFs | Generic bullet points | Prioritized action plan & PDF executive report |

---

### SLIDE 6: PROPOSED SYSTEM SOLUTION
- **End-to-End Self-Service Web Platform:**
  - **Interactive Assessment Wizard:** 4-step progressive questionnaire evaluating profile, controls, and threats.
  - **Real-Time Algorithmic Engine:** Instantaneous recalculation of risk scores, classifications, and posture ratings.
  - **Executive Analytics Dashboard:** Visual KPIs and 5 dynamic charts (Distribution, Rankings, Scatter, Radar, Controls).
  - **Interactive 5×5 Risk Matrix:** Color-coded risk zones with clickable threat chips opening immediate mitigation modals.
  - **Comprehensive Risk Register:** Searchable, filterable, and sortable table with one-click CSV and JSON export.
  - **Prioritized Action Plan:** Rule-based remediation tasks grouped from Priority 1 (Immediate) to Priority 5.

---

### SLIDE 7: SYSTEM ARCHITECTURE
- **Three-Tier Modular Architecture:**
  - **Presentation Layer (Frontend):** Modern responsive HTML5, custom cyber-themed CSS3 design system, Vanilla JS, and Chart.js.
  - **Application Layer (Backend):** Dual-compatible REST API server (Python 3.x native standard library & Node.js Express).
  - **Data Persistence Layer:** SQLite database (`assessments.db`) and JSON document store with ACID persistence.
- **Zero-Dependency Execution:** Capable of running out-of-the-box on standard Python without requiring any external package installations.

---

### SLIDE 8: THE 10 CRITICAL SME THREATS
1. **Phishing:** Deceptive emails, spear phishing, credential harvesting (NIST: Protect).
2. **Ransomware:** Operational data encryption and extortion demands (NIST: Protect/Recover).
3. **Malware:** Trojans, keyloggers, and spyware infiltrating endpoints (NIST: Protect).
4. **Insider Threat:** Disgruntled or negligent staff exfiltrating IP (NIST: Identify).
5. **Data Breach:** Compromise of confidential customer PII or financial data (NIST: Identify/Protect).
6. **Weak Passwords:** Single-factor, guessable, or reused employee credentials (NIST: Protect).
7. **DDoS:** Traffic floods overwhelming e-commerce or client portals (NIST: Respond).
8. **Unpatched Software:** Known unpatched CVEs on servers and workstations (NIST: Protect).
9. **Social Engineering:** BEC wire fraud and executive impersonation (NIST: Protect).
10. **Unauthorized Access:** Exposed remote desktop (RDP 3389) or excessive privileges (NIST: Protect).

---

### SLIDE 9: QUANTITATIVE RISK SCORING MODEL
- **Mathematical Formula:**
  $$\text{Risk Score} = \text{Likelihood (1-5)} \times \text{Severity (1-5)} \times \text{Business Impact (1-5)}$$
  - $\text{Minimum Score} = 1 \times 1 \times 1 = \mathbf{1}$
  - $\text{Maximum Score} = 5 \times 5 \times 5 = \mathbf{125}$
- **Five-Tier Classification System:**
  - **0 – 25 (Low):** Green (`#10b981`) — Acceptable risk / Routine review.
  - **26 – 50 (Moderate):** Amber (`#f59e0b`) — Manageable risk / Standard safeguards.
  - **51 – 75 (High):** Orange (`#f97316`) — Elevated risk / Formal mitigation in 30 days.
  - **76 – 100 (Very High):** Red-Orange (`#ef4444`) — Severe risk / Remediation in 14 days.
  - **101 – 125 (Critical):** Crimson (`#dc2626`) — Catastrophic / Emergency action within 48h.
- **Security Posture Score:**
  $$\text{Posture Score} = \left( \frac{\text{Implemented Controls}}{\text{10 Total Controls}} \right) \times 100\%$$

---

### SLIDE 10: NIST CSF 2.0 INTEGRATION
- **1. IDENTIFY (ID):** Asset management, risk identification, and data classification.
- **2. PROTECT (PR):** Identity management, MFA, endpoint protection, encryption, awareness training, patch hygiene.
- **3. DETECT (DE):** Continuous monitoring, authentication logging, anomaly alerting.
- **4. RESPOND (RS):** Incident response plan, containment, crisis communications.
- **5. RECOVER (RC):** 3-2-1 backup strategy, disaster recovery restoration, post-incident review.
- **Radar Visualization:** Real-time maturity score computed for each of the 5 pillars.

---

### SLIDE 11: EXECUTIVE DASHBOARD & VISUALIZATIONS
- **KPI Metrics:** Overall Risk Index, Security Posture %, Critical/High/Moderate/Low threat counters.
- **5 Real-Time Analytical Charts:**
  1. *Risk Severity Distribution:* Visualizes proportion of high vs low threats.
  2. *Threat Risk Ranking:* Bar chart highlighting top vulnerabilities needing budget.
  3. *Likelihood vs. Impact Correlation:* Bubble plot illustrating exposure clusters.
  4. *NIST CSF 2.0 Maturity:* 5-axis radar chart displaying defensive maturity.
  5. *Controls Implementation Ratio:* Identifies security control gaps.

---

### SLIDE 12: 5×5 RISK MATRIX & RISK REGISTER
- **Interactive 5×5 Matrix:**
  - Plots all 10 threats into exact coordinate cells: Likelihood (X: 1-5) vs Severity (Y: 5-1).
  - Visual heat zones provide instant executive clarity on high-risk clusters.
  - Clickable threat chips open comprehensive remediation drawers.
- **Dynamic Risk Register:**
  - Filterable by threat name, risk level (Critical, High, Moderate, Low), and NIST function.
  - Column sorting by risk score, priority, or likelihood.
  - Instant data export to CSV and JSON formats.

---

### SLIDE 13: CASE STUDY RESULTS (TECHNOVA SOLUTIONS)
- **Profile:** 50 Employees, 75 Devices, 2 Offices, IT Services Sector.
- **Audited Controls:** 5/10 Implemented (50.0% Posture Score — *Needs Improvement*).
  - *Key Gaps:* No MFA, unencrypted laptops, no staff phishing drills, missing log monitoring.
- **Evaluated Risk Findings:**
  - Overall Risk Score: **53.5 / 125 (High Risk)**.
  - Top Threats: Unauthorized Access (80), Data Breach (80), Ransomware (75), Phishing (64).
- **Automated Roadmap:**
  - **Priority 1:** Enforce hardware/app MFA immediately; isolate immutable offline backups.
  - **Priority 2:** Turn on BitLocker disk encryption across all 75 laptops; close external RDP.
  - **Priority 3:** Implement monthly phishing drills and centralized log monitoring.

---

### SLIDE 14: TESTING & SYSTEM VERIFICATION
- **Automated Test Coverage:**
  - 100% of core mathematical algorithms and classification boundaries verified.
  - Edge cases verified: $(1, 1, 1) = 1$ and $(5, 5, 5) = 125$.
  - Clamping verified for out-of-bounds inputs.
  - Ascending priority sorting verified for all mitigation action plans.
  - Legal disclaimer verification confirmed across all generated outputs.

---

### SLIDE 15: CONCLUSION & FUTURE ENHANCEMENTS
- **Project Achievements:**
  - Successfully created a complete, working, professional web-based cybersecurity risk assessment platform for SMEs.
  - Bridged the gap between enterprise security standards (NIST CSF 2.0) and small business resource realities.
  - Delivered transparent mathematical scoring, interactive visual intelligence, and automated report generation.
- **Future Enhancements:**
  - Automated Cloud API integrations (Microsoft Entra ID / Google Workspace).
  - Cyber insurance premium reduction modeling.
  - Machine learning predictive vulnerability scoring.
- **Thank you! Questions & Discussion.**
