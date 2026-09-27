# ACADEMIC PROJECT REPORT

## PROJECT TITLE:
# Cybersecurity Risk Assessment Framework for Small Businesses (SMEs)

**Degree Program:** Minor / Major Project in Computer Science & Engineering / Information Security  
**Academic Year:** 2025 – 2026  
**Framework Alignment:** National Institute of Standards and Technology Cybersecurity Framework (NIST CSF 2.0)  

---

## TABLE OF CONTENTS
1. [Chapter 1 - Introduction](#chapter-1---introduction)
2. [Chapter 2 - Problem Statement](#chapter-2---problem-statement)
3. [Chapter 3 - Project Objectives](#chapter-3---project-objectives)
4. [Chapter 4 - Literature Review & Background Study](#chapter-4---literature-review--background-study)
5. [Chapter 5 - Research & Assessment Methodology](#chapter-5---research--assessment-methodology)
6. [Chapter 6 - System Architecture & Design](#chapter-6---system-architecture--design)
7. [Chapter 7 - Implementation Details](#chapter-7---implementation-details)
8. [Chapter 8 - Quantitative Risk Assessment Model](#chapter-8---quantitative-risk-assessment-model)
9. [Chapter 9 - Experimental Results & Case Study Analysis](#chapter-9---experimental-results--case-study-analysis)
10. [Chapter 10 - Verification & Software Testing](#chapter-10---verification--software-testing)
11. [Chapter 11 - Limitations](#chapter-11---limitations)
12. [Chapter 12 - Future Scope & Enhancements](#chapter-12---future-scope--enhancements)
13. [Chapter 13 - Conclusion](#chapter-13---conclusion)
14. [References](#references)

---

## CHAPTER 1 - INTRODUCTION

### 1.1 Context and Motivation
Small and Medium Enterprises (SMEs) constitute over 90% of business enterprises worldwide, contributing upwards of 50% of employment and generating substantial proportions of national GDP across both developed and emerging economies. Over the last decade, rapid digitalization—accelerated by cloud computing adoption, software-as-a-service (SaaS) toolsets, remote working modalities, and electronic customer records—has fundamentally altered the operational landscape of SMEs.

However, this ubiquitous connectivity has inadvertently transformed small businesses into prime targets for sophisticated cybercrime syndicates. Historically, threat actors prioritized large financial institutions and defense contractors. In contemporary threat environments, adversaries systematically target SMEs, recognizing them as "soft targets" characterized by enterprise-grade data assets but lacking enterprise-grade defensive perimeters.

### 1.2 The Threat Landscape for Small Businesses
Empirical cybersecurity research indicates alarming trends:
- **Disproportionate Targeting**: Approximately 43% of all cyber attacks globally are directed at small businesses.
- **Catastrophic Mortality**: An estimated 60% of small businesses that sustain a severe data breach or ransomware outage become insolvent and shut down within six months.
- **Supply Chain Pivot**: Adversaries exploit vulnerabilities within SME vendors, suppliers, and legal/accounting contractors to compromise tier-1 enterprise partners (e.g., the infamous Target breach originated through a compromised HVAC vendor).

### 1.3 Project Purpose
This project designs, develops, validates, and deploys the **Cybersecurity Risk Assessment Framework for Small Businesses**, a web-based decision-support system. Built strictly on the principles of the **NIST Cybersecurity Framework (CSF 2.0)**, the framework democratizes cybersecurity risk analysis. It replaces expensive external consultancy audits with an accessible, mathematically rigorous, self-service quantitative model.

---

## CHAPTER 2 - PROBLEM STATEMENT

Despite recognizing the catastrophic danger of cyber attacks, SMEs face unique, systemic impediments that prevent effective risk management:

1. **The Resource & Expertise Deficit**: Small businesses rarely employ dedicated Chief Information Security Officers (CISOs) or maintain 24/7 Security Operations Centers (SOCs). IT operations are frequently delegated to generalist office managers or outsourced Managed Service Providers (MSPs) without formal risk oversight.
2. **Inadequacy of Enterprise Frameworks**: Classical risk frameworks—such as ISO/IEC 27005, NIST SP 800-30, and Factor Analysis of Information Risk (FAIR)—require months of manual documentation, statistical telemetry, and specialized risk analyst expertise that small organizations cannot afford.
3. **Ambiguity of Qualitative Audits**: Many informal checklists categorize vulnerabilities into subjective buckets (e.g., "Medium", "High") without transparent mathematical formulas, making it impossible for non-technical business owners to quantify their financial exposure or justify defensive expenditures.
4. **Lack of Prioritized, Actionable Roadmaps**: Vulnerability reports typically generate hundreds of disjointed findings without organizing them into priority tiers or realistic implementation timeframes.

Therefore, an urgent need exists for a lightweight, transparent, standards-aligned cybersecurity risk framework tailored specifically to SME resource constraints.

---

## CHAPTER 3 - OBJECTIVES

The core objectives of this project are:
1. **Analyze Common Cyber Threats in SMEs**: Research and catalog the 10 most damaging cybersecurity threat vectors:
   - Phishing & Email Fraud
   - Ransomware & Extortion
   - Malware Infiltration
   - Insider Threat
   - Customer Data Breach
   - Weak Passwords & Credential Stuffing
   - Distributed Denial of Service (DDoS)
   - Unpatched Software Vulnerabilities
   - Social Engineering / Executive Impersonation
   - Unauthorized Access (Open RDP / Lateral Movement)
2. **Develop a 3-Dimensional Quantitative Risk Evaluation Model**: Formulate a transparent, repeatable risk algorithm:
   $$\text{Risk Score} = \text{Likelihood} \times \text{Severity} \times \text{Business Impact} \quad (\text{Scale: 1 – 125})$$
3. **Establish a 10-Point Security Baseline**: Formulate an audit model evaluating 10 essential security controls and computing an overall **Security Posture Score** ($0\% - 100\%$).
4. **Align with NIST CSF 2.0**: Map all threats, questions, and recommendations to the five core NIST functions: *Identify, Protect, Detect, Respond, and Recover*.
5. **Engineer an Interactive Decision-Support Dashboard**: Build an enterprise-grade UI featuring dynamic Chart.js visualizations, an interactive 5×5 Risk Matrix, and a searchable Risk Register.
6. **Construct a Prioritized Rule-Based Mitigation Engine**: Automate the generation of targeted recommendations categorized into Priority 1 (Immediate / Critical) through Priority 5 (Proactive Maintenance).
7. **Empirically Validate through Case Studies**: Validate the framework using realistic SME case study data (**TechNova Solutions**).

---

## CHAPTER 4 - LITERATURE REVIEW & BACKGROUND STUDY

### 4.1 Evolution of Risk Assessment Models
Information security risk assessment has transitioned through three major paradigms:

1. **Qualitative Models**: Emphasize ordinal rankings (Low, Medium, High). While simple to communicate, qualitative matrices suffer from *range compression* and *reversal errors* (Cox, 2008), where two wildly different risks receive identical visual markers.
2. **Quantitative Models (e.g., FAIR)**: Utilize Monte Carlo simulations and Annualized Loss Expectancy (ALE) calculations:
   $$\text{ALE} = \text{Single Loss Expectancy (SLE)} \times \text{Annualized Rate of Occurrence (ARO)}$$
   While mathematically sound, FAIR requires actuarial loss distribution data that SMEs simply do not collect.
3. **Semi-Quantitative Hybrid Models**: Balance mathematical repeatability with accessible parameter estimation. By combining discrete Likert parameters (1–5) across multi-dimensional criteria (Likelihood, Severity, and Organizational Impact), hybrid models provide sufficient granularity without overwhelming the evaluator.

### 4.2 NIST Cybersecurity Framework (CSF 2.0)
Published by the National Institute of Standards and Technology, the NIST CSF is universally recognized as the gold standard for structuring defensive security programs. Version 2.0 organizes security into five core functions:
- **IDENTIFY**: Pinpointing organizational assets, legal obligations, and threat exposure.
- **PROTECT**: Implementing technological and operational barriers against attack.
- **DETECT**: Providing situational awareness and monitoring to reveal active anomalies.
- **RESPOND**: Orchestrating incident containment and mitigation during active crises.
- **RECOVER**: Restoring operational services and communications following an intrusion.

Our framework systematically maps both threat vectors and defensive controls into these five functions.

---

## CHAPTER 5 - RESEARCH & ASSESSMENT METHODOLOGY

The development methodology followed a structured 5-stage engineering lifecycle:

```
[Phase 1: Threat Modeling & Control Synthesis]
                      │
                      ▼
[Phase 2: Mathematical Risk & Posture Formulation]
                      │
                      ▼
[Phase 3: Rule-Based Mitigation Engine Design]
                      │
                      ▼
[Phase 4: Full-Stack Web Application Engineering]
                      │
                      ▼
[Phase 5: Case Study Validation & Automated Testing]
```

### 5.1 Threat Parameter Definition
For each of the 10 threats, three parameters are quantified on a 1 to 5 scale:
1. **Likelihood ($L$)**: Frequency with which the organization anticipates encountering the threat vector (1 = Rare/Annual, 5 = Continuous/Daily).
2. **Technical Severity ($S$)**: Technical capability of the exploit to compromise confidentiality, integrity, or availability (1 = Negligible, 5 = Complete System Compromise).
3. **Business Impact ($I$)**: Financial, legal, and operational consequences (1 = Minor inconvenience, 5 = Existential threat / Solvency failure).

---

## CHAPTER 6 - SYSTEM ARCHITECTURE & DESIGN

### 6.1 Architectural Overview
The system utilizes a clean three-tier client-server architecture:
- **Presentation Tier**: Single Page Application (SPA) built using modern HTML5, responsive CSS3 variables, and vanilla ES6+ JavaScript. Visual analytics are rendered using Chart.js.
- **Application Tier**: RESTful API server implemented with dual compatibility:
  - Standard Python 3.x (`http.server`, `sqlite3`, `json`) requiring zero external dependencies.
  - Node.js Express server (`server.js`) with Helmet security headers and CORS protection.
- **Data Persistence Tier**: Relational SQLite database (`assessments.db`) maintaining historical assessment runs, organization profiles, and raw metric payloads with ACID transactional integrity.

### 6.2 Data Model Schema
```sql
CREATE TABLE IF NOT EXISTS assessments (
    id TEXT PRIMARY KEY,
    business_name TEXT NOT NULL,
    industry TEXT,
    employees INTEGER,
    devices INTEGER,
    locations INTEGER,
    overall_score REAL,
    overall_level TEXT,
    posture_score REAL,
    posture_level TEXT,
    is_demo INTEGER DEFAULT 0,
    payload_json TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

---

## CHAPTER 7 - IMPLEMENTATION DETAILS

### 7.1 Frontend Architecture
- **State Management**: Centralized application state (`currentAssessment`) in `app.js` drives real-time DOM updates without unnecessary page reloads.
- **Dynamic Assessment Wizard**: A 4-step wizard guides the SME through:
  - Step 1: Organizational metadata & operational exposure attributes.
  - Step 2: 10 Core Security Controls Checklist with NIST subcategory tags.
  - Step 3: Threat Evaluation Sliders with real-time score pills updating on every input event.
  - Step 4: Executive configuration review before submission.
- **Data Visualizations**: Five specialized charts provide multi-dimensional intelligence:
  1. *Risk Severity Distribution*: Doughnut chart breaking down threat classifications.
  2. *Threat Risk Ranking*: Horizontal bar chart ranking all 10 threats from highest to lowest.
  3. *Likelihood vs. Impact Correlation*: Scatter/bubble chart illustrating cluster densities.
  4. *NIST CSF 2.0 Maturity Profile*: Radar chart plotting organizational maturity across all 5 functions.
  5. *Controls Implementation*: Doughnut gauge comparing implemented safeguards against remaining vulnerabilities.

---

## CHAPTER 8 - QUANTITATIVE RISK ASSESSMENT MODEL

### 8.1 Threat Scoring Formulation
$$\text{Score}(t) = L_t \times S_t \times I_t \quad \text{where } L_t, S_t, I_t \in \{1, 2, 3, 4, 5\}$$
The maximum score is:
$$\text{Max Score} = 5 \times 5 \times 5 = 125$$

### 8.2 Five-Tier Classification Boundaries
- **0 – 25**: Low (Acceptable risk profile; baseline operational hygiene)
- **26 – 50**: Moderate (Manageable exposure; defense-in-depth recommended)
- **51 – 75**: High (Elevated operational risk; formal mitigation within 30 days)
- **76 – 100**: Very High (Severe business exposure; intervention within 14 days)
- **101 – 125**: Critical (Catastrophic vulnerability; immediate remediation within 48 hours)

### 8.3 Security Posture Formulation
$$\text{Posture Score} = \left( \frac{\sum_{j=1}^{10} C_j}{10} \right) \times 100\% \quad \text{where } C_j \in \{0, 1\}$$

Maturity Tiers:
- **80% – 100%**: Tier 4 (Adaptive / Strong Posture)
- **60% – 79%**: Tier 3 (Repeatable / Good Posture)
- **40% – 59%**: Tier 2 (Risk-Informed / Needs Improvement)
- **20% – 39%**: Tier 1 (Partial / Weak Posture)
- **0% – 19%**: Tier 0 (Deficient / Critical Posture)

---

## CHAPTER 9 - RESULTS & CASE STUDY ANALYSIS

### 9.1 TechNova Solutions Case Study
To validate the model, the framework was executed against **TechNova Solutions**, a representative IT services SME:
- **Headcount**: 50 employees, 75 managed endpoints, 2 physical sites.
- **Operations**: Cloud-hosted (AWS & M365), stores customer PII, 40% remote workforce.
- **Defensive Audit**:
  - Implemented: Perimeter Firewall, Antivirus/EDR, Regular Backups, Software Patching, Directory Access Controls.
  - **Deficiencies**: Missing Multi-Factor Authentication (MFA), unencrypted laptops, no staff phishing awareness training, no centralized log monitoring, no written Incident Response Plan.

### 9.2 Generated Risk Profile
- **Overall Organization Risk Score**: **53.5 / 125 (High Risk)**
- **Security Posture Score**: **50.0% (Needs Improvement - Tier 2)**
- **Critical & High Threats Identified**:
  - *Unauthorized Access*: Score = $4 \times 4 \times 5 = \mathbf{80}$ (Very High)
  - *Data Breach*: Score = $4 \times 5 \times 4 = \mathbf{80}$ (Very High)
  - *Ransomware*: Score = $3 \times 5 \times 5 = \mathbf{75}$ (High)
  - *Phishing*: Score = $4 \times 4 \times 4 = \mathbf{64}$ (High)
  - *Weak Passwords*: Score = $4 \times 4 \times 4 = \mathbf{64}$ (High)
  - *Social Engineering*: Score = $4 \times 4 \times 4 = \mathbf{64}$ (High)

### 9.3 Generated Prioritized Action Plan
The mitigation engine generated a 10-point roadmap:
1. **Priority 1 (Critical)**: Immediately enforce hardware/app-based MFA across email and cloud portals; isolate offline backups with object-lock immutability.
2. **Priority 2 (Very High)**: Enable full-disk BitLocker/FileVault encryption on all 75 laptops; close external public RDP port 3389.
3. **Priority 3 (High)**: Launch monthly simulated phishing drills; deploy centralized log retention.
4. **Priority 4 & 5**: Formalize an Incident Response playbook and draft quarterly RBAC reviews.

---

## CHAPTER 10 - VERIFICATION & TESTING

Automated test suites were developed in both Python (`unittest`) and Node.js to rigorously verify system stability:

```
[Suite 1: Threat Score Calculation & Edge Cases]
  ✔ PASS: Minimum inputs (1, 1, 1) = 1
  ✔ PASS: Maximum inputs (5, 5, 5) = 125
  ✔ PASS: Lower bound clamping (<1 -> 1)
  ✔ PASS: Upper bound clamping (>5 -> 5)

[Suite 2: Risk Classification Boundaries]
  ✔ PASS: Scores 1 and 25 classified as Low
  ✔ PASS: Scores 26 and 50 classified as Moderate
  ✔ PASS: Scores 51 and 75 classified as High
  ✔ PASS: Scores 76 and 100 classified as Very High
  ✔ PASS: Scores 101 and 125 classified as Critical

[Suite 3: Security Controls & Posture Scoring]
  ✔ PASS: 10/10 controls = 100.0% (Strong)
  ✔ PASS: 0/10 controls = 0.0% (Critical)
  ✔ PASS: 5/10 controls = 50.0% (Needs Improvement)

[Suite 4: NIST CSF 2.0 Alignment]
  ✔ PASS: All 5 functions present and bounded [0, 100]

[Suite 5: Action Plan Prioritization]
  ✔ PASS: Strict ascending priority order sorting (P1 -> P5)
  ✔ PASS: Non-guarantee legal disclaimer presence

All 4 test suites passed with 100% compliance.
```

---

## CHAPTER 11 - LIMITATIONS

1. **Self-Reported Qualitative Input**: The scoring accuracy is contingent upon the honesty and technical literacy of the user entering parameter values.
2. **Static Point-in-Time Assessment**: Risk posture fluctuates dynamically as new Common Vulnerabilities and Exposures (CVEs) emerge; the current model requires periodic manual re-assessment.
3. **Absence of Active Probing**: The application does not perform automated port scanning, vulnerability scanning, or packet sniffing.

---

## CHAPTER 12 - FUTURE SCOPE

1. **Automated Vulnerability Telemetry**: Integrating lightweight agent-based probes or API connectors to Microsoft Graph API and AWS Security Hub to automatically verify MFA enforcement and patch currency.
2. **Cyber Insurance Premium Optimization**: Modeling actuarial discounts on cyber insurance policies achievable through specific control implementations.
3. **Machine Learning Predictive Threat Modeling**: Utilizing historical breach telemetry to predict attack likelihood based on SME industry vertical and employee headcount.

---

## CHAPTER 13 - CONCLUSION

The **Cybersecurity Risk Assessment Framework for Small Businesses** bridges the critical gap between complex, costly enterprise risk methodologies and the pragmatic defensive needs of SMEs. By combining a transparent 3-dimensional scoring algorithm, strict NIST CSF 2.0 mapping, dynamic data visualization, and an intelligent rule-based mitigation engine, the system empowers small business leaders to quantify their threat exposure, allocate defensive budgets efficiently, and take decisive action to protect their organizations against devastating cyber crises.

---

## REFERENCES

1. National Institute of Standards and Technology (NIST). (2024). *The NIST Cybersecurity Framework (CSF) 2.0*. NIST Special Publication. https://doi.org/10.6028/NIST.CSWP.29
2. Cox, L. A. (2008). *What's Wrong with Risk Matrices?* Risk Analysis: An International Journal, 28(2), 497-512.
3. Cybersecurity and Infrastructure Security Agency (CISA). (2023). *Cyber Guidance for Small Businesses*. U.S. Department of Homeland Security.
4. Freund, J., & Jones, J. (2015). *Measuring and Managing Information Risk: A FAIR Approach*. Butterworth-Heinemann.
5. Verizon. (2024). *2024 Data Breach Investigations Report (DBIR)*. Verizon Enterprise Solutions.
6. Ponemon Institute & IBM Security. (2023). *Cost of a Data Breach Report 2023*. IBM Corporation.
7. ENISA (European Union Agency for Cybersecurity). (2022). *Cybersecurity for SMEs: Challenges and Recommendations*.
8. ISO/IEC. (2022). *ISO/IEC 27005:2022 - Information security, cybersecurity and privacy protection — Guidance on managing information security risks*. International Organization for Standardization.
