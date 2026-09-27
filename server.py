"""
Cybersecurity Risk Assessment Framework for Small Businesses (SMEs)
Python 3.x Standard Library REST API & Web Server
Zero external dependencies required - runs natively on any Python installation.
"""

import sys
import os
import json
import sqlite3
import urllib.parse
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from datetime import datetime

# Paths
BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"
DATABASE_DIR = BASE_DIR / "database"
DB_FILE = DATABASE_DIR / "assessments.db"

# Ensure directories exist
DATABASE_DIR.mkdir(parents=True, exist_ok=True)

# Initialize SQLite Database
def init_db():
    conn = sqlite3.connect(str(DB_FILE))
    cursor = conn.cursor()
    cursor.execute("""
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
        )
    """)
    conn.commit()
    conn.close()

init_db()

# Threat Definitions (10 Core SME Threats)
THREAT_CATALOG = [
    {
        "id": "phishing",
        "name": "Phishing",
        "nistCategory": "PROTECT",
        "nistSubcategory": "PR.AT (Awareness and Training)",
        "description": "Deceptive electronic communications designed to trick employees into revealing credentials or transferring funds.",
        "defaultLikelihood": 4, "defaultSeverity": 4, "defaultImpact": 4,
        "commonMitigations": [
            "Implement ongoing employee phishing awareness & simulation drills",
            "Deploy automated email gateway filtering with DMARC, DKIM, and SPF validation",
            "Enforce Multi-Factor Authentication (MFA) across all email platforms",
            "Establish out-of-band callback verification for financial transactions"
        ]
    },
    {
        "id": "ransomware",
        "name": "Ransomware",
        "nistCategory": "PROTECT",
        "nistSubcategory": "PR.DS (Data Security)",
        "description": "Malicious software encrypting business files and backups, demanding cryptocurrency extortion.",
        "defaultLikelihood": 3, "defaultSeverity": 5, "defaultImpact": 5,
        "commonMitigations": [
            "Maintain immutable 3-2-1 offline or cloud-isolated backups",
            "Deploy Next-Gen Endpoint Detection & Response (EDR) with automated rollback",
            "Implement network segmentation between user subnets and core servers",
            "Develop and rehearse a formal Incident Response and Recovery Plan"
        ]
    },
    {
        "id": "malware",
        "name": "Malware",
        "nistCategory": "PROTECT",
        "nistSubcategory": "PR.PT (Protective Technology)",
        "description": "Hostile software including spyware, trojans, and keyloggers designed to exfiltrate data.",
        "defaultLikelihood": 3, "defaultSeverity": 3, "defaultImpact": 4,
        "commonMitigations": [
            "Deploy centrally managed endpoint protection with heuristic behavioral monitoring",
            "Disable automated USB media execution and enforce software whitelisting",
            "Strip standard employee accounts of local administrative install rights"
        ]
    },
    {
        "id": "insider_threat",
        "name": "Insider Threat",
        "nistCategory": "IDENTIFY",
        "nistSubcategory": "ID.AM (Asset Management)",
        "description": "Risks from employees or contractors misusing legitimate access to exfiltrate data or sabotage systems.",
        "defaultLikelihood": 2, "defaultSeverity": 4, "defaultImpact": 4,
        "commonMitigations": [
            "Enforce Role-Based Access Control (RBAC) and Principle of Least Privilege",
            "Institute a mandatory 4-hour offboarding checklist to revoke single sign-on tokens",
            "Log and monitor sensitive file access and bulk directory downloads"
        ]
    },
    {
        "id": "data_breach",
        "name": "Data Breach",
        "nistCategory": "IDENTIFY",
        "nistSubcategory": "ID.RA (Risk Assessment)",
        "description": "Security incident in which confidential or customer PII is accessed or stolen without authorization.",
        "defaultLikelihood": 3, "defaultSeverity": 5, "defaultImpact": 5,
        "commonMitigations": [
            "Enforce AES-256 disk encryption (BitLocker/FileVault) and TLS 1.3 across networks",
            "Conduct structured data classification (Public, Internal, Confidential, Restricted)",
            "Perform regular external vulnerability scanning and attack surface audits"
        ]
    },
    {
        "id": "weak_passwords",
        "name": "Weak Passwords",
        "nistCategory": "PROTECT",
        "nistSubcategory": "PR.AC (Access Control)",
        "description": "Predictable, reused, or single-factor credentials vulnerable to brute-force attacks and credential stuffing.",
        "defaultLikelihood": 4, "defaultSeverity": 4, "defaultImpact": 4,
        "commonMitigations": [
            "Deploy enterprise Password Manager and mandate 14+ character passphrases",
            "Enforce hardware/authenticator app MFA unconditionally on all SaaS tools",
            "Configure automatic account lockout after 5 consecutive failed login attempts"
        ]
    },
    {
        "id": "ddos",
        "name": "DDoS",
        "nistCategory": "RESPOND",
        "nistSubcategory": "RS.MI (Mitigation)",
        "description": "Volumetric traffic flood overwhelming web servers or client portals, causing service downtime.",
        "defaultLikelihood": 2, "defaultSeverity": 3, "defaultImpact": 4,
        "commonMitigations": [
            "Route public web traffic through a cloud CDN / DDoS mitigation proxy (e.g., Cloudflare)",
            "Implement rate limiting and web application firewall (WAF) filtering",
            "Establish ISP emergency upstream escalation procedures"
        ]
    },
    {
        "id": "unpatched_software",
        "name": "Unpatched Software",
        "nistCategory": "PROTECT",
        "nistSubcategory": "PR.IP (Maintenance)",
        "description": "Failure to apply vendor security updates to operating systems and applications, leaving CVEs exposed.",
        "defaultLikelihood": 4, "defaultSeverity": 4, "defaultImpact": 4,
        "commonMitigations": [
            "Deploy automated patch management (RMM) to update OS and browsers within 14 days",
            "Maintain an active hardware, software, and cloud SaaS inventory",
            "Decommission legacy systems that have reached end-of-life (EOL)"
        ]
    },
    {
        "id": "social_engineering",
        "name": "Social Engineering",
        "nistCategory": "PROTECT",
        "nistSubcategory": "PR.AT (Awareness)",
        "description": "Psychological deception manipulating staff into executing unauthorized wire transfers or sharing passwords.",
        "defaultLikelihood": 3, "defaultSeverity": 4, "defaultImpact": 4,
        "commonMitigations": [
            "Mandate out-of-band phone verification for payment details or vendor bank account changes",
            "Conduct quarterly scenario-based executive impersonation training drills",
            "Promote an open, blameless reporting culture for reporting suspicious requests"
        ]
    },
    {
        "id": "unauthorized_access",
        "name": "Unauthorized Access",
        "nistCategory": "PROTECT",
        "nistSubcategory": "PR.AC (Access Control)",
        "description": "Illicit intrusion via exposed remote desktop ports (RDP 3389), open firewalls, or dormant credentials.",
        "defaultLikelihood": 3, "defaultSeverity": 4, "defaultImpact": 5,
        "commonMitigations": [
            "Disable public RDP exposure and enforce Zero Trust Network Access (ZTNA) or VPN with MFA",
            "Conduct quarterly access reviews and automatically deactivate accounts inactive for 60 days",
            "Apply IP allowlisting and geo-blocking restrictions to administration consoles"
        ]
    }
]

# 10 Core Security Controls
CONTROL_CATALOG = [
    {"id": "firewall", "name": "Hardware/Software Firewall", "nistCategory": "PROTECT", "desc": "Traffic filtering"},
    {"id": "antivirus", "name": "Antivirus / Endpoint EDR", "nistCategory": "PROTECT", "desc": "Next-gen threat defense"},
    {"id": "mfa", "name": "Multi-Factor Authentication (MFA)", "nistCategory": "PROTECT", "desc": "Two-step identity protection"},
    {"id": "backups", "name": "Regular & Immutable Backups", "nistCategory": "RECOVER", "desc": "3-2-1 offline backup copy"},
    {"id": "encryption", "name": "Data Encryption", "nistCategory": "PROTECT", "desc": "AES-256 for disks and TLS 1.3"},
    {"id": "training", "name": "Cybersecurity Training", "nistCategory": "PROTECT", "desc": "Ongoing employee drills"},
    {"id": "patching", "name": "Regular Software Updates", "nistCategory": "PROTECT", "desc": "14-day vulnerability patching"},
    {"id": "access_control", "name": "Access Control & RBAC", "nistCategory": "PROTECT", "desc": "Principle of least privilege"},
    {"id": "monitoring", "name": "Security Event Monitoring", "nistCategory": "DETECT", "desc": "Log analysis and intrusion alerts"},
    {"id": "incident_response", "name": "Incident Response Plan", "nistCategory": "RESPOND", "desc": "Documented recovery playbook"}
]

# Calculation Engine Functions
def calculate_threat_score(likelihood, severity, impact):
    l = min(5, max(1, int(likelihood or 1)))
    s = min(5, max(1, int(severity or 1)))
    i = min(5, max(1, int(impact or 1)))
    return l * s * i

def classify_risk_score(score):
    score = round(score)
    if score <= 25:
        return {"name": "Low", "color": "#10b981", "badgeClass": "badge-low", "priority": 5}
    elif score <= 50:
        return {"name": "Moderate", "color": "#f59e0b", "badgeClass": "badge-moderate", "priority": 4}
    elif score <= 75:
        return {"name": "High", "color": "#f97316", "badgeClass": "badge-high", "priority": 3}
    elif score <= 100:
        return {"name": "Very High", "color": "#ef4444", "badgeClass": "badge-very-high", "priority": 2}
    else:
        return {"name": "Critical", "color": "#dc2626", "badgeClass": "badge-critical", "priority": 1}

def classify_posture_score(score):
    score = round(score)
    if score >= 80:
        return {"name": "Strong", "color": "#10b981", "badgeClass": "posture-strong"}
    elif score >= 60:
        return {"name": "Good", "color": "#3b82f6", "badgeClass": "posture-good"}
    elif score >= 40:
        return {"name": "Needs Improvement", "color": "#f59e0b", "badgeClass": "posture-needs-improvement"}
    elif score >= 20:
        return {"name": "Weak", "color": "#f97316", "badgeClass": "posture-weak"}
    else:
        return {"name": "Critical", "color": "#dc2626", "badgeClass": "posture-critical"}

def evaluate_assessment(payload):
    biz = payload.get("businessInfo", {})
    raw_ctrls = payload.get("controls", {})
    raw_threats = payload.get("threats", {})

    # Evaluate Controls
    implemented_count = 0
    control_details = []
    for c in CONTROL_CATALOG:
        is_imp = bool(raw_ctrls.get(c["id"], False))
        if is_imp:
            implemented_count += 1
        control_details.append({**c, "implemented": is_imp})

    total_controls = len(CONTROL_CATALOG)
    posture_score = round((implemented_count / total_controls) * 100, 1)
    posture_meta = classify_posture_score(posture_score)

    # Evaluate Threats
    total_threat_score = 0
    counts = {"critical": 0, "veryHigh": 0, "high": 0, "moderate": 0, "low": 0}
    evaluated_threats = []

    for t in THREAT_CATALOG:
        user_t = raw_threats.get(t["id"], {})
        l = user_t.get("likelihood", t["defaultLikelihood"])
        s = user_t.get("severity", t["defaultSeverity"])
        i = user_t.get("impact", t["defaultImpact"])
        score = calculate_threat_score(l, s, i)
        risk_meta = classify_risk_score(score)

        if risk_meta["name"] == "Critical": counts["critical"] += 1
        elif risk_meta["name"] == "Very High": counts["veryHigh"] += 1
        elif risk_meta["name"] == "High": counts["high"] += 1
        elif risk_meta["name"] == "Moderate": counts["moderate"] += 1
        else: counts["low"] += 1

        total_threat_score += score
        evaluated_threats.append({
            "id": t["id"],
            "name": t["name"],
            "nistCategory": t["nistCategory"],
            "description": t["description"],
            "likelihood": int(l),
            "severity": int(s),
            "impact": int(i),
            "score": score,
            "riskLevel": risk_meta["name"],
            "riskColor": risk_meta["color"],
            "badgeClass": risk_meta["badgeClass"],
            "priority": risk_meta["priority"],
            "commonMitigations": t["commonMitigations"]
        })

    evaluated_threats.sort(key=lambda x: x["score"], reverse=True)
    overall_score = round(total_threat_score / len(evaluated_threats), 1)
    overall_meta = classify_risk_score(overall_score)

    # NIST Functions
    functions = ["IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"]
    nist_results = {}
    for fn in functions:
        fn_c = [c for c in control_details if c["nistCategory"] == fn]
        fn_t = [t for t in evaluated_threats if t["nistCategory"] == fn]
        imp = len([c for c in fn_c if c["implemented"]])
        tot = len(fn_c)
        ctrl_pct = (imp / tot) * 100 if tot > 0 else 70.0
        avg_thr = sum(t["score"] for t in fn_t) / len(fn_t) if fn_t else 30.0
        score = max(0, min(100, round((ctrl_pct * 0.7) + ((100 - (avg_thr / 125 * 100)) * 0.3))))

        tier = "Tier 1 (Partial)"
        if score >= 80: tier = "Tier 4 (Adaptive)"
        elif score >= 60: tier = "Tier 3 (Repeatable)"
        elif score >= 40: tier = "Tier 2 (Risk Informed)"

        nist_results[fn] = {
            "functionName": fn,
            "score": score,
            "maturityLevel": tier,
            "controlCoverage": f"{imp}/{tot} controls",
            "implementedControls": imp,
            "totalControls": tot,
            "avgThreatScore": round(avg_thr, 1)
        }

    # Action Plan
    plan_items = []
    for t in evaluated_threats:
        plan_items.append({
            "threatId": t["id"],
            "threatName": t["name"],
            "threatScore": t["score"],
            "riskLevel": t["riskLevel"],
            "priority": t["priority"],
            "nistFunction": t["nistCategory"],
            "problem": f"Elevated exposure to {t['name']} attacks compromising SME operations.",
            "action": t["commonMitigations"][0] if t["commonMitigations"] else "Implement defense-in-depth controls.",
            "expectedBenefit": f"Mitigates direct threat attack surface and reduces unauthorized access risk.",
            "suggestedTimeframe": "Immediate" if t["priority"] <= 2 else "30 days"
        })

    plan_items.sort(key=lambda x: x["priority"])

    return {
        "id": f"ASM-{int(datetime.now().timestamp() * 1000)}",
        "createdAt": datetime.now().isoformat(),
        "isDemo": bool(payload.get("isDemo", False)),
        "businessInfo": biz,
        "controlResults": {
            "totalControls": total_controls,
            "implementedControls": implemented_count,
            "missingControls": total_controls - implemented_count,
            "score": posture_score,
            "postureLevel": posture_meta["name"],
            "postureColor": posture_meta["color"],
            "postureBadgeClass": posture_meta["badgeClass"],
            "controlDetails": control_details
        },
        "threatResults": {
            "threats": evaluated_threats,
            "overallScore": overall_score,
            "overallLevel": overall_meta["name"],
            "overallColor": overall_meta["color"],
            "overallBadgeClass": overall_meta["badgeClass"],
            "counts": counts
        },
        "nistResults": nist_results,
        "mitigationPlan": {
            "totalActions": len(plan_items),
            "planItems": plan_items,
            "disclaimer": "DISCLAIMER: This framework provides strategic cybersecurity risk assessment based on NIST CSF 2.0 principles. It does not replace professional penetration testing or formal compliance auditing."
        }
    }

# HTTP Request Handler
class CybersecurityFrameworkHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(FRONTEND_DIR), **kwargs)

    def end_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, DELETE")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/health":
            self.send_json({
                "status": "online",
                "framework": "Cybersecurity Risk Assessment Framework for Small Businesses",
                "runtime": "Python 3.x",
                "nistVersion": "NIST CSF 2.0 Aligned",
                "timestamp": datetime.now().isoformat()
            })
            return

        elif path == "/api/demo/load":
            demo_payload = {
                "isDemo": True,
                "businessInfo": {
                    "businessName": "TechNova Solutions (DEMO DATA)",
                    "industry": "IT Services",
                    "employees": 50,
                    "devices": 75,
                    "locations": 2,
                    "usesCloud": True,
                    "storesCustomerData": True,
                    "hasRemoteEmployees": True
                },
                "controls": {
                    "firewall": True, "antivirus": True, "mfa": False, "backups": True,
                    "encryption": False, "training": False, "patching": True, "access_control": True,
                    "monitoring": False, "incident_response": False
                },
                "threats": {
                    "phishing": {"likelihood": 4, "severity": 4, "impact": 4},
                    "ransomware": {"likelihood": 3, "severity": 5, "impact": 5},
                    "malware": {"likelihood": 3, "severity": 3, "impact": 4},
                    "insider_threat": {"likelihood": 2, "severity": 3, "impact": 3},
                    "data_breach": {"likelihood": 4, "severity": 5, "impact": 4},
                    "weak_passwords": {"likelihood": 4, "severity": 4, "impact": 4},
                    "ddos": {"likelihood": 2, "severity": 3, "impact": 3},
                    "unpatched_software": {"likelihood": 3, "severity": 3, "impact": 4},
                    "social_engineering": {"likelihood": 4, "severity": 4, "impact": 4},
                    "unauthorized_access": {"likelihood": 4, "severity": 4, "impact": 5}
                }
            }
            evaluated = evaluate_assessment(demo_payload)
            self.save_to_sqlite(evaluated)
            self.send_json({"success": True, "isDemo": True, "assessment": evaluated})
            return

        elif path == "/api/assessments":
            conn = sqlite3.connect(str(DB_FILE))
            cursor = conn.cursor()
            cursor.execute("SELECT id, business_name, industry, employees, overall_score, overall_level, posture_score, posture_level, is_demo, created_at FROM assessments ORDER BY created_at DESC")
            rows = cursor.fetchall()
            conn.close()

            results = []
            for r in rows:
                results.append({
                    "id": r[0], "businessName": r[1], "industry": r[2], "employees": r[3],
                    "overallScore": r[4], "overallLevel": r[5], "postureScore": r[6], "postureLevel": r[7],
                    "isDemo": bool(r[8]), "createdAt": r[9]
                })
            self.send_json({"success": True, "count": len(results), "assessments": results})
            return

        # Serve static frontend files
        return super().do_GET()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path in ["/api/assessments", "/api/assessments/calculate"]:
            length = int(self.headers.get("Content-Length", 0))
            raw_body = self.rfile.read(length).decode("utf-8")
            try:
                payload = json.loads(raw_body)
            except Exception as e:
                self.send_error(400, "Invalid JSON payload")
                return

            evaluated = evaluate_assessment(payload)

            if parsed.path == "/api/assessments":
                self.save_to_sqlite(evaluated)

            self.send_json({"success": True, "assessment": evaluated}, status=201)
            return

        self.send_error(404, "Endpoint not found")

    def save_to_sqlite(self, assessment):
        try:
            conn = sqlite3.connect(str(DB_FILE))
            cursor = conn.cursor()
            b = assessment["businessInfo"]
            t = assessment["threatResults"]
            c = assessment["controlResults"]
            cursor.execute("""
                INSERT OR REPLACE INTO assessments 
                (id, business_name, industry, employees, devices, locations, overall_score, overall_level, posture_score, posture_level, is_demo, payload_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                assessment["id"],
                b.get("businessName", "SME"),
                b.get("industry", "General"),
                b.get("employees", 1),
                b.get("devices", 1),
                b.get("locations", 1),
                t["overallScore"],
                t["overallLevel"],
                c["score"],
                c["postureLevel"],
                1 if assessment.get("isDemo") else 0,
                json.dumps(assessment)
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            print("SQLite save error:", e)

    def send_json(self, data, status=200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

if __name__ == "__main__":
    PORT = 5000
    if len(sys.argv) > 1:
        try: PORT = int(sys.argv[1])
        except: pass

    server = HTTPServer(("0.0.0.0", PORT), CybersecurityFrameworkHandler)
    print("====================================================")
    print(f" CYBERSECURITY RISK ASSESSMENT FRAMEWORK FOR SMEs")
    print(f" Server running at: http://localhost:{PORT}")
    print(f" Health Endpoint:  http://localhost:{PORT}/api/health")
    print("====================================================")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer shutting down gracefully.")
        server.server_close()
