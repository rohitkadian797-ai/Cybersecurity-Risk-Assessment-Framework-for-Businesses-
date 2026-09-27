"""
End-to-End System Readiness Verification Script
Validates that the server, API routes, database, static assets, and calculations are 100% operational.
"""

import urllib.request
import json
import sqlite3
from pathlib import Path

BASE_URL = "http://localhost:5000"
DB_PATH = Path(__file__).resolve().parent.parent / "database" / "assessments.db"

results = []

def check(name, success, details=""):
    results.append((name, success, details))
    status_icon = "[PASS]" if success else "[FAIL]"
    print(f"  {status_icon}: {name} {('- ' + details) if details else ''}")

print("\n" + "=" * 60)
print(" SYSTEM READINESS & OPERATIONAL VERIFICATION")
print("=" * 60 + "\n")

# 1. Health check
try:
    with urllib.request.urlopen(f"{BASE_URL}/api/health", timeout=5) as r:
        data = json.loads(r.read().decode())
        check("API Health Check", data.get("status") == "online", f"Status: {data.get('status')}")
except Exception as e:
    check("API Health Check", False, str(e))

# 2. Frontend HTML
try:
    with urllib.request.urlopen(f"{BASE_URL}/", timeout=5) as r:
        content = r.read().decode()
        has_title = "Cybersecurity Risk Assessment Framework" in content
        has_wizard = "id=\"view-wizard\"" in content
        has_matrix = "id=\"view-matrix\"" in content
        has_charts = "chart-threat-ranking" in content
        check("Frontend HTML Rendering", has_title and has_wizard and has_matrix and has_charts, f"Size: {len(content)} bytes")
except Exception as e:
    check("Frontend HTML Rendering", False, str(e))

# 3. CSS Stylesheet
try:
    with urllib.request.urlopen(f"{BASE_URL}/css/styles.css", timeout=5) as r:
        content = r.read().decode()
        has_vars = "--bg-primary" in content and "--risk-critical" in content
        check("CSS Stylesheet Loaded", has_vars, f"Size: {len(content)} bytes")
except Exception as e:
    check("CSS Stylesheet Loaded", False, str(e))

# 4. JS Files
try:
    with urllib.request.urlopen(f"{BASE_URL}/js/api.js", timeout=5) as r:
        content = r.read().decode()
        check("Frontend API Client Loaded", "localCalculateAssessment" in content, f"Size: {len(content)} bytes")
except Exception as e:
    check("Frontend API Client Loaded", False, str(e))

try:
    with urllib.request.urlopen(f"{BASE_URL}/js/app.js", timeout=5) as r:
        content = r.read().decode()
        check("Frontend Application Engine Loaded", "renderCharts" in content and "renderRiskMatrix" in content, f"Size: {len(content)} bytes")
except Exception as e:
    check("Frontend Application Engine Loaded", False, str(e))

# 5. Demo Assessment Endpoint
try:
    with urllib.request.urlopen(f"{BASE_URL}/api/demo/load", timeout=5) as r:
        data = json.loads(r.read().decode())
        asm = data.get("assessment", {})
        score = asm.get("threatResults", {}).get("overallScore")
        posture = asm.get("controlResults", {}).get("score")
        check("Demo Assessment (TechNova Solutions)", data.get("success") and score == 53.5 and posture == 50.0, f"Risk Score: {score}, Posture: {posture}%")
except Exception as e:
    check("Demo Assessment (TechNova Solutions)", False, str(e))

# 6. Custom Assessment Submission (POST)
custom_payload = {
    "isDemo": False,
    "businessInfo": {
        "businessName": "Apex Manufacturing Ltd",
        "industry": "Manufacturing",
        "employees": 120,
        "devices": 180,
        "locations": 3,
        "usesCloud": True,
        "storesCustomerData": True,
        "hasRemoteEmployees": False
    },
    "controls": {
        "firewall": True, "antivirus": True, "mfa": True, "backups": True,
        "encryption": True, "training": True, "patching": True, "access_control": True,
        "monitoring": True, "incident_response": True
    },
    "threats": {
        "phishing": {"likelihood": 2, "severity": 2, "impact": 2},
        "ransomware": {"likelihood": 1, "severity": 4, "impact": 4},
        "malware": {"likelihood": 2, "severity": 2, "impact": 2},
        "insider_threat": {"likelihood": 1, "severity": 2, "impact": 2},
        "data_breach": {"likelihood": 1, "severity": 4, "impact": 3},
        "weak_passwords": {"likelihood": 1, "severity": 3, "impact": 2},
        "ddos": {"likelihood": 1, "severity": 2, "impact": 2},
        "unpatched_software": {"likelihood": 1, "severity": 2, "impact": 2},
        "social_engineering": {"likelihood": 2, "severity": 2, "impact": 2},
        "unauthorized_access": {"likelihood": 1, "severity": 3, "impact": 2}
    }
}

try:
    req = urllib.request.Request(
        f"{BASE_URL}/api/assessments",
        data=json.dumps(custom_payload).encode(),
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=5) as r:
        res = json.loads(r.read().decode())
        asm = res.get("assessment", {})
        posture = asm.get("controlResults", {}).get("score")
        score = asm.get("threatResults", {}).get("overallScore")
        check("Custom Assessment Submission (POST)", posture == 100.0, f"Posture: {posture}% (Strong), Risk Score: {score}")
except Exception as e:
    check("Custom Assessment Submission (POST)", False, str(e))

# 7. SQLite Storage Verification
try:
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM assessments")
    count = c.fetchone()[0]
    conn.close()
    check("SQLite Database Persistence", count >= 2, f"Total saved assessment records: {count}")
except Exception as e:
    check("SQLite Database Persistence", False, str(e))

print("\n" + "=" * 60)
passed = sum(1 for _, ok, _ in results if ok)
failed = sum(1 for _, ok, _ in results if not ok)

if failed == 0:
    print(f" [SUCCESS] ALL {passed} READINESS CHECKS PASSED!")
    print(" The application is 100% READY TO USE!")
else:
    print(f" [FAILED] {failed} CHECKS FAILED out of {len(results)}")
print("=" * 60 + "\n")
