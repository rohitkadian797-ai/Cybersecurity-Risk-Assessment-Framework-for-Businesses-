"""
Automated Test Suite for Cybersecurity Risk Assessment Framework
Tests risk calculations, classification boundaries, posture scoring, NIST alignment, and edge cases.
Run with: python tests/test_risk_engine.py
"""

import sys
import unittest
from pathlib import Path

# Add backend directory to path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR / "backend"))

from server import (
    calculate_threat_score,
    classify_risk_score,
    classify_posture_score,
    evaluate_assessment,
    THREAT_CATALOG,
    CONTROL_CATALOG
)

class TestCybersecurityRiskFramework(unittest.TestCase):

    def test_single_threat_edge_cases(self):
        """Verify edge cases: Minimum score 1 and Maximum score 125"""
        min_score = calculate_threat_score(1, 1, 1)
        self.assertEqual(min_score, 1, "Minimum inputs (1, 1, 1) must equal 1")

        max_score = calculate_threat_score(5, 5, 5)
        self.assertEqual(max_score, 125, "Maximum inputs (5, 5, 5) must equal 125")

        # Test out of bounds clamping
        self.assertEqual(calculate_threat_score(0, -5, 0), 1, "Lower bounds must clamp to 1")
        self.assertEqual(calculate_threat_score(99, 10, 8), 125, "Upper bounds must clamp to 5 (resulting in 125)")

        # Test intermediate calculation
        self.assertEqual(calculate_threat_score(3, 4, 2), 24, "3 x 4 x 2 must equal 24")
        self.assertEqual(calculate_threat_score(4, 5, 4), 80, "4 x 5 x 4 must equal 80")

    def test_risk_classification_boundaries(self):
        """Verify 5-tier risk classification: Low (0-25), Moderate (26-50), High (51-75), Very High (76-100), Critical (101-125)"""
        self.assertEqual(classify_risk_score(1)["name"], "Low")
        self.assertEqual(classify_risk_score(25)["name"], "Low")

        self.assertEqual(classify_risk_score(26)["name"], "Moderate")
        self.assertEqual(classify_risk_score(50)["name"], "Moderate")

        self.assertEqual(classify_risk_score(51)["name"], "High")
        self.assertEqual(classify_risk_score(75)["name"], "High")

        self.assertEqual(classify_risk_score(76)["name"], "Very High")
        self.assertEqual(classify_risk_score(100)["name"], "Very High")

        self.assertEqual(classify_risk_score(101)["name"], "Critical")
        self.assertEqual(classify_risk_score(125)["name"], "Critical")

    def test_security_posture_scoring(self):
        """Verify Security Posture Score (0 - 100%) and classification"""
        self.assertEqual(classify_posture_score(90)["name"], "Strong")
        self.assertEqual(classify_posture_score(80)["name"], "Strong")
        self.assertEqual(classify_posture_score(70)["name"], "Good")
        self.assertEqual(classify_posture_score(50)["name"], "Needs Improvement")
        self.assertEqual(classify_posture_score(30)["name"], "Weak")
        self.assertEqual(classify_posture_score(10)["name"], "Critical")

    def test_full_assessment_pipeline_demo_data(self):
        """Verify full assessment with TechNova Solutions demo parameters"""
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
                "phishing": {"likelihood": 4, "severity": 4, "impact": 4},           # 64 -> High
                "ransomware": {"likelihood": 3, "severity": 5, "impact": 5},         # 75 -> High
                "malware": {"likelihood": 3, "severity": 3, "impact": 4},            # 36 -> Moderate
                "insider_threat": {"likelihood": 2, "severity": 3, "impact": 3},     # 18 -> Low
                "data_breach": {"likelihood": 4, "severity": 5, "impact": 4},        # 80 -> Very High
                "weak_passwords": {"likelihood": 4, "severity": 4, "impact": 4},     # 64 -> High
                "ddos": {"likelihood": 2, "severity": 3, "impact": 3},               # 18 -> Low
                "unpatched_software": {"likelihood": 3, "severity": 3, "impact": 4}, # 36 -> Moderate
                "social_engineering": {"likelihood": 4, "severity": 4, "impact": 4}, # 64 -> High
                "unauthorized_access": {"likelihood": 4, "severity": 4, "impact": 5} # 80 -> Very High
            }
        }

        result = evaluate_assessment(demo_payload)

        # 1. Controls verification: 5 implemented out of 10 = 50.0%
        self.assertEqual(result["controlResults"]["implementedControls"], 5)
        self.assertEqual(result["controlResults"]["score"], 50.0)
        self.assertEqual(result["controlResults"]["postureLevel"], "Needs Improvement")

        # 2. Threat verification: 10 threats total
        threats = result["threatResults"]["threats"]
        self.assertEqual(len(threats), 10)
        self.assertTrue(result["threatResults"]["overallScore"] > 0)
        self.assertTrue(result["threatResults"]["overallScore"] <= 125)

        # 3. NIST Framework verification
        nist = result["nistResults"]
        for fn in ["IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"]:
            self.assertIn(fn, nist)
            self.assertTrue(0 <= nist[fn]["score"] <= 100)

        # 4. Action Plan verification & sorting (Priority 1 to 5)
        actions = result["mitigationPlan"]["planItems"]
        self.assertTrue(len(actions) > 0)
        for i in range(len(actions) - 1):
            self.assertLessEqual(actions[i]["priority"], actions[i + 1]["priority"], "Mitigation actions must be sorted by Priority ascending")

        # 5. Non-guarantee disclaimer presence
        self.assertIn("DISCLAIMER", result["mitigationPlan"]["disclaimer"])

if __name__ == "__main__":
    print("\n============================================================")
    print(" RUNNING AUTOMATED UNIT & INTEGRATION TESTS (PYTHON)")
    print(" Cybersecurity Risk Assessment Framework for Small Businesses")
    print("============================================================\n")
    unittest.main(verbosity=2)
