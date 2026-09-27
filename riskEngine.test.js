/**
 * Comprehensive Automated Test Suite
 * Tests risk calculation, classification, posture evaluation, mitigation engine, and edge cases.
 * Run directly with: node tests/riskEngine.test.js
 */

const {
  calculateThreatScore,
  classifyRiskScore,
  classifySecurityPosture,
  calculateSecurityControls,
  evaluateThreats,
  calculateNistFrameworkPosture,
  calculateAssessment,
  RISK_LEVELS,
  POSTURE_LEVELS
} = require('../backend/services/riskEngine');

const {
  generateMitigationPlan,
  THREAT_RULES,
  CONTROL_GAP_RULES
} = require('../backend/services/mitigationEngine');

const { DEMO_ASSESSMENT_INPUT } = require('../backend/data/demoData');

let totalTests = 0;
let passedTests = 0;
let failedTests = 0;

function assert(condition, testName, details = '') {
  totalTests += 1;
  if (condition) {
    passedTests += 1;
    console.log(`  \x1b[32m✔ PASS\x1b[0m: ${testName}`);
  } else {
    failedTests += 1;
    console.error(`  \x1b[31m✖ FAIL\x1b[0m: ${testName} - ${details}`);
  }
}

function assertEqual(actual, expected, testName) {
  assert(
    actual === expected,
    testName,
    `Expected [${expected}], but received [${actual}]`
  );
}

console.log('\n============================================================');
console.log(' RUNNING AUTOMATED UNIT & INTEGRATION TESTS');
console.log(' Cybersecurity Risk Assessment Framework for Small Businesses');
console.log('============================================================\n');

// ------------------------------------------------------------
// Test Suite 1: Single Threat Calculation & Edge Cases
// ------------------------------------------------------------
console.log('\x1b[36m[Suite 1: Threat Score Calculation & Edge Cases]\x1b[0m');

// Edge Case 1: Minimum values (1, 1, 1)
const minScore = calculateThreatScore(1, 1, 1);
assertEqual(minScore, 1, 'Edge Case: Minimum inputs (1, 1, 1) must equal 1');

// Edge Case 2: Maximum values (5, 5, 5)
const maxScore = calculateThreatScore(5, 5, 5);
assertEqual(maxScore, 125, 'Edge Case: Maximum inputs (5, 5, 5) must equal 125');

// Clamping test: Out-of-bounds lower inputs
assertEqual(calculateThreatScore(0, -2, -10), 1, 'Out-of-bounds lower values must clamp to 1 (result = 1)');

// Clamping test: Out-of-bounds upper inputs
assertEqual(calculateThreatScore(10, 8, 99), 125, 'Out-of-bounds upper values must clamp to 5 (result = 125)');

// Intermediate calculation
assertEqual(calculateThreatScore(3, 4, 2), 24, 'Intermediate test: 3 × 4 × 2 must equal 24');
assertEqual(calculateThreatScore(4, 5, 4), 80, 'Intermediate test: 4 × 5 × 4 must equal 80');

// ------------------------------------------------------------
// Test Suite 2: Risk Classification Thresholds
// ------------------------------------------------------------
console.log('\n\x1b[36m[Suite 2: Risk Classification Boundaries (0-125)]\x1b[0m');

// 0 - 25 = Low
assertEqual(classifyRiskScore(1).name, 'Low', 'Score 1 classified as Low');
assertEqual(classifyRiskScore(25).name, 'Low', 'Score 25 boundary classified as Low');

// 26 - 50 = Moderate
assertEqual(classifyRiskScore(26).name, 'Moderate', 'Score 26 boundary classified as Moderate');
assertEqual(classifyRiskScore(50).name, 'Moderate', 'Score 50 boundary classified as Moderate');

// 51 - 75 = High
assertEqual(classifyRiskScore(51).name, 'High', 'Score 51 boundary classified as High');
assertEqual(classifyRiskScore(75).name, 'High', 'Score 75 boundary classified as High');

// 76 - 100 = Very High
assertEqual(classifyRiskScore(76).name, 'Very High', 'Score 76 boundary classified as Very High');
assertEqual(classifyRiskScore(100).name, 'Very High', 'Score 100 boundary classified as Very High');

// 101 - 125 = Critical
assertEqual(classifyRiskScore(101).name, 'Critical', 'Score 101 boundary classified as Critical');
assertEqual(classifyRiskScore(125).name, 'Critical', 'Score 125 boundary classified as Critical');

// ------------------------------------------------------------
// Test Suite 3: Security Controls & Posture Calculation
// ------------------------------------------------------------
console.log('\n\x1b[36m[Suite 3: Security Controls & Posture Scoring]\x1b[0m');

// 100% controls implemented
const allControls = {
  firewall: true, antivirus: true, mfa: true, backups: true,
  encryption: true, training: true, patching: true, access_control: true,
  monitoring: true, incident_response: true
};
const fullControlsResult = calculateSecurityControls(allControls);
assertEqual(fullControlsResult.score, 100, 'All 10 controls implemented yields 100% score');
assertEqual(fullControlsResult.postureLevel, 'Strong', '100% score classified as Strong');

// 0% controls implemented
const zeroControlsResult = calculateSecurityControls({});
assertEqual(zeroControlsResult.score, 0, 'No controls implemented yields 0% score');
assertEqual(zeroControlsResult.postureLevel, 'Critical', '0% score classified as Critical posture');

// Partial controls: 5 out of 10 = 50%
const halfControls = {
  firewall: true, antivirus: true, backups: true, patching: true, access_control: true
};
const halfControlsResult = calculateSecurityControls(halfControls);
assertEqual(halfControlsResult.score, 50, '5/10 controls implemented yields 50% score');
assertEqual(halfControlsResult.postureLevel, 'Needs Improvement', '50% score classified as Needs Improvement');

// Posture classification boundaries
assertEqual(classifySecurityPosture(85).name, 'Strong', 'Score 85 classified as Strong');
assertEqual(classifySecurityPosture(70).name, 'Good', 'Score 70 classified as Good');
assertEqual(classifySecurityPosture(45).name, 'Needs Improvement', 'Score 45 classified as Needs Improvement');
assertEqual(classifySecurityPosture(30).name, 'Weak', 'Score 30 classified as Weak');
assertEqual(classifySecurityPosture(10).name, 'Critical', 'Score 10 classified as Critical');

// ------------------------------------------------------------
// Test Suite 4: NIST Cybersecurity Framework Mapping
// ------------------------------------------------------------
console.log('\n\x1b[36m[Suite 4: NIST Cybersecurity Framework Alignment]\x1b[0m');

const evaluatedThreats = evaluateThreats({
  phishing: { likelihood: 4, severity: 4, impact: 4 },
  ransomware: { likelihood: 5, severity: 5, impact: 5 }
});
const nistPosture = calculateNistFrameworkPosture(evaluatedThreats.threats, halfControlsResult.controlDetails);

assert(nistPosture.IDENTIFY !== undefined, 'NIST IDENTIFY function exists');
assert(nistPosture.PROTECT !== undefined, 'NIST PROTECT function exists');
assert(nistPosture.DETECT !== undefined, 'NIST DETECT function exists');
assert(nistPosture.RESPOND !== undefined, 'NIST RESPOND function exists');
assert(nistPosture.RECOVER !== undefined, 'NIST RECOVER function exists');

assert(nistPosture.PROTECT.score >= 0 && nistPosture.PROTECT.score <= 100, 'NIST PROTECT score is bounded between 0 and 100');
assert(typeof nistPosture.PROTECT.maturityLevel === 'string', 'NIST PROTECT has valid maturity tier designation');

// ------------------------------------------------------------
// Test Suite 5: Mitigation Engine & Action Plan Prioritization
// ------------------------------------------------------------
console.log('\n\x1b[36m[Suite 5: Rule-based Mitigation Engine & Priority Sorting]\x1b[0m');

const fullAssessment = calculateAssessment(DEMO_ASSESSMENT_INPUT);
const mitigationPlan = generateMitigationPlan(fullAssessment);

assert(mitigationPlan.totalActions > 0, 'Mitigation engine generated actionable recommendations');
assert(Array.isArray(mitigationPlan.planItems), 'Action plan returned as structured array');

// Verify priority ordering: items must be sorted in ascending order of priority (1, 2, 3...)
let isSorted = true;
for (let i = 0; i < mitigationPlan.planItems.length - 1; i++) {
  if (mitigationPlan.planItems[i].priority > mitigationPlan.planItems[i + 1].priority) {
    isSorted = false;
    break;
  }
}
assert(isSorted, 'Mitigation plan is strictly sorted from Priority 1 (highest) to Priority 5 (lowest)');

// Verify presence of disclaimer
assert(mitigationPlan.disclaimer.includes('DISCLAIMER'), 'Action plan includes mandatory non-guarantee disclaimer');

// ------------------------------------------------------------
// Test Suite 6: Full Assessment Pipeline with Demo Data
// ------------------------------------------------------------
console.log('\n\x1b[36m[Suite 6: End-to-End Demo Assessment Validation]\x1b[0m');

assertEqual(fullAssessment.businessInfo.businessName, 'TechNova Solutions (DEMO DATA)', 'Demo business name set correctly');
assertEqual(fullAssessment.businessInfo.employees, 50, 'Demo employees count is 50');
assertEqual(fullAssessment.businessInfo.devices, 75, 'Demo devices count is 75');
assertEqual(fullAssessment.threatResults.threats.length, 10, 'All 10 required threats evaluated');
assertEqual(fullAssessment.controlResults.totalControls, 10, 'All 10 security controls tracked');

assert(fullAssessment.threatResults.overallScore > 0, 'Overall risk score calculated and strictly positive');
assert(fullAssessment.threatResults.overallScore <= 125, 'Overall risk score does not exceed 125 maximum');

console.log('\n============================================================');
console.log(` TEST SUMMARY: ${passedTests} passed, ${failedTests} failed out of ${totalTests} total assertions.`);
console.log('============================================================\n');

if (failedTests > 0) {
  process.exit(1);
} else {
  console.log('\x1b[32m✔ All automated tests passed successfully with 100% compliance.\x1b[0m\n');
  process.exit(0);
}
