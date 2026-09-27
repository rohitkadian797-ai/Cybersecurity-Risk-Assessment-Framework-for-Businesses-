/**
 * Risk Calculation Engine
 * 
 * Implements the mathematical formulas and classification models for the
 * Cybersecurity Risk Assessment Framework for Small Businesses.
 */

const { THREAT_DEFINITIONS } = require('../data/threatDefinitions');
const { CONTROL_DEFINITIONS } = require('../data/controlDefinitions');

// Risk Level Classification Thresholds
const RISK_LEVELS = {
  LOW: { name: 'Low', min: 0, max: 25, color: '#10b981', badgeClass: 'badge-low', priority: 5 },
  MODERATE: { name: 'Moderate', min: 26, max: 50, color: '#f59e0b', badgeClass: 'badge-moderate', priority: 4 },
  HIGH: { name: 'High', min: 51, max: 75, color: '#f97316', badgeClass: 'badge-high', priority: 3 },
  VERY_HIGH: { name: 'Very High', min: 76, max: 100, color: '#ef4444', badgeClass: 'badge-very-high', priority: 2 },
  CRITICAL: { name: 'Critical', min: 101, max: 125, color: '#dc2626', badgeClass: 'badge-critical', priority: 1 }
};

// Security Posture Classification Thresholds
const POSTURE_LEVELS = {
  STRONG: { name: 'Strong', min: 80, max: 100, color: '#10b981', badgeClass: 'posture-strong' },
  GOOD: { name: 'Good', min: 60, max: 79, color: '#3b82f6', badgeClass: 'posture-good' },
  NEEDS_IMPROVEMENT: { name: 'Needs Improvement', min: 40, max: 59, color: '#f59e0b', badgeClass: 'posture-needs-improvement' },
  WEAK: { name: 'Weak', min: 20, max: 39, color: '#f97316', badgeClass: 'posture-weak' },
  CRITICAL: { name: 'Critical', min: 0, max: 19, color: '#dc2626', badgeClass: 'posture-critical' }
};

/**
 * Calculate single threat risk score
 * Formula: Risk Score = Likelihood × Severity × Business Impact
 * @param {number} likelihood 1-5
 * @param {number} severity 1-5
 * @param {number} impact 1-5
 * @returns {number} Score from 1 to 125
 */
function calculateThreatScore(likelihood, severity, impact) {
  const l = Math.min(5, Math.max(1, parseInt(likelihood, 10) || 1));
  const s = Math.min(5, Math.max(1, parseInt(severity, 10) || 1));
  const i = Math.min(5, Math.max(1, parseInt(impact, 10) || 1));
  return l * s * i;
}

/**
 * Classify a risk score into its corresponding Risk Level
 * @param {number} score
 * @returns {object} Level metadata
 */
function classifyRiskScore(score) {
  const rounded = Math.round(score);
  if (rounded <= 25) return { ...RISK_LEVELS.LOW };
  if (rounded <= 50) return { ...RISK_LEVELS.MODERATE };
  if (rounded <= 75) return { ...RISK_LEVELS.HIGH };
  if (rounded <= 100) return { ...RISK_LEVELS.VERY_HIGH };
  return { ...RISK_LEVELS.CRITICAL };
}

/**
 * Classify a security posture score (0-100)
 * @param {number} score
 * @returns {object} Posture metadata
 */
function classifySecurityPosture(score) {
  const rounded = Math.round(score);
  if (rounded >= 80) return { ...POSTURE_LEVELS.STRONG };
  if (rounded >= 60) return { ...POSTURE_LEVELS.GOOD };
  if (rounded >= 40) return { ...POSTURE_LEVELS.NEEDS_IMPROVEMENT };
  if (rounded >= 20) return { ...POSTURE_LEVELS.WEAK };
  return { ...POSTURE_LEVELS.CRITICAL };
}

/**
 * Calculate security control score
 * Formula: (implemented controls / total controls) × 100
 * @param {object} controls Object mapping controlId -> boolean
 * @returns {object} Implementation stats and score
 */
function calculateSecurityControls(controls = {}) {
  const total = CONTROL_DEFINITIONS.length;
  let implemented = 0;
  const controlDetails = [];

  for (const def of CONTROL_DEFINITIONS) {
    const isImplemented = Boolean(controls[def.id]);
    if (isImplemented) implemented += 1;

    controlDetails.push({
      id: def.id,
      name: def.name,
      nistCategory: def.nistCategory,
      nistSubcategory: def.nistSubcategory,
      implemented: isImplemented,
      description: def.description,
      guidance: def.guidance
    });
  }

  const score = total > 0 ? (implemented / total) * 100 : 0;
  const posture = classifySecurityPosture(score);

  return {
    totalControls: total,
    implementedControls: implemented,
    missingControls: total - implemented,
    score: Math.round(score * 10) / 10,
    postureLevel: posture.name,
    postureColor: posture.color,
    postureBadgeClass: posture.badgeClass,
    controlDetails
  };
}

/**
 * Calculate Threat Assessment results
 * @param {object} threatInputs Object mapping threatId -> { likelihood, severity, impact }
 * @returns {object} Evaluated threats, counts, overall risk
 */
function evaluateThreats(threatInputs = {}) {
  const evaluatedThreats = [];
  let totalScore = 0;
  const counts = {
    critical: 0,
    veryHigh: 0,
    high: 0,
    moderate: 0,
    low: 0
  };

  for (const def of THREAT_DEFINITIONS) {
    const input = threatInputs[def.id] || {};
    const likelihood = parseInt(input.likelihood, 10) || def.defaultLikelihood;
    const severity = parseInt(input.severity, 10) || def.defaultSeverity;
    const impact = parseInt(input.impact, 10) || def.defaultImpact;

    const score = calculateThreatScore(likelihood, severity, impact);
    const classification = classifyRiskScore(score);

    if (classification.name === 'Critical') counts.critical += 1;
    else if (classification.name === 'Very High') counts.veryHigh += 1;
    else if (classification.name === 'High') counts.high += 1;
    else if (classification.name === 'Moderate') counts.moderate += 1;
    else counts.low += 1;

    totalScore += score;

    evaluatedThreats.push({
      id: def.id,
      name: def.name,
      nistCategory: def.nistCategory,
      nistSubcategory: def.nistSubcategory,
      description: def.description,
      smeContext: def.smeContext,
      likelihood,
      severity,
      impact,
      score,
      riskLevel: classification.name,
      riskColor: classification.color,
      badgeClass: classification.badgeClass,
      priority: classification.priority,
      commonMitigations: def.commonMitigations
    });
  }

  // Sort by score descending for ranking
  evaluatedThreats.sort((a, b) => b.score - a.score);

  const threatCount = evaluatedThreats.length;
  const overallScore = threatCount > 0 ? totalScore / threatCount : 0;
  const overallClassification = classifyRiskScore(overallScore);

  return {
    threats: evaluatedThreats,
    overallScore: Math.round(overallScore * 10) / 10,
    overallLevel: overallClassification.name,
    overallColor: overallClassification.color,
    overallBadgeClass: overallClassification.badgeClass,
    counts
  };
}

/**
 * Calculate NIST Cybersecurity Framework (CSF 2.0) maturity scores
 * The 5 Functions: IDENTIFY, PROTECT, DETECT, RESPOND, RECOVER
 * @param {Array} evaluatedThreats
 * @param {Array} controlDetails
 * @returns {object} NIST function posture map
 */
function calculateNistFrameworkPosture(evaluatedThreats, controlDetails) {
  const FUNCTIONS = ['IDENTIFY', 'PROTECT', 'DETECT', 'RESPOND', 'RECOVER'];
  const nistPosture = {};

  for (const fn of FUNCTIONS) {
    const fnControls = controlDetails.filter(c => c.nistCategory === fn);
    const fnThreats = evaluatedThreats.filter(t => t.nistCategory === fn);

    const implemented = fnControls.filter(c => c.implemented).length;
    const total = fnControls.length;
    const controlPercent = total > 0 ? (implemented / total) * 100 : 70; // baseline if no controls directly assigned

    // Calculate threat pressure: average threat score for this function (1-125) normalized to percentage (0-100)
    let avgThreatScore = 0;
    if (fnThreats.length > 0) {
      avgThreatScore = fnThreats.reduce((acc, t) => acc + t.score, 0) / fnThreats.length;
    } else {
      avgThreatScore = 30; // neutral default
    }

    // Resilience formula: Control implementation weighted against threat pressure
    // Higher controls boost score; high threat slightly reduces unless defended
    const threatRiskFactor = (avgThreatScore / 125) * 100;
    const maturityScore = Math.max(0, Math.min(100, Math.round((controlPercent * 0.7) + ((100 - threatRiskFactor) * 0.3))));

    let maturityLevel = 'Tier 1 (Partial)';
    if (maturityScore >= 80) maturityLevel = 'Tier 4 (Adaptive)';
    else if (maturityScore >= 60) maturityLevel = 'Tier 3 (Repeatable)';
    else if (maturityScore >= 40) maturityLevel = 'Tier 2 (Risk Informed)';

    nistPosture[fn] = {
      functionName: fn,
      score: maturityScore,
      maturityLevel,
      controlCoverage: `${implemented}/${total} controls implemented`,
      totalControls: total,
      implementedControls: implemented,
      threatCount: fnThreats.length,
      avgThreatScore: Math.round(avgThreatScore * 10) / 10
    };
  }

  return nistPosture;
}

/**
 * Full Assessment Calculation Pipeline
 * @param {object} input
 * @returns {object} Full calculated report dataset
 */
function calculateAssessment(input = {}) {
  const { businessInfo = {}, controls = {}, threats = {} } = input;

  const controlResults = calculateSecurityControls(controls);
  const threatResults = evaluateThreats(threats);
  const nistResults = calculateNistFrameworkPosture(threatResults.threats, controlResults.controlDetails);

  return {
    businessInfo: {
      businessName: businessInfo.businessName || 'Unnamed SME',
      industry: businessInfo.industry || 'General Business',
      employees: parseInt(businessInfo.employees, 10) || 1,
      devices: parseInt(businessInfo.devices, 10) || 1,
      locations: parseInt(businessInfo.locations, 10) || 1,
      usesCloud: Boolean(businessInfo.usesCloud),
      storesCustomerData: Boolean(businessInfo.storesCustomerData),
      hasRemoteEmployees: Boolean(businessInfo.hasRemoteEmployees)
    },
    threatResults,
    controlResults,
    nistResults,
    calculatedAt: new Date().toISOString()
  };
}

module.exports = {
  RISK_LEVELS,
  POSTURE_LEVELS,
  calculateThreatScore,
  classifyRiskScore,
  classifySecurityPosture,
  calculateSecurityControls,
  evaluateThreats,
  calculateNistFrameworkPosture,
  calculateAssessment
};
