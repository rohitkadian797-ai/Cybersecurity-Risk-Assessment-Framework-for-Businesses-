/**
 * API Client & Local Fallback Engine
 * Provides seamless connectivity to Express REST API with client-side fallback
 */

const API_BASE_URL = window.location.origin.includes('http') ? '' : 'http://localhost:5000';

// Fallback Threats Catalog
const CLIENT_THREAT_CATALOG = [
  { id: 'phishing', name: 'Phishing', nistCategory: 'PROTECT', defaultLikelihood: 4, defaultSeverity: 4, defaultImpact: 4 },
  { id: 'ransomware', name: 'Ransomware', nistCategory: 'PROTECT', defaultLikelihood: 3, defaultSeverity: 5, defaultImpact: 5 },
  { id: 'malware', name: 'Malware', nistCategory: 'PROTECT', defaultLikelihood: 3, defaultSeverity: 3, defaultImpact: 4 },
  { id: 'insider_threat', name: 'Insider Threat', nistCategory: 'IDENTIFY', defaultLikelihood: 2, defaultSeverity: 4, defaultImpact: 4 },
  { id: 'data_breach', name: 'Data Breach', nistCategory: 'IDENTIFY', defaultLikelihood: 3, defaultSeverity: 5, defaultImpact: 5 },
  { id: 'weak_passwords', name: 'Weak Passwords', nistCategory: 'PROTECT', defaultLikelihood: 4, defaultSeverity: 4, defaultImpact: 4 },
  { id: 'ddos', name: 'DDoS', nistCategory: 'RESPOND', defaultLikelihood: 2, defaultSeverity: 3, defaultImpact: 4 },
  { id: 'unpatched_software', name: 'Unpatched Software', nistCategory: 'PROTECT', defaultLikelihood: 4, defaultSeverity: 4, defaultImpact: 4 },
  { id: 'social_engineering', name: 'Social Engineering', nistCategory: 'PROTECT', defaultLikelihood: 3, defaultSeverity: 4, defaultImpact: 4 },
  { id: 'unauthorized_access', name: 'Unauthorized Access', nistCategory: 'PROTECT', defaultLikelihood: 3, defaultSeverity: 4, defaultImpact: 5 }
];

// Fallback Controls Catalog
const CLIENT_CONTROL_CATALOG = [
  { id: 'firewall', name: 'Hardware/Software Firewall', nistCategory: 'PROTECT', description: 'Monitors & filters network traffic' },
  { id: 'antivirus', name: 'Antivirus / Endpoint EDR', nistCategory: 'PROTECT', description: 'Next-gen malware & ransomware defense' },
  { id: 'mfa', name: 'Multi-Factor Authentication (MFA)', nistCategory: 'PROTECT', description: 'Two-step authentication across all logins' },
  { id: 'backups', name: 'Regular & Immutable Backups', nistCategory: 'RECOVER', description: '3-2-1 offline/immutable backup strategy' },
  { id: 'encryption', name: 'Data Encryption', nistCategory: 'PROTECT', description: 'AES-256 for data at rest and TLS in transit' },
  { id: 'training', name: 'Cybersecurity Training', nistCategory: 'PROTECT', description: 'Ongoing employee awareness & phishing drills' },
  { id: 'patching', name: 'Regular Software Updates', nistCategory: 'PROTECT', description: 'Timely OS and app vulnerability patching' },
  { id: 'access_control', name: 'Access Control & RBAC', nistCategory: 'PROTECT', description: 'Principle of Least Privilege access controls' },
  { id: 'monitoring', name: 'Security Event Monitoring', nistCategory: 'DETECT', description: 'Centralized log analysis & intrusion alerts' },
  { id: 'incident_response', name: 'Incident Response Plan', nistCategory: 'RESPOND', description: 'Documented & rehearsed breach recovery procedures' }
];

// Local Calculation Engine (matching backend riskEngine.js)
function localCalculateAssessment(payload) {
  const { businessInfo = {}, controls = {}, threats = {} } = payload;

  // 1. Controls
  const totalControls = CLIENT_CONTROL_CATALOG.length;
  let implemented = 0;
  const controlDetails = CLIENT_CONTROL_CATALOG.map(c => {
    const isImp = Boolean(controls[c.id]);
    if (isImp) implemented += 1;
    return { ...c, implemented: isImp };
  });

  const postureScore = Math.round((implemented / totalControls) * 100);
  let postureLevel = 'Critical';
  let postureColor = '#dc2626';
  let postureBadgeClass = 'posture-critical';

  if (postureScore >= 80) { postureLevel = 'Strong'; postureColor = '#10b981'; postureBadgeClass = 'posture-strong'; }
  else if (postureScore >= 60) { postureLevel = 'Good'; postureColor = '#3b82f6'; postureBadgeClass = 'posture-good'; }
  else if (postureScore >= 40) { postureLevel = 'Needs Improvement'; postureColor = '#f59e0b'; postureBadgeClass = 'posture-needs-improvement'; }
  else if (postureScore >= 20) { postureLevel = 'Weak'; postureColor = '#f97316'; postureBadgeClass = 'posture-weak'; }

  // 2. Threats
  let totalScore = 0;
  const counts = { critical: 0, veryHigh: 0, high: 0, moderate: 0, low: 0 };
  const evaluatedThreats = CLIENT_THREAT_CATALOG.map(t => {
    const input = threats[t.id] || {};
    const l = Math.min(5, Math.max(1, parseInt(input.likelihood, 10) || t.defaultLikelihood));
    const s = Math.min(5, Math.max(1, parseInt(input.severity, 10) || t.defaultSeverity));
    const i = Math.min(5, Math.max(1, parseInt(input.impact, 10) || t.defaultImpact));
    const score = l * s * i;

    let riskLevel = 'Low';
    let riskColor = '#10b981';
    let badgeClass = 'badge-low';
    let priority = 5;

    if (score >= 101) { riskLevel = 'Critical'; riskColor = '#dc2626'; badgeClass = 'badge-critical'; priority = 1; counts.critical += 1; }
    else if (score >= 76) { riskLevel = 'Very High'; riskColor = '#ef4444'; badgeClass = 'badge-very-high'; priority = 2; counts.veryHigh += 1; }
    else if (score >= 51) { riskLevel = 'High'; riskColor = '#f97316'; badgeClass = 'badge-high'; priority = 3; counts.high += 1; }
    else if (score >= 26) { riskLevel = 'Moderate'; riskColor = '#f59e0b'; badgeClass = 'badge-moderate'; priority = 4; counts.moderate += 1; }
    else { counts.low += 1; }

    totalScore += score;

    return {
      id: t.id,
      name: t.name,
      nistCategory: t.nistCategory,
      likelihood: l,
      severity: s,
      impact: i,
      score,
      riskLevel,
      riskColor,
      badgeClass,
      priority
    };
  });

  evaluatedThreats.sort((a, b) => b.score - a.score);
  const overallScore = Math.round((totalScore / evaluatedThreats.length) * 10) / 10;
  let overallLevel = 'Low';
  let overallColor = '#10b981';
  let overallBadgeClass = 'badge-low';

  if (overallScore >= 101) { overallLevel = 'Critical'; overallColor = '#dc2626'; overallBadgeClass = 'badge-critical'; }
  else if (overallScore >= 76) { overallLevel = 'Very High'; overallColor = '#ef4444'; overallBadgeClass = 'badge-very-high'; }
  else if (overallScore >= 51) { overallLevel = 'High'; overallColor = '#f97316'; overallBadgeClass = 'badge-high'; }
  else if (overallScore >= 26) { overallLevel = 'Moderate'; overallColor = '#f59e0b'; overallBadgeClass = 'badge-moderate'; }

  // 3. NIST Functions
  const FUNCTIONS = ['IDENTIFY', 'PROTECT', 'DETECT', 'RESPOND', 'RECOVER'];
  const nistResults = {};
  for (const fn of FUNCTIONS) {
    const fnControls = controlDetails.filter(c => c.nistCategory === fn);
    const fnThreats = evaluatedThreats.filter(t => t.nistCategory === fn);
    const imp = fnControls.filter(c => c.implemented).length;
    const tot = fnControls.length;
    const ctrlPct = tot > 0 ? (imp / tot) * 100 : 70;
    const avgThr = fnThreats.length > 0 ? fnThreats.reduce((a, b) => a + b.score, 0) / fnThreats.length : 30;
    const score = Math.max(0, Math.min(100, Math.round((ctrlPct * 0.7) + ((100 - (avgThr / 125 * 100)) * 0.3))));

    let maturityLevel = 'Tier 1 (Partial)';
    if (score >= 80) maturityLevel = 'Tier 4 (Adaptive)';
    else if (score >= 60) maturityLevel = 'Tier 3 (Repeatable)';
    else if (score >= 40) maturityLevel = 'Tier 2 (Risk Informed)';

    nistResults[fn] = {
      functionName: fn,
      score,
      maturityLevel,
      controlCoverage: `${imp}/${tot} controls`,
      implementedControls: imp,
      totalControls: tot,
      avgThreatScore: Math.round(avgThr * 10) / 10
    };
  }

  // 4. Action Plan
  const planItems = [];
  for (const t of evaluatedThreats) {
    let action = `Strengthen security defenses, technical controls, and operational monitoring against ${t.name}.`;
    let benefit = `Reduces SME exposure to ${t.name} attacks.`;
    let timeframe = '30 days';

    if (t.id === 'phishing') {
      action = 'Implement mandatory employee phishing awareness simulations and enforce Multi-Factor Authentication (MFA).';
      benefit = 'Reduces credential harvesting success rate by 99% and trains staff as an active human defense.';
      timeframe = 'Immediate (1-2 weeks)';
    } else if (t.id === 'ransomware') {
      action = 'Deploy immutable 3-2-1 offline backups, endpoint EDR, and implement network segmentation.';
      benefit = 'Guarantees disaster recovery without paying extortion demands.';
      timeframe = 'Immediate (48 hours)';
    } else if (t.id === 'data_breach') {
      action = 'Enforce AES-256 full disk encryption, data classification, and regular third-party security audits.';
      benefit = 'Protects customer PII from disclosure and satisfies regulatory standards (GDPR, HIPAA, PCI).';
      timeframe = '1 - 2 weeks';
    } else if (t.id === 'weak_passwords') {
      action = 'Deploy enterprise Password Manager and enforce 14+ character passphrases with mandatory MFA.';
      benefit = 'Eliminates credential stuffing and brute-force vulnerabilities.';
      timeframe = 'Immediate';
    } else if (t.id === 'unauthorized_access') {
      action = 'Disable open external RDP (port 3389) and place administration behind secure VPN / ZTNA.';
      benefit = 'Closes primary entry point exploited by ransomware syndicates.';
      timeframe = 'Immediate';
    }

    planItems.push({
      threatId: t.id,
      threatName: t.name,
      threatScore: t.score,
      riskLevel: t.riskLevel,
      priority: t.priority,
      nistFunction: t.nistCategory,
      problem: `High likelihood and potential business disruption from ${t.name}.`,
      action,
      expectedBenefit: benefit,
      suggestedTimeframe: timeframe
    });
  }

  planItems.sort((a, b) => a.priority - b.priority);

  return {
    id: `ASM-${Date.now()}`,
    createdAt: new Date().toISOString(),
    isDemo: Boolean(payload.isDemo),
    businessInfo,
    controlResults: {
      totalControls,
      implementedControls: implemented,
      missingControls: totalControls - implemented,
      score: postureScore,
      postureLevel,
      postureColor,
      postureBadgeClass,
      controlDetails
    },
    threatResults: {
      threats: evaluatedThreats,
      overallScore,
      overallLevel,
      overallColor,
      overallBadgeClass,
      counts
    },
    nistResults,
    mitigationPlan: {
      totalActions: planItems.length,
      planItems,
      disclaimer: 'DISCLAIMER: This framework provides risk assessment and mitigation guidance based on NIST CSF 2.0 principles. It does not replace professional penetration testing or formal compliance certification.'
    }
  };
}

const apiClient = {
  async submitAssessment(payload) {
    try {
      const res = await fetch(`${API_BASE_URL}/api/assessments`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      if (res.ok) {
        const data = await res.json();
        return data.assessment;
      }
    } catch (e) {
      console.warn('Backend API unavailable. Utilizing local calculation engine.', e);
    }
    // Fallback to local calculation
    const calculated = localCalculateAssessment(payload);
    // Cache in local storage
    const existing = JSON.parse(localStorage.getItem('sme_assessments') || '[]');
    existing.unshift(calculated);
    localStorage.setItem('sme_assessments', JSON.stringify(existing));
    return calculated;
  },

  async loadDemoAssessment() {
    try {
      const res = await fetch(`${API_BASE_URL}/api/demo/load`);
      if (res.ok) {
        const data = await res.json();
        return data.assessment;
      }
    } catch (e) {
      console.warn('Backend API unavailable for demo. Utilizing client demo dataset.', e);
    }

    const demoPayload = {
      isDemo: true,
      businessInfo: {
        businessName: 'TechNova Solutions (DEMO DATA)',
        industry: 'IT Services',
        employees: 50,
        devices: 75,
        locations: 2,
        usesCloud: true,
        storesCustomerData: true,
        hasRemoteEmployees: true
      },
      controls: {
        firewall: true, antivirus: true, mfa: false, backups: true,
        encryption: false, training: false, patching: true, access_control: true,
        monitoring: false, incident_response: false
      },
      threats: {
        phishing: { likelihood: 4, severity: 4, impact: 4 },
        ransomware: { likelihood: 3, severity: 5, impact: 5 },
        malware: { likelihood: 3, severity: 3, impact: 4 },
        insider_threat: { likelihood: 2, severity: 3, impact: 3 },
        data_breach: { likelihood: 4, severity: 5, impact: 4 },
        weak_passwords: { likelihood: 4, severity: 4, impact: 4 },
        ddos: { likelihood: 2, severity: 3, impact: 3 },
        unpatched_software: { likelihood: 3, severity: 3, impact: 4 },
        social_engineering: { likelihood: 4, severity: 4, impact: 4 },
        unauthorized_access: { likelihood: 4, severity: 4, impact: 5 }
      }
    };

    return localCalculateAssessment(demoPayload);
  },

  async getAssessments() {
    try {
      const res = await fetch(`${API_BASE_URL}/api/assessments`);
      if (res.ok) {
        const data = await res.json();
        return data.assessments;
      }
    } catch (e) {
      console.warn('Fetching assessments from localStorage fallback');
    }
    const stored = JSON.parse(localStorage.getItem('sme_assessments') || '[]');
    return stored.map(s => ({
      id: s.id,
      createdAt: s.createdAt,
      isDemo: s.isDemo,
      businessName: s.businessInfo?.businessName || 'Unnamed SME',
      industry: s.businessInfo?.industry || 'Unknown',
      overallScore: s.threatResults?.overallScore || 0,
      overallLevel: s.threatResults?.overallLevel || 'Unknown',
      overallColor: s.threatResults?.overallColor || '#94a3b8',
      postureScore: s.controlResults?.score || 0,
      postureLevel: s.controlResults?.postureLevel || 'Unknown',
      criticalRisks: s.threatResults?.counts?.critical || 0,
      highRisks: s.threatResults?.counts?.high || 0
    }));
  }
};
