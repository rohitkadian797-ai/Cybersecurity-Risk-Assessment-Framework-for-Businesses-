/**
 * Pre-configured Demo Assessment Data for "TechNova Solutions"
 * Clearly labeled as DEMO DATA for demonstration and testing.
 */

const DEMO_ASSESSMENT_INPUT = {
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
    firewall: true,          // Implemented
    antivirus: true,         // Implemented
    mfa: false,              // Gap: No enterprise MFA
    backups: true,           // Implemented (daily backups)
    encryption: false,       // Gap: Laptops unencrypted
    training: false,         // Gap: No formal staff training
    patching: true,          // Implemented
    access_control: true,    // Implemented (basic directory permissions)
    monitoring: false,       // Gap: No centralized log monitoring
    incident_response: false // Gap: No written IR plan
  },
  threats: {
    phishing: { likelihood: 4, severity: 4, impact: 4 },           // 64 -> High
    ransomware: { likelihood: 3, severity: 5, impact: 5 },         // 75 -> High
    malware: { likelihood: 3, severity: 3, impact: 4 },            // 36 -> Moderate
    insider_threat: { likelihood: 2, severity: 3, impact: 3 },     // 18 -> Low
    data_breach: { likelihood: 4, severity: 5, impact: 4 },        // 80 -> Very High
    weak_passwords: { likelihood: 4, severity: 4, impact: 4 },     // 64 -> High
    ddos: { likelihood: 2, severity: 3, impact: 3 },               // 18 -> Low
    unpatched_software: { likelihood: 3, severity: 3, impact: 4 }, // 36 -> Moderate
    social_engineering: { likelihood: 4, severity: 4, impact: 4 }, // 64 -> High
    unauthorized_access: { likelihood: 4, severity: 4, impact: 5 } // 80 -> Very High
  }
};

module.exports = { DEMO_ASSESSMENT_INPUT };
