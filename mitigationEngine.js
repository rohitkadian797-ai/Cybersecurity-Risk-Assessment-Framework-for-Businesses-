/**
 * Intelligent Rule-Based Mitigation Engine
 * Generates prioritized, actionable cybersecurity mitigation strategies
 * customized to the SME's threat scores and security control deficiencies.
 */

/**
 * Detailed rulebase for threat mitigation
 */
const THREAT_RULES = {
  phishing: {
    threatName: 'Phishing',
    nistFunction: 'PROTECT',
    timeframe: 'Immediate (1 - 2 Weeks)',
    actions: [
      {
        problem: 'Employees vulnerable to deceptive phishing emails, spoofed sender domains, and credential harvesting links.',
        action: 'Deploy automated email gateway protection with SPF/DKIM/DMARC enforcement and launch monthly simulated phishing tests.',
        benefit: 'Reduces phishing link click-through rate by up to 75% and filters out 99%+ of commodity phishing attacks before reaching inboxes.',
        suggestedTimeframe: '1 - 2 weeks'
      },
      {
        problem: 'Single-factor authentication allows compromised passwords from phishing to grant full account takeover.',
        action: 'Mandate hardware or app-based Multi-Factor Authentication (MFA) across all email suites (Google Workspace / Microsoft 365).',
        benefit: 'Blocks 99.9% of automated account takeover attempts even if credentials are leaked.',
        suggestedTimeframe: 'Immediate'
      }
    ]
  },
  ransomware: {
    threatName: 'Ransomware',
    nistFunction: 'PROTECT',
    timeframe: 'Immediate (Critical)',
    actions: [
      {
        problem: 'Online network shares and connected backups are easily encrypted or deleted by active ransomware strains.',
        action: 'Enforce 3-2-1 backup strategy with immutable cloud storage (object lock) or an air-gapped offline storage repository.',
        benefit: 'Guarantees operational restoration without paying extortion fees or suffering permanent data loss.',
        suggestedTimeframe: 'Immediate (Within 48 hours)'
      },
      {
        problem: 'Traditional signature-based antivirus fails to detect zero-day or polymorphic ransomware payloads.',
        action: 'Deploy Next-Generation Endpoint Detection & Response (EDR) with automated behavioral containment and file rollback.',
        benefit: 'Stops encryption in milliseconds upon heuristic detection and isolates infected nodes from spreading across the LAN.',
        suggestedTimeframe: '1 - 2 weeks'
      },
      {
        problem: 'Flat network architectures allow ransomware to rapidly traverse from one infected workstation to production servers.',
        action: 'Implement VLAN segmentation, firewall access control lists (ACLs), and disable SMBv1.',
        benefit: 'Constrains malicious payloads to isolated subnets and prevents enterprise-wide paralysis.',
        suggestedTimeframe: '30 days'
      }
    ]
  },
  malware: {
    threatName: 'Malware',
    nistFunction: 'PROTECT',
    timeframe: '1 - 2 Weeks',
    actions: [
      {
        problem: 'Trojan horses, keyloggers, and spyware entering through unapproved downloads and unauthorized USB drives.',
        action: 'Configure centralized endpoint policies to block unauthorized script execution and disable auto-run on removable media.',
        benefit: 'Eliminates drive-by infections and physical USB drop attacks.',
        suggestedTimeframe: '1 - 2 weeks'
      },
      {
        problem: 'Standard users possess administrative privileges enabling silent background malware installations.',
        action: 'Strip local administrative rights from all standard employee accounts and utilize dedicated admin credentials for maintenance.',
        benefit: 'Prevents 85% of critical Windows malware exploits from acquiring persistence or system-level privileges.',
        suggestedTimeframe: '2 - 3 weeks'
      }
    ]
  },
  insider_threat: {
    threatName: 'Insider Threat',
    nistFunction: 'IDENTIFY',
    timeframe: '30 Days',
    actions: [
      {
        problem: 'Over-permissive shared folders and loose access rights allow disgruntled or departing staff to exfiltrate confidential files.',
        action: 'Implement strict Role-Based Access Control (RBAC), enforce Principle of Least Privilege, and audit file permissions quarterly.',
        benefit: 'Ensures staff only access information strictly necessary for their active duties, preventing bulk unauthorized IP exfiltration.',
        suggestedTimeframe: '30 days'
      },
      {
        problem: 'Delayed offboarding leaves former employees with lingering access to corporate email, cloud SaaS, and internal portals.',
        action: 'Institute a mandatory 4-hour offboarding checklist to revoke single sign-on tokens, reset passwords, and repossess devices.',
        benefit: 'Eliminates unauthorized access by former staff and third-party contractors.',
        suggestedTimeframe: 'Immediate'
      }
    ]
  },
  data_breach: {
    threatName: 'Data Breach',
    nistFunction: 'IDENTIFY',
    timeframe: 'Immediate to 30 Days',
    actions: [
      {
        problem: 'Customer records, financial numbers, and personally identifiable information (PII) stored in plaintext.',
        action: 'Apply AES-256 encryption across all laptops (BitLocker/FileVault), backup archives, and database volumes.',
        benefit: 'Prevents data disclosure even if hardware devices are stolen, lost, or improperly disposed of.',
        suggestedTimeframe: '1 - 2 weeks'
      },
      {
        problem: 'Lack of visibility into where sensitive business data resides across email, local drives, and third-party cloud apps.',
        action: 'Conduct formal data classification: categorize data into Public, Internal, Confidential, and Restricted.',
        benefit: 'Enables focused security controls on highest-risk data assets, satisfying regulatory obligations (GDPR, HIPAA, PCI-DSS).',
        suggestedTimeframe: '30 days'
      }
    ]
  },
  weak_passwords: {
    threatName: 'Weak Passwords',
    nistFunction: 'PROTECT',
    timeframe: 'Immediate',
    actions: [
      {
        problem: 'Employees use short, easily guessed, or reused passwords across personal and corporate systems.',
        action: 'Deploy a company-wide enterprise Password Manager (e.g., 1Password or Bitwarden) and enforce minimum 14-character passphrases.',
        benefit: 'Eliminates credential reuse and ensures high cryptographic entropy across all corporate logins.',
        suggestedTimeframe: 'Immediate'
      },
      {
        problem: 'Online services vulnerable to dictionary attacks and automated brute-forcing.',
        action: 'Configure automatic lockout policies (5 attempts) and ban commonly breached passwords using HaveIBeenPwned database checks.',
        benefit: 'Thwarts automated credential stuffing and dictionary attacks.',
        suggestedTimeframe: '1 week'
      }
    ]
  },
  ddos: {
    threatName: 'DDoS',
    nistFunction: 'RESPOND',
    timeframe: '30 - 60 Days',
    actions: [
      {
        problem: 'Customer-facing web services, e-commerce stores, or client portals susceptible to volumetric or application-layer floods.',
        action: 'Route web traffic through an enterprise Cloud CDN / DDoS mitigation proxy (e.g., Cloudflare, AWS CloudFront) with rate limiting.',
        benefit: 'Absorbs multi-gigabit traffic floods at edge networks, maintaining 99.9% uptime during deliberate denial-of-service attempts.',
        suggestedTimeframe: '30 days'
      }
    ]
  },
  unpatched_software: {
    threatName: 'Unpatched Software',
    nistFunction: 'PROTECT',
    timeframe: '1 - 2 Weeks',
    actions: [
      {
        problem: 'Laptops, servers, routers, and CMS platforms running outdated versions with publicly published CVE vulnerabilities.',
        action: 'Deploy automated remote monitoring and patch management (RMM) tooling to apply critical OS and application updates within 14 days.',
        benefit: 'Closes known exploitation windows that automated vulnerability scanners and botnets actively scan for.',
        suggestedTimeframe: '1 - 2 weeks'
      },
      {
        problem: 'Unknown shadow IT hardware and uninventoried legacy software running without maintenance.',
        action: 'Establish an automated network asset discovery tool and maintain an active software inventory with end-of-support dates.',
        benefit: 'Provides 100% visibility into attack surface exposure and forces timely decommissioning of obsolete software.',
        suggestedTimeframe: '30 days'
      }
    ]
  },
  social_engineering: {
    threatName: 'Social Engineering',
    nistFunction: 'PROTECT',
    timeframe: '2 - 4 Weeks',
    actions: [
      {
        problem: 'Fraudsters impersonating executives, suppliers, or IT support via phone or email to authorize wire transfers or credential resets.',
        action: 'Institute a mandatory out-of-band callback verification rule using verified phone numbers for all banking and wire transfer changes.',
        benefit: 'Neutralizes Business Email Compromise (BEC) and executive impersonation scams completely.',
        suggestedTimeframe: 'Immediate'
      },
      {
        problem: 'Staff lack confidence to challenge suspicious authority requests or report errors due to fear of reprimand.',
        action: 'Foster a blameless security culture with clear, anonymous, and rewarded incident reporting channels.',
        benefit: 'Dramatically cuts incident detection time from days to minutes through rapid employee reporting.',
        suggestedTimeframe: '30 days'
      }
    ]
  },
  unauthorized_access: {
    threatName: 'Unauthorized Access',
    nistFunction: 'PROTECT',
    timeframe: 'Immediate to 2 Weeks',
    actions: [
      {
        problem: 'Remote Desktop Protocol (RDP) or administrative interfaces exposed directly to the public internet.',
        action: 'Immediately disable open external RDP (port 3389) and place all remote administration behind a secure VPN with MFA or ZTNA.',
        benefit: 'Blocks the primary pathway used by ransomware gangs for initial SME perimeter breach.',
        suggestedTimeframe: 'Immediate'
      },
      {
        problem: 'Dormant user accounts, former contractor profiles, and orphaned credentials remain active indefinitely.',
        action: 'Establish automated monthly access reviews and enable automatic account deactivation after 60 days of inactivity.',
        benefit: 'Minimizes stale attack surface and prevents credential exploitation.',
        suggestedTimeframe: '30 days'
      }
    ]
  }
};

/**
 * Control Gap Rules: Specific mitigations when a security control is missing
 */
const CONTROL_GAP_RULES = {
  firewall: {
    name: 'Hardware/Software Firewall',
    nistFunction: 'PROTECT',
    priority: 2,
    problem: 'Perimeter firewall is missing or not properly managed, exposing internal network ports.',
    action: 'Install a dedicated Next-Gen Firewall (NGFW) or enable managed host-based firewalls with default-inbound-deny rules.',
    benefit: 'Blocks unauthorized incoming scans and restricts malicious egress traffic.',
    suggestedTimeframe: '1 - 2 weeks'
  },
  antivirus: {
    name: 'Antivirus / Endpoint Protection (EDR)',
    nistFunction: 'PROTECT',
    priority: 1,
    problem: 'No centralized endpoint detection or antivirus protection on company workstations.',
    action: 'Deploy centrally managed cloud EDR across 100% of workstations and servers.',
    benefit: 'Provides real-time malware interception and threat isolation capabilities.',
    suggestedTimeframe: 'Immediate'
  },
  mfa: {
    name: 'Multi-Factor Authentication (MFA)',
    nistFunction: 'PROTECT',
    priority: 1,
    problem: 'MFA is not enforced, leaving accounts unprotected against single credential compromise.',
    action: 'Turn on mandatory MFA for email, VPN, cloud storage, and payroll systems immediately.',
    benefit: 'Prevents 99% of unauthorized logins from stolen or guessed passwords.',
    suggestedTimeframe: 'Immediate'
  },
  backups: {
    name: 'Regular & Immutable Backups',
    nistFunction: 'RECOVER',
    priority: 1,
    problem: 'Backups are irregular, untested, or connected to the primary network without immutability.',
    action: 'Configure automated daily incremental and weekly full backups adhering to 3-2-1 rules with air-gapped/cloud-locked storage.',
    benefit: 'Ensures business survival and zero data loss after ransomware or hardware failure.',
    suggestedTimeframe: 'Immediate'
  },
  encryption: {
    name: 'Data Encryption',
    nistFunction: 'PROTECT',
    priority: 2,
    problem: 'Endpoints and sensitive files are unencrypted, creating massive data breach liabilities if devices are misplaced.',
    action: 'Enable BitLocker (Windows) or FileVault (macOS) via group policy or MDM across all portable devices.',
    benefit: 'Renders stolen drive data completely unreadable without recovery keys.',
    suggestedTimeframe: '2 weeks'
  },
  training: {
    name: 'Cybersecurity Awareness Training',
    nistFunction: 'PROTECT',
    priority: 3,
    problem: 'Employees have received no structured security education or phishing awareness training.',
    action: 'Schedule quarterly interactive security training sessions and run randomized phishing drills.',
    benefit: 'Transforms employees into an alert first line of defense against social engineering.',
    suggestedTimeframe: '30 days'
  },
  patching: {
    name: 'Regular Software Updates',
    nistFunction: 'PROTECT',
    priority: 2,
    problem: 'Software patching is performed ad-hoc or neglected, leaving known vulnerabilities open.',
    action: 'Implement automated patching schedules with mandatory reboot windows within 14 days of patch release.',
    benefit: 'Eliminates low-hanging fruit vulnerabilities targeted by automated cybercrime tools.',
    suggestedTimeframe: '2 weeks'
  },
  access_control: {
    name: 'Access Control & RBAC',
    nistFunction: 'PROTECT',
    priority: 2,
    problem: 'Lack of role-based access controls permits broad user permissions across sensitive corporate repositories.',
    action: 'Review and segregate folder permissions so users only access files required for their specific responsibilities.',
    benefit: 'Prevents lateral spread of breaches and limits data leakage.',
    suggestedTimeframe: '30 days'
  },
  monitoring: {
    name: 'Security Event Monitoring',
    nistFunction: 'DETECT',
    priority: 3,
    problem: 'System and authentication logs are not monitored, leaving security breaches undetected for months.',
    action: 'Enable centralized logging for critical services and configure real-time alerts for repeat failed logins and privilege escalations.',
    benefit: 'Drastically reduces dwell time and enables proactive incident containment.',
    suggestedTimeframe: '45 days'
  },
  incident_response: {
    name: 'Incident Response Plan',
    nistFunction: 'RESPOND',
    priority: 3,
    problem: 'No documented response protocol exists for cyber emergencies, creating panic and prolonged downtime.',
    action: 'Draft and circulate an SME Incident Response playbook with emergency phone trees, legal contacts, and recovery steps.',
    benefit: 'Ensures orderly, legal-compliant, and rapid containment during an active cyber incident.',
    suggestedTimeframe: '60 days'
  }
};

/**
 * Generate prioritized recommendations from assessment results
 * @param {object} assessmentResults Output from riskEngine.calculateAssessment
 * @returns {object} Prioritized Action Plan & summary metrics
 */
function generateMitigationPlan(assessmentResults) {
  const { threatResults, controlResults } = assessmentResults;
  const planItems = [];
  const addedActionKeys = new Set();

  // 1. Process threats based on calculated risk score
  for (const threat of threatResults.threats) {
    const rules = THREAT_RULES[threat.id];
    if (!rules) continue;

    // Only generate high-priority recommendations for Critical, Very High, and High risks,
    // or moderate risks with elevated likelihood/severity
    if (threat.score >= 51 || threat.riskLevel === 'Critical' || threat.riskLevel === 'Very High' || threat.riskLevel === 'High') {
      for (const item of rules.actions) {
        const uniqueKey = `${threat.id}-${item.action.slice(0, 20)}`;
        if (addedActionKeys.has(uniqueKey)) continue;
        addedActionKeys.add(uniqueKey);

        planItems.push({
          threatId: threat.id,
          threatName: threat.name,
          threatScore: threat.score,
          riskLevel: threat.riskLevel,
          priority: threat.priority, // 1: Critical, 2: Very High, 3: High, 4: Moderate, 5: Low
          nistFunction: rules.nistFunction,
          problem: item.problem,
          action: item.action,
          expectedBenefit: item.benefit,
          suggestedTimeframe: item.suggestedTimeframe,
          originType: 'threat_risk'
        });
      }
    } else if (threat.score >= 26) {
      // Moderate threat: include primary action at Priority 4
      const primaryItem = rules.actions[0];
      const uniqueKey = `${threat.id}-${primaryItem.action.slice(0, 20)}`;
      if (!addedActionKeys.has(uniqueKey)) {
        addedActionKeys.add(uniqueKey);
        planItems.push({
          threatId: threat.id,
          threatName: threat.name,
          threatScore: threat.score,
          riskLevel: threat.riskLevel,
          priority: 4,
          nistFunction: rules.nistFunction,
          problem: primaryItem.problem,
          action: primaryItem.action,
          expectedBenefit: primaryItem.benefit,
          suggestedTimeframe: primaryItem.suggestedTimeframe,
          originType: 'threat_risk'
        });
      }
    } else {
      // Low threat: include proactive baseline recommendation at Priority 5
      const primaryItem = rules.actions[0];
      const uniqueKey = `${threat.id}-${primaryItem.action.slice(0, 20)}`;
      if (!addedActionKeys.has(uniqueKey)) {
        addedActionKeys.add(uniqueKey);
        planItems.push({
          threatId: threat.id,
          threatName: threat.name,
          threatScore: threat.score,
          riskLevel: threat.riskLevel,
          priority: 5,
          nistFunction: rules.nistFunction,
          problem: `Proactive baseline maintenance for ${threat.name}.`,
          action: primaryItem.action,
          expectedBenefit: primaryItem.benefit,
          suggestedTimeframe: '90 days / Continuous',
          originType: 'proactive_baseline'
        });
      }
    }
  }

  // 2. Process Security Control Deficiencies (Missing Controls)
  for (const control of controlResults.controlDetails) {
    if (!control.implemented) {
      const gapRule = CONTROL_GAP_RULES[control.id];
      if (gapRule) {
        const uniqueKey = `control-${control.id}`;
        if (!addedActionKeys.has(uniqueKey)) {
          addedActionKeys.add(uniqueKey);
          planItems.push({
            threatId: `control_${control.id}`,
            threatName: `Control Gap: ${gapRule.name}`,
            threatScore: null,
            riskLevel: gapRule.priority === 1 ? 'Critical' : gapRule.priority === 2 ? 'Very High' : 'High',
            priority: gapRule.priority,
            nistFunction: gapRule.nistFunction,
            problem: gapRule.problem,
            action: gapRule.action,
            expectedBenefit: gapRule.benefit,
            suggestedTimeframe: gapRule.suggestedTimeframe,
            originType: 'control_gap'
          });
        }
      }
    }
  }

  // Sort plan by Priority ascending (1 -> 2 -> 3 -> 4 -> 5)
  planItems.sort((a, b) => a.priority - b.priority);

  // Group into Priority Tiers
  const groupedPlan = {
    priority1: planItems.filter(item => item.priority === 1), // Critical
    priority2: planItems.filter(item => item.priority === 2), // Very High
    priority3: planItems.filter(item => item.priority === 3), // High
    priority4: planItems.filter(item => item.priority === 4), // Moderate
    priority5: planItems.filter(item => item.priority === 5)  // Low
  };

  const disclaimer = 'DISCLAIMER: This framework and its generated recommendations provide risk assessment and strategic security guidance based on user-supplied parameters and standard cybersecurity heuristics (NIST CSF 2.0). These recommendations do not guarantee invulnerability against cyber attacks or substitute for certified, hands-on professional penetration testing, forensic analysis, or regulatory compliance auditing.';

  return {
    totalActions: planItems.length,
    planItems,
    groupedPlan,
    disclaimer
  };
}

module.exports = {
  THREAT_RULES,
  CONTROL_GAP_RULES,
  generateMitigationPlan
};
