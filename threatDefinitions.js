/**
 * Threat Definitions & Metadata Catalog
 * Aligned with NIST Cybersecurity Framework (CSF 2.0) and SME Threat Profiles
 */

const THREAT_DEFINITIONS = [
  {
    id: 'phishing',
    name: 'Phishing',
    nistCategory: 'PROTECT',
    nistSubcategory: 'PR.AT (Awareness and Training)',
    description: 'Deceptive electronic communications (email, SMS, voice) designed to trick employees into revealing credentials, downloading malicious attachments, or transferring funds.',
    smeContext: 'Phishing is the #1 initial access vector for SMEs due to high volume, sophisticated pretexting, and lack of dedicated email filtering gateways.',
    defaultLikelihood: 4,
    defaultSeverity: 4,
    defaultImpact: 4,
    commonMitigations: [
      'Implement ongoing employee phishing awareness & simulation training',
      'Deploy automated email security gateways with DMARC, DKIM, and SPF validation',
      'Enforce Multi-Factor Authentication (MFA) across all email and SaaS platforms',
      'Establish a dual-approval process for financial transactions and credential changes'
    ]
  },
  {
    id: 'ransomware',
    name: 'Ransomware',
    nistCategory: 'PROTECT',
    nistSubcategory: 'PR.DS (Data Security) & PR.PT (Protective Technology)',
    description: 'Malicious software that encrypts business files, databases, and operational backups, demanding extortion payment in cryptocurrency for decryption keys.',
    smeContext: 'Average SME downtime from ransomware exceeds 16-21 days, frequently threatening solvency due to lost revenue and recovery costs.',
    defaultLikelihood: 3,
    defaultSeverity: 5,
    defaultImpact: 5,
    commonMitigations: [
      'Maintain immutable, air-gapped, or cloud-isolated 3-2-1 offline backups',
      'Deploy Next-Generation Endpoint Detection & Response (EDR) with behavioral anti-ransomware rollback',
      'Implement strict network segmentation between user workstations and core database servers',
      'Develop, rehearse, and maintain an SME-tailored Incident Response and Disaster Recovery Plan'
    ]
  },
  {
    id: 'malware',
    name: 'Malware',
    nistCategory: 'PROTECT',
    nistSubcategory: 'PR.PT (Protective Technology)',
    description: 'Broad classification of hostile software including spyware, trojans, keyloggers, and rootkits designed to infiltrate systems and exfiltrate data.',
    smeContext: 'Malware often enters SME networks through downloaded utilities, shadow IT applications, or infected USB flash drives.',
    defaultLikelihood: 3,
    defaultSeverity: 3,
    defaultImpact: 4,
    commonMitigations: [
      'Deploy centrally managed endpoint protection with real-time heuristic scanning',
      'Disable automated USB execution and enforce application whitelisting policies',
      'Implement network perimeter firewalls with deep packet inspection and antivirus streaming',
      'Restrict standard employee accounts from possessing administrative install privileges'
    ]
  },
  {
    id: 'insider_threat',
    name: 'Insider Threat',
    nistCategory: 'IDENTIFY',
    nistSubcategory: 'ID.AM (Asset Management) & PR.AC (Access Control)',
    description: 'Security risks originating from employees, contractors, or business partners who misuse legitimate access to steal IP, sabotage systems, or leak data.',
    smeContext: 'In small businesses, informal trust relationships and shared credentials severely amplify insider risk, especially during employee departures.',
    defaultLikelihood: 2,
    defaultSeverity: 4,
    defaultImpact: 4,
    commonMitigations: [
      'Enforce Role-Based Access Control (RBAC) and strict Principle of Least Privilege',
      'Implement rapid and standardized employee offboarding checklists with immediate token revocation',
      'Log and monitor sensitive file access, large bulk downloads, and after-hours remote sessions',
      'Require mandatory Non-Disclosure Agreements (NDAs) and clean desk policies'
    ]
  },
  {
    id: 'data_breach',
    name: 'Data Breach',
    nistCategory: 'IDENTIFY',
    nistSubcategory: 'ID.RA (Risk Assessment) & PR.DS (Data Security)',
    description: 'Security incident in which confidential, proprietary, or personally identifiable information (PII/PHI) is accessed, disclosed, or stolen without authorization.',
    smeContext: 'SMEs face regulatory fines (GDPR, HIPAA, CCPA, PCI-DSS) alongside legal liabilities and reputational ruin following customer data disclosure.',
    defaultLikelihood: 3,
    defaultSeverity: 5,
    defaultImpact: 5,
    commonMitigations: [
      'Enforce AES-256 encryption for data at rest (laptops, databases) and TLS 1.3 for data in transit',
      'Conduct comprehensive data classification to identify where sensitive customer data resides',
      'Restrict database access using strict network firewalls and multi-factor authentication',
      'Perform regular third-party vulnerability scans and external surface security audits'
    ]
  },
  {
    id: 'weak_passwords',
    name: 'Weak Passwords',
    nistCategory: 'PROTECT',
    nistSubcategory: 'PR.AC (Identity Management & Access Control)',
    description: 'Pervasive use of predictable, reused, default, or single-factor credentials susceptible to brute-force attacks, credential stuffing, and dictionary harvesting.',
    smeContext: 'Over 80% of SME hacking-related breaches leverage stolen, reused, or easily guessable user passwords.',
    defaultLikelihood: 4,
    defaultSeverity: 3,
    defaultImpact: 4,
    commonMitigations: [
      'Implement a mandatory password policy enforcing minimum 14 characters or passphrases',
      'Mandate company-wide deployment of an approved corporate Password Manager',
      'Enforce hardware or authenticator app Multi-Factor Authentication (MFA) unconditionally',
      'Configure automatic account lockout after 5 consecutive failed authentication attempts'
    ]
  },
  {
    id: 'ddos',
    name: 'DDoS (Distributed Denial of Service)',
    nistCategory: 'RESPOND',
    nistSubcategory: 'RS.MI (Mitigation) & PR.PT (Protective Technology)',
    description: 'Coordinated flood of malicious web traffic or API requests overwhelming SME servers, firewalls, or e-commerce portals, rendering services unavailable.',
    smeContext: 'DDoS can take down small online stores, client portals, and web services, causing immediate revenue loss and customer defection.',
    defaultLikelihood: 2,
    defaultSeverity: 3,
    defaultImpact: 4,
    commonMitigations: [
      'Deploy cloud-based DDoS mitigation and Content Delivery Network (CDN) protection (e.g., Cloudflare)',
      'Implement rate limiting and web application firewall (WAF) filtering on public endpoints',
      'Establish traffic anomaly monitoring and ISP emergency upstream escalation procedures',
      'Architect resilient DNS routing and redundant cloud failover environments'
    ]
  },
  {
    id: 'unpatched_software',
    name: 'Unpatched Software',
    nistCategory: 'PROTECT',
    nistSubcategory: 'PR.IP (Information Protection Processes & Maintenance)',
    description: 'Failure to apply vendor security updates to operating systems, firmware, CMS platforms, and third-party software, leaving known vulnerabilities (CVEs) exposed.',
    smeContext: 'Cybercriminals actively automate internet scans for outdated plugins and OS vulnerabilities, which SMEs often neglect due to lack of dedicated IT staff.',
    defaultLikelihood: 4,
    defaultSeverity: 4,
    defaultImpact: 4,
    commonMitigations: [
      'Deploy automated patch management software across all workstations and servers',
      'Implement regular monthly automated vulnerability scanning of external and internal assets',
      'Maintain an up-to-date hardware, software, and SaaS inventory with end-of-life tracking',
      'Decommission or strictly isolate legacy systems that no longer receive vendor security updates'
    ]
  },
  {
    id: 'social_engineering',
    name: 'Social Engineering',
    nistCategory: 'PROTECT',
    nistSubcategory: 'PR.AT (Awareness and Training)',
    description: 'Psychological manipulation of employees to divulge confidential information, bypass security protocols, or authorize illegitimate transfers (e.g., CEO fraud, pretexting).',
    smeContext: 'Smaller teams often operate with high levels of personal trust and urgency, making them particularly vulnerable to executive impersonation.',
    defaultLikelihood: 3,
    defaultSeverity: 4,
    defaultImpact: 4,
    commonMitigations: [
      'Establish out-of-band verification procedures (phone call confirmation) for all payment instructions',
      'Conduct regular scenario-based social engineering awareness sessions for finance and HR staff',
      'Implement clear whistleblower and incident reporting channels without employee punitive backlash',
      'Enforce digital signatures and cryptographic verification on corporate financial communications'
    ]
  },
  {
    id: 'unauthorized_access',
    name: 'Unauthorized Access',
    nistCategory: 'PROTECT',
    nistSubcategory: 'PR.AC (Access Control)',
    description: 'Illicit entry into corporate networks, cloud tenants, or applications by external actors exploiting unmanaged endpoints, open ports, or missing access boundaries.',
    smeContext: 'Proliferation of Remote Desktop Protocol (RDP) exposed to the public internet is a frequent vector for SME compromise.',
    defaultLikelihood: 3,
    defaultSeverity: 4,
    defaultImpact: 5,
    commonMitigations: [
      'Enforce strict Zero Trust Network Access (ZTNA) or enterprise VPN with mandatory MFA',
      'Disable public exposure of administrative ports (RDP 3389, SSH 22, SMB 445)',
      'Implement quarterly access permission reviews and revoke dormant guest accounts',
      'Utilize IP allowlisting and geo-blocking restrictions for core administrative management portals'
    ]
  }
];

module.exports = { THREAT_DEFINITIONS };
