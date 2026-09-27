/**
 * Security Control Definitions Catalog
 * Aligned with NIST Cybersecurity Framework (CSF 2.0)
 */

const CONTROL_DEFINITIONS = [
  {
    id: 'firewall',
    name: 'Hardware/Software Firewall',
    nistCategory: 'PROTECT',
    nistSubcategory: 'PR.PT (Protective Technology)',
    description: 'Managed perimeter and host-based firewalls that monitor and filter incoming and outgoing network traffic based on predefined security rules.',
    guidance: 'Ensure stateful inspection is enabled, default-deny rules are enforced for inbound connections, and remote administration ports are shielded from the public internet.',
    weight: 1.0
  },
  {
    id: 'antivirus',
    name: 'Antivirus / Endpoint Protection (EDR)',
    nistCategory: 'PROTECT',
    nistSubcategory: 'PR.PT (Protective Technology)',
    description: 'Centrally managed next-generation antivirus or endpoint detection & response software installed across all employee laptops, desktops, and servers.',
    guidance: 'EDR provides heuristic and behavioral defense against novel ransomware variants rather than relying solely on obsolete signature files.',
    weight: 1.0
  },
  {
    id: 'mfa',
    name: 'Multi-Factor Authentication (MFA)',
    nistCategory: 'PROTECT',
    nistSubcategory: 'PR.AC (Identity Management & Access Control)',
    description: 'Enforcement of two or more distinct authentication factors (e.g., authenticator app, FIDO2 hardware token) for email, cloud portals, and remote access.',
    guidance: 'MFA neutralizes up to 99% of bulk automated credential stuffing and password guessing attacks.',
    weight: 1.2
  },
  {
    id: 'backups',
    name: 'Regular & Immutable Backups',
    nistCategory: 'RECOVER',
    nistSubcategory: 'RC.RP (Recovery Planning) & PR.DS (Data Security)',
    description: 'Adherence to the 3-2-1 backup strategy (3 copies, 2 different media types, 1 isolated/offline or cloud-immutable copy) with documented quarterly test restores.',
    guidance: 'Without verified offline or immutable backups, recovering from modern double-extortion ransomware without paying extortion is virtually impossible.',
    weight: 1.2
  },
  {
    id: 'encryption',
    name: 'Data Encryption (At Rest & In Transit)',
    nistCategory: 'PROTECT',
    nistSubcategory: 'PR.DS (Data Security)',
    description: 'Full-disk encryption (BitLocker, FileVault) enabled on all endpoint devices, strong TLS 1.3 encryption on web communications, and encrypted database stores.',
    guidance: 'If an employee laptop is lost or stolen, full-disk encryption prevents unauthorized extraction of sensitive business data.',
    weight: 1.0
  },
  {
    id: 'training',
    name: 'Employee Cybersecurity Awareness Training',
    nistCategory: 'PROTECT',
    nistSubcategory: 'PR.AT (Awareness and Training)',
    description: 'Periodic interactive security education for all staff, including phishing simulations, safe web browsing habits, and credential hygiene practices.',
    guidance: 'Human error is implicated in the majority of cybersecurity breaches; trained staff serve as an active human firewall.',
    weight: 1.0
  },
  {
    id: 'patching',
    name: 'Regular Software & Patch Updates',
    nistCategory: 'PROTECT',
    nistSubcategory: 'PR.IP (Information Protection Processes & Maintenance)',
    description: 'Systematic schedule for testing and applying operating system security patches, firmware updates, and third-party software updates within 14-30 days of release.',
    guidance: 'Unpatched known vulnerabilities (CVEs) are weaponized within hours of public disclosure.',
    weight: 1.0
  },
  {
    id: 'access_control',
    name: 'Access Control & Role-Based Access (RBAC)',
    nistCategory: 'PROTECT',
    nistSubcategory: 'PR.AC (Access Control)',
    description: 'Enforcement of least privilege where staff only have access to directories and systems essential for their job role; administrative rights strictly restricted.',
    guidance: 'Prevents lateral movement during an intrusion and mitigates insider threat risks.',
    weight: 1.0
  },
  {
    id: 'monitoring',
    name: 'Security Event Monitoring & Logging',
    nistCategory: 'DETECT',
    nistSubcategory: 'DE.CM (Continuous Monitoring)',
    description: 'Centralized retention and automated alerts for system event logs, authentication failures, firewall alerts, and endpoint anomalies.',
    guidance: 'Without log monitoring, the average breach dwell time (attacker undetected on the network) exceeds 200 days.',
    weight: 1.0
  },
  {
    id: 'incident_response',
    name: 'Incident Response & Disaster Recovery Plan',
    nistCategory: 'RESPOND',
    nistSubcategory: 'RS.RP (Response Planning)',
    description: 'Written, documented, and tested response protocols detailing emergency contacts, containment steps, forensics retention, and customer communication plans.',
    guidance: 'A structured incident response plan drastically cuts operational downtime and mitigates financial losses during a cyber crisis.',
    weight: 1.0
  }
];

module.exports = { CONTROL_DEFINITIONS };
