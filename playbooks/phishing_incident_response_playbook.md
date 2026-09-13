# Enterprise Phishing Incident Response Playbook

## Purpose

This playbook defines the SOC investigation and response process for suspected phishing incidents analyzed through the Enterprise Phishing Incident Response Center.

## 1. Detection

Potential phishing incidents may originate from:

- User-reported suspicious email
- Security monitoring alerts
- Suspicious links or attachments
- Credential-submission indicators
- Threat-intelligence matches
- Abnormal network activity

## 2. Initial Triage

The SOC analyst should collect:

- Case ID
- Sender address
- Recipient
- Subject
- URLs
- Attachments
- File hashes
- Urgency indicators
- Credential-related indicators
- Reply-to anomalies

The automated phishing analysis scripts calculate a risk score that assists with prioritization.

## 3. Risk Classification

### Low Risk
Continue monitoring and document findings.

### Medium Risk
Perform additional IOC and threat-intelligence investigation.

### High Risk
Escalate for immediate investigation and containment.

High-risk indicators may include credential harvesting, suspicious URLs, malicious attachments, impersonation, or multiple correlated phishing indicators.

## 4. Threat Intelligence Enrichment

Extracted indicators should be enriched using approved threat-intelligence sources.

Examples:

- File hashes
- Domains
- URLs
- IP addresses

VirusTotal can be used to determine whether an indicator has previously been associated with malicious activity.

An unknown result must not automatically be classified as safe or malicious.

## 5. SIEM Investigation

Use Splunk to correlate phishing evidence with security events.

Review:

- Incident severity
- Risk score
- User activity
- IOC matches
- Threat-intelligence status
- Escalation status
- MITRE ATT&CK context

## 6. Network Investigation

Use Wireshark when network-level evidence is required.

Investigate:

- DNS queries
- Destination IP addresses
- Suspicious domains
- HTTP/HTTPS connections
- Unusual outbound communication

Preserve relevant packet captures as investigation evidence.

## 7. MITRE ATT&CK Mapping

Phishing activity should be mapped to applicable MITRE ATT&CK techniques when supported by investigation evidence.

Examples include:

- Spearphishing Attachment
- Spearphishing Link

ATT&CK mappings provide standardized context for communicating attacker behavior.

## 8. Containment

For confirmed or highly suspicious phishing incidents, appropriate actions may include:

- Block malicious domains and URLs
- Block malicious sender addresses
- Isolate affected endpoints
- Disable compromised accounts
- Reset affected credentials
- Revoke active sessions
- Preserve forensic evidence

## 9. Eradication

Remove identified malicious artifacts and persistence mechanisms.

Actions may include:

- Delete malicious emails
- Remove downloaded payloads
- Remove malicious files
- Scan affected systems
- Verify endpoint security controls
- Remove unauthorized persistence

## 10. Recovery

After containment and eradication:

- Restore affected systems if required
- Re-enable accounts when safe
- Verify credential resets
- Monitor for recurring indicators
- Confirm normal endpoint and account activity

## 11. Escalation

High-risk incidents should be escalated to Tier 2 Incident Response when deeper investigation or containment is required.

Escalation documentation should include:

- Case ID
- Risk score
- Severity
- Relevant IOCs
- Investigation findings
- Threat-intelligence results
- Network evidence
- Recommended response actions

## 12. Lessons Learned

After incident closure:

- Document root cause
- Review detection effectiveness
- Identify control gaps
- Update detection rules
- Update phishing awareness guidance
- Improve the response playbook when necessary

## Investigation Workflow

Suspicious Email
→ IOC Extraction
→ Automated Risk Scoring
→ Threat Intelligence
→ Splunk Investigation
→ Network Analysis
→ Analyst Decision
→ Containment
→ Eradication
→ Recovery
→ Lessons Learned