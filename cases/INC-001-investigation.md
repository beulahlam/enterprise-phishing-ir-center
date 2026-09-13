# Incident Investigation Record

## Case Information

**Case ID:** INC-001  
**Status:** Open  
**Category:** Suspected Credential Phishing  
**Initial Severity:** Medium  
**Source:** Employee-Reported Suspicious Email

## Email Information

**Sender Display Name:** Microsoft Security  
**Sender Address:** security@example.com  
**Recipient:** employee@company.example  
**Reply-To:** account-support@example.net  
**Subject:** URGENT: Password Expiration Notice

## Indicators Identified

- Urgency language
- Password-expiration theme
- Threat of account suspension
- Account-verification request
- Embedded URL
- Sender and Reply-To domain mismatch

## URL Identified

http://example.com/security/login

## Attachments

None

## Analyst Assessment

The email contains multiple characteristics associated with credential-phishing and social-engineering attempts. The sender and Reply-To domains differ, and the message uses urgency and the threat of account suspension to encourage the recipient to follow an account-verification link.

These indicators justify additional investigation but do not independently establish that the message is malicious.

## Investigation Actions

- [x] Reviewed sender information
- [x] Reviewed Reply-To information
- [x] Reviewed subject
- [x] Reviewed message content
- [x] Identified embedded URL
- [ ] Extract IOCs with Python
- [ ] Perform threat-intelligence enrichment
- [ ] Map relevant MITRE ATT&CK technique
- [ ] Assign final severity
- [ ] Determine escalation requirement
- [ ] Document containment recommendation
- [ ] Determine final disposition

## Current Disposition

**Suspicious — Investigation in Progress**