def calculate_risk_score(
    urgency=False,
    credential_request=False,
    sender_replyto_mismatch=False,
    suspicious_url=False,
    suspicious_attachment=False,
    financial_request=False,
    impersonation=False,
    user_clicked=False,
    credentials_submitted=False,
    known_malicious_ioc=False
):
    """Calculate a repeatable phishing incident risk score."""

    score = 0
    reasons = []

    indicators = [
        (urgency, 10, "Urgency / pressure language"),
        (credential_request, 20, "Credential or account-verification request"),
        (sender_replyto_mismatch, 15, "Sender / Reply-To mismatch"),
        (suspicious_url, 15, "Suspicious URL"),
        (suspicious_attachment, 20, "Suspicious attachment"),
        (financial_request, 20, "Financial request"),
        (impersonation, 15, "Impersonation"),
        (user_clicked, 20, "User clicked suspicious link"),
        (credentials_submitted, 40, "Credentials submitted"),
        (known_malicious_ioc, 40, "Known-malicious IOC")
    ]

    for present, points, reason in indicators:
        if present:
            score += points
            reasons.append((reason, points))

    # Keep the enterprise score on a 0-100 scale.
    score = min(score, 100)

    if score >= 80:
        severity = "Critical"
    elif score >= 60:
        severity = "High"
    elif score >= 40:
        severity = "Medium"
    elif score >= 20:
        severity = "Low"
    else:
        severity = "Informational"

    return score, severity, reasons


# INC-001 evidence identified during our investigation
score, severity, reasons = calculate_risk_score(
    urgency=True,
    credential_request=True,
    sender_replyto_mismatch=True,
    suspicious_url=True,
    suspicious_attachment=False,
    financial_request=False,
    impersonation=False,
    user_clicked=False,
    credentials_submitted=False,
    known_malicious_ioc=False
)

print("=" * 60)
print("PHISHING INCIDENT RISK ASSESSMENT")
print("=" * 60)

print("\nCase ID: INC-001")

print("\nSCORING EVIDENCE")
print("-" * 60)

for reason, points in reasons:
    print(f"+{points:>2}  {reason}")

print("\nRISK RESULT")
print("-" * 60)
print(f"Risk Score : {score}/100")
print(f"Severity   : {severity}")