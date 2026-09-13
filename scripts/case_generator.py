import json
from pathlib import Path
from datetime import datetime


case = {
    "case_id": "INC-001",
    "timestamp": datetime.now().isoformat(timespec="seconds"),

    "source": "Employee-Reported Suspicious Email",
    "category": "Suspected Credential Phishing",

    "sender": "security@example.com",
    "sender_display_name": "Microsoft Security",
    "recipient": "employee@company.example",
    "reply_to": "account-support@example.net",
    "subject": "URGENT: Password Expiration Notice",

    "urls": [
        "http://example.com/security/login"
    ],

    "domains": [
        "example.com"
    ],

    "ip_addresses": [],

    "attachments": [],

    "indicators": {
        "urgency": True,
        "credential_request": True,
        "sender_replyto_mismatch": True,
        "suspicious_url": True,
        "suspicious_attachment": False,
        "user_clicked": False,
        "credentials_submitted": False,
        "known_malicious_ioc": False
    },

    "risk_score": 60,
    "severity": "High",

    "status": "Investigating",

    "escalation_required": True,

    "containment_action": "Pending investigation",

    "final_disposition": "Suspicious - Investigation in Progress"
}


output_file = Path("cases/INC-001.json")

with open(output_file, "w", encoding="utf-8") as file:
    json.dump(case, file, indent=4)


print("=" * 60)
print("INCIDENT CASE GENERATED")
print("=" * 60)

print(f"\nCase ID     : {case['case_id']}")
print(f"Category    : {case['category']}")
print(f"Risk Score  : {case['risk_score']}/100")
print(f"Severity    : {case['severity']}")
print(f"Status      : {case['status']}")

print(f"\nCase saved to: {output_file}")