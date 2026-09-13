import hashlib
import json
import re
import os
import urllib.error
import urllib.request

from datetime import datetime
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path
from urllib.parse import urlparse


# ---------------------------------------------------------
# EMAIL PARSING
# ---------------------------------------------------------

def load_email(file_path):

    with open(file_path, "rb") as file:
        return BytesParser(
            policy=policy.default
        ).parse(file)


def get_plain_text_body(message):

    body = message.get_body(preferencelist=("plain",))

    if body:
        return body.get_content()

    return ""


# ---------------------------------------------------------
# ATTACHMENT ANALYSIS
# ---------------------------------------------------------

def calculate_sha256(data):
    """Calculate SHA-256 for attachment bytes."""

    return hashlib.sha256(data).hexdigest()


def extract_attachments(message):

    attachments = []

    for part in message.iter_attachments():

        filename = part.get_filename()

        payload = part.get_payload(decode=True)

        if payload is None:
            continue

        sha256_hash = calculate_sha256(payload)

        attachments.append({
            "filename": filename or "unnamed_attachment",
            "content_type": part.get_content_type(),
            "size_bytes": len(payload),
            "sha256": sha256_hash
        })

    return attachments


# ---------------------------------------------------------
# IOC EXTRACTION
# ---------------------------------------------------------

def extract_urls(text):

    pattern = r'https?://[^\s<>"\']+'

    return sorted(set(re.findall(pattern, text)))


def extract_domains(urls):

    domains = []

    for url in urls:

        parsed = urlparse(url)

        if parsed.hostname:
            domains.append(parsed.hostname.lower())

    return sorted(set(domains))


def extract_email_addresses(text):

    pattern = (
        r'\b[A-Za-z0-9._%+-]+@'
        r'[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
    )

    return sorted(set(re.findall(pattern, text)))


# ---------------------------------------------------------
# DOMAIN COMPARISON
# ---------------------------------------------------------

def get_email_domain(address):

    _, email_address = parseaddr(address)

    if "@" not in email_address:
        return ""

    return email_address.rsplit("@", 1)[1].lower()


# ---------------------------------------------------------
# PHISHING INDICATOR ANALYSIS
# ---------------------------------------------------------

def detect_indicators(message, body, urls, attachments):

    sender = str(message.get("From", ""))
    reply_to = str(message.get("Reply-To", ""))

    sender_domain = get_email_domain(sender)
    reply_domain = get_email_domain(reply_to)

    text = (
        str(message.get("Subject", "")) +
        "\n" +
        body
    ).lower()

    urgency_terms = [
        "urgent",
        "immediately",
        "expire today",
        "suspended"
    ]

    credential_terms = [
        "password",
        "verify your account",
        "login",
        "credential"
    ]

    urgency = any(
        term in text
        for term in urgency_terms
    )

    credential_request = any(
        term in text
        for term in credential_terms
    )

    sender_replyto_mismatch = bool(
        sender_domain
        and reply_domain
        and sender_domain != reply_domain
    )

    # Lab heuristic only.
    # Presence of a URL alone does NOT prove maliciousness.
    suspicious_url = len(urls) > 0
    suspicious_attachment = len(attachments) > 0

    return {
        "urgency": urgency,
        "credential_request": credential_request,
        "sender_replyto_mismatch": sender_replyto_mismatch,
        "suspicious_url": suspicious_url,
        "suspicious_attachment": suspicious_attachment
    }


# ---------------------------------------------------------
# THREAT-INTELLIGENCE ENRICHMENT
# ---------------------------------------------------------

def virustotal_hash_lookup(file_hash):
    """Look up a SHA-256 hash in VirusTotal."""

    api_key = os.getenv("VT_API_KEY")

    if not api_key:
        return {
            "provider": "VirusTotal",
            "lookup_type": "SHA-256",
            "hash": file_hash,
            "status": "api_key_missing",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0
        }

    url = (
        "https://www.virustotal.com/api/v3/files/"
        + file_hash
    )

    request = urllib.request.Request(
        url,
        headers={
            "x-apikey": api_key
        }
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=15
        ) as response:

            data = json.loads(
                response.read().decode("utf-8")
            )

    except urllib.error.HTTPError as error:

        if error.code == 404:
            return {
                "provider": "VirusTotal",
                "lookup_type": "SHA-256",
                "hash": file_hash,
                "status": "not_found",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0
            }

        return {
            "provider": "VirusTotal",
            "lookup_type": "SHA-256",
            "hash": file_hash,
            "status": f"http_error_{error.code}",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0
        }

    except urllib.error.URLError:

        return {
            "provider": "VirusTotal",
            "lookup_type": "SHA-256",
            "hash": file_hash,
            "status": "network_error",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0
        }

    attributes = data.get(
        "data",
        {}
    ).get(
        "attributes",
        {}
    )

    stats = attributes.get(
        "last_analysis_stats",
        {}
    )

    return {
        "provider": "VirusTotal",
        "lookup_type": "SHA-256",
        "hash": file_hash,
        "status": "found",
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0)
    }


# ---------------------------------------------------------
# MITRE ATT&CK MAPPING
# ---------------------------------------------------------

def map_mitre_attack(indicators):

    techniques = []

    if (
        indicators["credential_request"]
        and indicators["suspicious_url"]
    ):
        techniques.append({
            "technique_id": "T1566.002",
            "technique": "Spearphishing Link",
            "tactic": "Initial Access"
        })

    if indicators["suspicious_attachment"]:
        techniques.append({
            "technique_id": "T1566.001",
            "technique": "Spearphishing Attachment",
            "tactic": "Initial Access"
        })

    return techniques


# ---------------------------------------------------------
# RISK SCORING
# ---------------------------------------------------------

def calculate_risk(indicators):

    score = 0

    if indicators["urgency"]:
        score += 10

    if indicators["credential_request"]:
        score += 20

    if indicators["sender_replyto_mismatch"]:
        score += 15

    if indicators["suspicious_url"]:
        score += 15

    if indicators["suspicious_attachment"]:
        score += 25

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

    return score, severity


# ---------------------------------------------------------
# INCIDENT RESPONSE DECISION
# ---------------------------------------------------------

def determine_response(severity, indicators):

    actions = []

    if severity in ["High", "Critical"]:

        actions.append(
            "Escalate case to senior CTC/SOC analyst"
        )

        actions.append(
            "Preserve email and investigation evidence"
        )

    if indicators["suspicious_url"]:

        actions.append(
            "Recommend blocking identified phishing URL/domain"
        )

    if indicators["suspicious_attachment"]:

        actions.append(
            "Preserve attachment and SHA-256 hash for threat-intelligence analysis"
        )

        actions.append(
            "Do not execute the attachment; perform safe reputation analysis"
        )

    if indicators["credential_request"]:

        actions.append(
            "Determine whether the recipient interacted with the link"
        )

        actions.append(
            "Determine whether credentials were submitted"
        )

    actions.append(
        "Search for similar messages across the environment"
    )

    actions.append(
        "Communicate investigation outcome to reporting user"
    )

    return actions


# ---------------------------------------------------------
# MAIN INVESTIGATION
# ---------------------------------------------------------

def analyze_email(file_path):

    message = load_email(file_path)

    body = get_plain_text_body(message)

    attachments = extract_attachments(message)

    threat_intelligence = []

    for attachment in attachments:

        vt_result = virustotal_hash_lookup(
            attachment["sha256"]
    )

        threat_intelligence.append(
            vt_result
    )

    urls = extract_urls(body)

    domains = extract_domains(urls)

    searchable_text = "\n".join([
        str(message.get("From", "")),
        str(message.get("To", "")),
        str(message.get("Reply-To", "")),
        body
    ])

    email_addresses = extract_email_addresses(
        searchable_text
    )

    indicators = detect_indicators(
        message,
        body,
        urls,
        attachments
    )

    mitre_techniques = map_mitre_attack(
    indicators
    )

    risk_score, severity = calculate_risk(
        indicators
    )

    response_actions = determine_response(
    severity,
    indicators
    )
    
    case = {

        "case_id": "INC-001",

        "analysis_timestamp":
            datetime.now().isoformat(timespec="seconds"),

        "source":
            "Employee-Reported Suspicious Email",

        "category":
            "Suspected Credential Phishing",

        "email": {

            "from": str(message.get("From", "")),

            "to": str(message.get("To", "")),

            "reply_to":
                str(message.get("Reply-To", "")),

            "subject":
                str(message.get("Subject", "")),

            "message_id":
                str(message.get("Message-ID", ""))

        },

        "iocs": {

            "urls": urls,

            "domains": domains,

            "email_addresses":
                email_addresses

        },

        "attachments": attachments,

        "threat_intelligence": threat_intelligence,

        "indicators": indicators,

        "mitre_attack": mitre_techniques,

        "risk_score": risk_score,

        "severity": severity,

        "escalation_required":
            severity in ["High", "Critical"],

        "recommended_response_actions":
            response_actions,
        
        "status":
            "Investigating"
    }

    return case


# ---------------------------------------------------------
# SAVE RESULT
# ---------------------------------------------------------

email_file = Path(
    "data/emails/INC-001-password-reset.eml"
)

result = analyze_email(email_file)

output_file = Path(
    "cases/INC-001-auto-analysis.json"
)

with open(
    output_file,
    "w",
    encoding="utf-8"
) as file:

    json.dump(
        result,
        file,
        indent=4
    )


print("=" * 60)
print("ENTERPRISE PHISHING INVESTIGATION")
print("=" * 60)

print(
    f"\nCase ID    : "
    f"{result['case_id']}"
)

print(
    f"Subject    : "
    f"{result['email']['subject']}"
)

print(
    f"From       : "
    f"{result['email']['from']}"
)

print(
    f"Reply-To   : "
    f"{result['email']['reply_to']}"
)

print("\nINDICATORS")
print("-" * 60)

for indicator, detected in result["indicators"].items():

    print(
        f"{indicator:<28}: "
        f"{detected}"
    )

print("\nMITRE ATT&CK")
print("-" * 60)

if result["mitre_attack"]:

    for technique in result["mitre_attack"]:

        print(
            f"{technique['technique_id']} - "
            f"{technique['technique']}"
        )

        print(
            f"Tactic     : "
            f"{technique['tactic']}"
        )

else:

    print("No ATT&CK technique mapped.")

print("\nRISK ASSESSMENT")
print("-" * 60)

for number, action in enumerate(
    result["recommended_response_actions"],
    start=1
):
    print(f"{number}. {action}")

print(
    f"Risk Score : "
    f"{result['risk_score']}/100"
)

print(
    f"Severity   : "
    f"{result['severity']}"
)

print(
    f"Escalation : "
    f"{result['escalation_required']}"
)

print("\nIOCs")
print("-" * 60)

for url in result["iocs"]["urls"]:
    print(f"URL        : {url}")

for domain in result["iocs"]["domains"]:
    print(f"Domain     : {domain}")

# ---------------------------------------------------------
# ATTACHMENT ANALYSIS OUTPUT
# ---------------------------------------------------------

print("\nATTACHMENT ANALYSIS")
print("-" * 60)

if result["attachments"]:

    for attachment in result["attachments"]:

        print(
            f"File Name   : "
            f"{attachment['filename']}"
        )

        print(
            f"Content Type: "
            f"{attachment['content_type']}"
        )

        print(
            f"Size        : "
            f"{attachment['size_bytes']} bytes"
        )

        print(
            f"SHA-256     : "
            f"{attachment['sha256']}"
        )

else:
    print("No attachments found.")

print("\nTHREAT INTELLIGENCE")
print("-" * 60)

if result["threat_intelligence"]:

    for item in result["threat_intelligence"]:

        print(
            f"Provider    : "
            f"{item['provider']}"
        )

        print(
            f"Hash        : "
            f"{item['hash']}"
        )

        print(
            f"Status      : "
            f"{item['status']}"
        )

        print(
            f"Malicious   : "
            f"{item['malicious']}"
        )

        print(
            f"Suspicious  : "
            f"{item['suspicious']}"
        )

        print(
            f"Harmless    : "
            f"{item['harmless']}"
        )

        print(
            f"Undetected  : "
            f"{item['undetected']}"
        )

else:

    print("No attachment threat-intelligence data.")

print(
    f"\nAnalysis saved to: "
    f"{output_file}"
)