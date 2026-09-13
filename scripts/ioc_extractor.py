import re
from email import policy
from email.parser import BytesParser
from pathlib import Path
from urllib.parse import urlparse


def extract_email_body(message):
    """Return the plain-text body from an email."""

    body = message.get_body(preferencelist=("plain",))

    if body:
        return body.get_content()

    return ""


def extract_urls(text):
    """Extract HTTP and HTTPS URLs."""

    url_pattern = r'https?://[^\s<>"\']+'

    return re.findall(url_pattern, text)


def extract_domains(urls):
    """Extract domain names from URLs."""

    domains = []

    for url in urls:
        parsed_url = urlparse(url)

        if parsed_url.hostname:
            domains.append(parsed_url.hostname)

    return sorted(set(domains))


def extract_email_addresses(text):
    """Extract email addresses from text."""

    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'

    return sorted(set(re.findall(email_pattern, text)))


def extract_ip_addresses(text):
    """Extract IPv4 addresses from text."""

    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'

    return sorted(set(re.findall(ip_pattern, text)))


def analyze_email(file_path):

    with open(file_path, "rb") as file:
        message = BytesParser(
            policy=policy.default
        ).parse(file)

    body = extract_email_body(message)

    # Combine selected headers and body for IOC searching.
    investigation_text = "\n".join([
        str(message.get("From", "")),
        str(message.get("To", "")),
        str(message.get("Reply-To", "")),
        body
    ])

    urls = extract_urls(body)
    domains = extract_domains(urls)
    email_addresses = extract_email_addresses(investigation_text)
    ip_addresses = extract_ip_addresses(investigation_text)

    print("=" * 60)
    print("IOC EXTRACTION RESULTS")
    print("=" * 60)

    print(f"\nSubject: {message.get('Subject')}")
    print(f"From: {message.get('From')}")
    print(f"Reply-To: {message.get('Reply-To')}")

    print("\nURLs FOUND")
    print("-" * 60)

    if urls:
        for url in urls:
            print(url)
    else:
        print("No URLs found.")

    print("\nDOMAINS FOUND")
    print("-" * 60)

    if domains:
        for domain in domains:
            print(domain)
    else:
        print("No domains found.")

    print("\nEMAIL ADDRESSES FOUND")
    print("-" * 60)

    if email_addresses:
        for address in email_addresses:
            print(address)
    else:
        print("No email addresses found.")

    print("\nIP ADDRESSES FOUND")
    print("-" * 60)

    if ip_addresses:
        for ip in ip_addresses:
            print(ip)
    else:
        print("No IP addresses found.")


email_file = Path(
    "data/emails/INC-001-password-reset.eml"
)

analyze_email(email_file)