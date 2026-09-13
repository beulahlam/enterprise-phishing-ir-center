from email import policy
from email.parser import BytesParser
from pathlib import Path


def parse_email(file_path):
    """Read an EML file and display important investigation fields."""

    with open(file_path, "rb") as file:
        message = BytesParser(policy=policy.default).parse(file)

    print("=" * 60)
    print("PHISHING EMAIL ANALYSIS")
    print("=" * 60)

    print(f"From       : {message.get('From')}")
    print(f"To         : {message.get('To')}")
    print(f"Subject    : {message.get('Subject')}")
    print(f"Date       : {message.get('Date')}")
    print(f"Message-ID : {message.get('Message-ID')}")
    print(f"Reply-To   : {message.get('Reply-To')}")

    print("\nEMAIL BODY")
    print("-" * 60)

    body = message.get_body(preferencelist=("plain",))

    if body:
        print(body.get_content())
    else:
        print("No plain-text body found.")


email_file = Path("data/emails/INC-001-password-reset.eml")

parse_email(email_file)