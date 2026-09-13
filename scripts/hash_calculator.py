import hashlib
from pathlib import Path


def calculate_sha256(file_path):
    """Calculate the SHA-256 hash of a file."""

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        while True:
            chunk = file.read(4096)

            if not chunk:
                break

            sha256.update(chunk)

    return sha256.hexdigest()


attachment = Path("data/attachments/invoice.txt")

print("=" * 60)
print("ATTACHMENT HASH ANALYSIS")
print("=" * 60)

print(f"\nFile Name : {attachment.name}")
print(f"File Path : {attachment}")

file_hash = calculate_sha256(attachment)

print("\nSHA-256")
print("-" * 60)
print(file_hash)