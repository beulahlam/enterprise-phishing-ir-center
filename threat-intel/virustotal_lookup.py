import json
import os
import urllib.error
import urllib.request


# SHA-256 from our harmless INC-002 attachment
FILE_HASH = (
    "5a0dcae34fa08928c1121c06a4e00e4b"
    "5a6588bc40672eb42adda671d8b10f8d"
)


def lookup_hash(file_hash):
    """Look up an existing file hash in VirusTotal."""

    api_key = os.getenv("VT_API_KEY")

    if not api_key:
        print("=" * 60)
        print("VIRUSTOTAL THREAT-INTELLIGENCE LOOKUP")
        print("=" * 60)

        print("\nNo VT_API_KEY environment variable was found.")
        print("The script is configured correctly, but no API")
        print("request will be made until a key is configured.")

        print("\nHash prepared for lookup:")
        print(file_hash)

        return None

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

        print(
            f"VirusTotal HTTP error: "
            f"{error.code}"
        )

        if error.code == 404:
            print(
                "This hash was not found in "
                "VirusTotal's existing dataset."
            )

        return None

    except urllib.error.URLError as error:

        print(
            f"Network error: "
            f"{error.reason}"
        )

        return None

    return data


def display_results(data):

    if not data:
        return

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

    print("=" * 60)
    print("VIRUSTOTAL THREAT-INTELLIGENCE RESULTS")
    print("=" * 60)

    print(
        f"\nSHA-256    : "
        f"{FILE_HASH}"
    )

    print(
        f"Malicious  : "
        f"{stats.get('malicious', 0)}"
    )

    print(
        f"Suspicious : "
        f"{stats.get('suspicious', 0)}"
    )

    print(
        f"Harmless   : "
        f"{stats.get('harmless', 0)}"
    )

    print(
        f"Undetected : "
        f"{stats.get('undetected', 0)}"
    )

    print(
        f"Timeout     : "
        f"{stats.get('timeout', 0)}"
    )


result = lookup_hash(FILE_HASH)

display_results(result)